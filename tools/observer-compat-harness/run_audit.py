#!/usr/bin/env python3
"""
End-to-end compatibility audit runner driving all 5 unmodified upstream MeshCore
observers against an unmodified main meshcore-mqtt-broker instance.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

HARNESS_ROOT = "/harness"
if HARNESS_ROOT not in sys.path:
    sys.path.insert(0, HARNESS_ROOT)

import paho.mqtt.client as mqtt
from ed25519_orlp import ed25519_sign

from shims.virtual_companion import ThreadedVirtualCompanion, generate_orlp_keypair
from shims.virtual_repeater_pty import VirtualRepeaterPty

UPSTREAM_REPOS = {
    "agessaman": ("/opt/observers/agessaman", "122d959f"),
    "cisien": ("/opt/observers/cisien", "9b4e022e"),
    "offband": ("/opt/observers/offband", "8be9a02003cfae4427cb349606938fa4fd2869bc"),
    "openhop": ("/opt/observers/openhop", "13eb8b2e"),
    "meshcore-ha": ("/opt/observers/meshcore-ha", "0d5855bf"),
}

CA_CERT_PATH = "/tmp/audit_certs/ca.crt"


def verify_upstream_repos() -> list[dict[str, str]]:
    """Confirm every upstream checkout matches its pinned commit and has no local edits."""
    status_list: list[dict[str, str]] = []
    for name, (repo_dir, expected_prefix) in UPSTREAM_REPOS.items():
        head = subprocess.check_output(["git", "-C", repo_dir, "rev-parse", "HEAD"], text=True).strip()
        dirty = subprocess.check_output(["git", "-C", repo_dir, "status", "--porcelain"], text=True).strip()
        if not head.startswith(expected_prefix):
            raise RuntimeError(f"Upstream {name} HEAD {head} does not match expected {expected_prefix}")
        if dirty:
            raise RuntimeError(f"Upstream {name} has unexpected modifications:\n{dirty}")
        status_list.append({"observer": name, "head": head, "clean": "true"})
    return status_list


def wait_for_broker_health(host: str, port: int, timeout_s: float = 30.0) -> None:
    """Block until the target broker /health HTTP endpoint returns 200."""
    url = f"http://{host}:{port}/health"
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_err = exc
        time.sleep(0.25)
    raise TimeoutError(f"Broker health check timed out at {url}: {last_err}")


def setup_test_certs() -> tuple[str, str, str]:
    """Generate a local CA + server certificate valid for localhost and 127.0.0.1."""
    cert_dir = "/tmp/audit_certs"
    os.makedirs(cert_dir, exist_ok=True)
    ca_key = os.path.join(cert_dir, "ca.key")
    ca_crt = os.path.join(cert_dir, "ca.crt")
    srv_key = os.path.join(cert_dir, "server.key")
    srv_csr = os.path.join(cert_dir, "server.csr")
    srv_crt = os.path.join(cert_dir, "server.crt")
    ext_cfg = os.path.join(cert_dir, "server.ext")

    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", "/CN=MeshCoreAuditCA", "-keyout", ca_key, "-out", ca_crt],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-subj", "/CN=localhost", "-keyout", srv_key, "-out", srv_csr],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(ext_cfg, "w", encoding="utf-8") as f:
        f.write(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        )
    subprocess.run(
        ["openssl", "x509", "-req", "-in", srv_csr, "-CA", ca_crt, "-CAkey", ca_key,
         "-CAcreateserial", "-out", srv_crt, "-days", "30", "-extfile", ext_cfg],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    shutil.copyfile(ca_crt, "/usr/local/share/ca-certificates/audit-ca.crt")
    subprocess.run(["update-ca-certificates"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return ca_crt, srv_crt, srv_key


def wait_tcp_port(host: str, port: int, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"TCP port {host}:{port} did not become ready within {timeout_s}s")


def start_tls_proxy(listen_port: int, target_host: str, target_port: int, cert: str, key: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [
            "python3",
            f"{HARNESS_ROOT}/tls_proxy.py",
            "--listen-host", "127.0.0.1",
            "--listen-port", str(listen_port),
            "--target-host", target_host,
            "--target-port", str(target_port),
            "--cert", cert,
            "--key", key,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    wait_tcp_port("127.0.0.1", listen_port, timeout_s=10.0)
    return proc


def sign_orlp_jwt(pub_hex: str, prv_hex: str, claims: dict[str, Any], uppercase_sig: bool = True) -> str:
    """Create a 3-part Ed25519 JWT token compatible with MeshCore / Cisien."""
    header = {"alg": "Ed25519", "typ": "JWT"}
    b64 = lambda b: base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    h_enc = b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_enc = b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_enc}.{p_enc}"
    sig = ed25519_sign(signing_input.encode("utf-8"), bytes.fromhex(pub_hex), bytes.fromhex(prv_hex))
    sig_hex = sig.hex().upper() if uppercase_sig else sig.hex()
    return f"{signing_input}.{sig_hex}"


class SubscriberMonitor:
    """Maintains a subscribed paho-mqtt v2 connection and captures received messages."""

    def __init__(self, name: str, host: str, ws_port: int, username: str, password: str) -> None:
        self.name = name
        self.host = host
        self.ws_port = ws_port
        self.username = username
        self.password = password
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self.messages: list[dict[str, Any]] = []
        self._connected = threading.Event()
        self._subacks = 0

        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"audit_{name}_{int(time.time())}",
            transport="websockets",
        )
        self.client.ws_set_options(path="/mqtt")
        self.client.username_pw_set(username, password)
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code == 0:
            client.subscribe([("meshcore/#", 0), ("$SYS/#", 0)])
            self._connected.set()

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties) -> None:
        with self._lock:
            self._subacks += len(reason_code_list)
            self._cond.notify_all()

    def _on_message(self, client, userdata, msg: mqtt.MQTTMessage) -> None:
        text = msg.payload.decode("utf-8", errors="replace")
        parsed: Any = None
        if text.startswith("{") or text.startswith("["):
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
        entry = {
            "ts": time.monotonic(),
            "wall": time.time(),
            "topic": msg.topic,
            "payload_text": text,
            "payload_json": parsed,
            "retain": bool(msg.retain),
            "qos": int(msg.qos),
        }
        with self._cond:
            self.messages.append(entry)
            self._cond.notify_all()

    def start(self, timeout_s: float = 10.0) -> None:
        self.client.connect(self.host, self.ws_port, keepalive=60)
        self.client.loop_start()
        if not self._connected.wait(timeout_s):
            raise TimeoutError(f"Subscriber {self.name} timed out connecting")
        deadline = time.monotonic() + timeout_s
        with self._cond:
            while self._subacks < 2:
                rem = deadline - time.monotonic()
                if rem <= 0:
                    raise TimeoutError(f"Subscriber {self.name} timed out waiting for SUBACK")
                self._cond.wait(rem)

    def stop(self) -> None:
        try:
            self.client.disconnect()
        except Exception:
            pass
        try:
            self.client.loop_stop()
        except Exception:
            pass

    def mark(self) -> int:
        with self._lock:
            return len(self.messages)

    def since(self, idx: int) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.messages[idx:])

    def wait_for(
        self,
        start_idx: int,
        predicate: Callable[[dict[str, Any]], bool],
        timeout_s: float = 8.0,
    ) -> Optional[dict[str, Any]]:
        deadline = time.monotonic() + timeout_s
        with self._cond:
            while True:
                for msg in self.messages[start_idx:]:
                    if predicate(msg):
                        return msg
                rem = deadline - time.monotonic()
                if rem <= 0:
                    return None
                self._cond.wait(rem)

    def latest_sys_value(self, suffix: str) -> Optional[str]:
        with self._lock:
            for msg in reversed(self.messages):
                if msg["topic"] == suffix:
                    return msg["payload_text"]
        return None


def spawn_virtual_companion_cli(name: str) -> tuple[subprocess.Popen, dict[str, Any]]:
    proc = subprocess.Popen(
        [
            "python3",
            f"{HARNESS_ROOT}/shims/virtual_companion.py",
            "--host", "127.0.0.1",
            "--port", "0",
            "--control-port", "0",
            "--name", name,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None
    line = proc.stdout.readline().strip()
    if not line:
        err = proc.stderr.read() if proc.stderr else ""
        raise RuntimeError(f"virtual_companion failed to start: {err}")
    return proc, json.loads(line)


def send_companion_rx(control_port: int, marker: str, route: str = "F", snr: float = 8.5, rssi: int = -88) -> None:
    payload = json.dumps({"action": "rx", "marker": marker, "route": route, "snr": snr, "rssi": rssi}) + "\n"
    with socket.create_connection(("127.0.0.1", control_port), timeout=3.0) as s:
        s.sendall(payload.encode("utf-8"))
        s.recv(1024)


def stop_proc(proc: Optional[subprocess.Popen], sig: int = signal.SIGTERM, timeout_s: float = 5.0) -> str:
    if proc is None:
        return ""
    if proc.poll() is None:
        proc.send_signal(sig)
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3.0)
    out = ""
    if proc.stdout:
        try:
            out += proc.stdout.read() or ""
        except Exception:
            pass
    if proc.stderr:
        try:
            out += "\n" + (proc.stderr.read() or "")
        except Exception:
            pass
    return out[-3000:]


def child_env(pythonpath: Optional[str] = None, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["SSL_CERT_FILE"] = "/etc/ssl/certs/ca-certificates.crt"
    env["REQUESTS_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
    env["OFFBAND_CA_CERT_FILE"] = CA_CERT_PATH
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    if extra:
        env.update(extra)
    return env


def run_all_tests(args: argparse.Namespace) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    admin: Optional[SubscriberMonitor] = None
    limited: Optional[SubscriberMonitor] = None
    wss_proxy: Optional[subprocess.Popen] = None
    tls_proxy: Optional[subprocess.Popen] = None

    def record(test_id: str, observer: str, status: str, details: dict[str, Any]) -> None:
        entry = {"id": test_id, "observer": observer, "status": status, "details": details}
        results.append(entry)
        print(f"[AUDIT] {test_id} ({observer}) -> {status}", file=sys.stderr, flush=True)

    try:
        upstream_info = verify_upstream_repos()
        wait_for_broker_health(args.broker_host, args.broker_ws_port, timeout_s=30.0)
        _, srv_crt, srv_key = setup_test_certs()
        wss_proxy = start_tls_proxy(8443, args.broker_host, args.broker_ws_port, srv_crt, srv_key)
        tls_proxy = start_tls_proxy(8444, args.broker_host, args.broker_tcp_port, srv_crt, srv_key)

        admin = SubscriberMonitor("admin", args.broker_host, args.broker_ws_port, args.admin_user, args.admin_pass)
        limited = SubscriberMonitor("limited", args.broker_host, args.broker_ws_port, args.limited_user, args.limited_pass)
        admin.start()
        limited.start()
        time.sleep(0.5)

        # =====================================================================
        # 1. agessaman/meshcore-packet-capture
        # =====================================================================
        # 1a: Baseline WSS (/), status retain strip, packets/raw, Role-1 vs Role-3, /internal
        comp_proc, comp_info = spawn_virtual_companion_cli("AgessamanVirt1A")
        ag_proc: Optional[subprocess.Popen] = None
        try:
            pub = comp_info["pubkey"].upper()
            data_dir = tempfile.mkdtemp(prefix="ag1a_")
            toml_path = os.path.join(data_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "SEA"\nlog_level = "DEBUG"\n\n'
                    f'[topics]\nraw = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/raw"\n\n'
                    f'[capture]\nconnection_type = "tcp"\ntcp_host = "127.0.0.1"\ntcp_port = {comp_info["port"]}\n'
                    f'data_dir = "{data_dir}"\nadvert_interval_hours = 0\ndrain_messages = false\n'
                    f'raw_duplicate_window = 0\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nwebsocket_path = "/"\nqos = 0\nretain = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\n'
                )
            idx_a, idx_l = admin.mark(), limited.mark()
            ag_proc = subprocess.Popen(
                ["python3", "-m", "meshcore_packet_capture", "--no-env-files", "--config", toml_path, "--debug"],
                cwd=data_dir,
                env=child_env("/opt/observers/agessaman/src"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            st_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online",
                timeout_s=15.0,
            )
            st_l = limited.wait_for(
                idx_l,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online",
                timeout_s=8.0,
            )
            internal_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/internal"),
                timeout_s=6.0,
            )
            send_companion_rx(comp_info["control_port"], "AG1A")
            pkt_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets"),
                timeout_s=8.0,
            )
            pkt_l = limited.wait_for(
                idx_l,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets"),
                timeout_s=6.0,
            )
            raw_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/raw"),
                timeout_s=6.0,
            )
            time.sleep(0.3)
            limited_msgs = limited.since(idx_l)
            limited_saw_sensitive = any(
                (m["topic"].endswith("/internal") and pub in m["topic"].upper()) or m["topic"].startswith("$SYS/")
                for m in limited_msgs
            )
            logs_1a = stop_proc(ag_proc, signal.SIGTERM)
            ag_proc = None

            status_json_l = (st_l or {}).get("payload_json") or {}
            pkt_json_l = (pkt_l or {}).get("payload_json") or {}
            ok = all([
                st_a is not None,
                st_l is not None,
                internal_a is not None,
                pkt_a is not None,
                pkt_l is not None,
                raw_a is not None,
                not (st_a or {}).get("retain", True),
                not limited_saw_sensitive,
                "stats" not in status_json_l and "model" not in status_json_l and "firmware_version" not in status_json_l,
                "SNR" not in pkt_json_l and "RSSI" not in pkt_json_l and "score" not in pkt_json_l,
            ])
            record("agessaman_1a_baseline_wss", "agessaman", "PASS" if ok else "FAIL", {
                "pubkey": pub,
                "status_topic": (st_a or {}).get("topic"),
                "status_retain": (st_a or {}).get("retain"),
                "internal_received_admin": internal_a is not None,
                "limited_saw_sensitive": limited_saw_sensitive,
                "packet_received": pkt_a is not None,
                "raw_received": raw_a is not None,
                "role3_status_filtered": "stats" not in status_json_l and "model" not in status_json_l,
                "role3_packet_filtered": "SNR" not in pkt_json_l and "RSSI" not in pkt_json_l,
                "log_tail": logs_1a[-600:],
            })
        finally:
            stop_proc(ag_proc, signal.SIGKILL)
            stop_proc(comp_proc, signal.SIGTERM)

        # 1b: --neighbors-now --neighbors-exit
        comp_proc, comp_info = spawn_virtual_companion_cli("AgessamanVirt1B")
        ag_proc = None
        try:
            pub = comp_info["pubkey"].upper()
            data_dir = tempfile.mkdtemp(prefix="ag1b_")
            toml_path = os.path.join(data_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "SEA"\nlog_level = "DEBUG"\n\n'
                    f'[capture]\nconnection_type = "tcp"\ntcp_host = "127.0.0.1"\ntcp_port = {comp_info["port"]}\n'
                    f'data_dir = "{data_dir}"\nadvert_interval_hours = 0\ndrain_messages = false\n'
                    f'neighbors_discover_window = 1\nneighbors_command_timeout = 2\n'
                    f'neighbors_scope_timeout = 2\nneighbors_scope_min_timeout = 1\n'
                    f'neighbors_scope_gap = 1\nneighbors_cycle_timeout = 6\n'
                    f'neighbors_self_scopes = "sea-mesh"\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nwebsocket_path = "/"\nqos = 0\nretain = true\nneighbors = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\n'
                )
            idx_a = admin.mark()
            ag_proc = subprocess.Popen(
                ["python3", "-m", "meshcore_packet_capture", "--no-env-files", "--config", toml_path,
                 "--neighbors-now", "--neighbors-exit", "--debug"],
                cwd=data_dir,
                env=child_env("/opt/observers/agessaman/src"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            nbr_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/neighbors"),
                timeout_s=35.0,
            )
            ag_proc.wait(timeout=35.0)
            logs_1b = stop_proc(ag_proc, signal.SIGTERM)
            ag_proc = None
            record("agessaman_1b_neighbors_now", "agessaman", "PASS" if nbr_a is not None else "FAIL", {
                "pubkey": pub,
                "neighbors_received": nbr_a is not None,
                "neighbors_retain": (nbr_a or {}).get("retain"),
                "neighbors_json": (nbr_a or {}).get("payload_json"),
                "log_tail": logs_1b[-600:],
            })
        except Exception as exc:
            record("agessaman_1b_neighbors_now", "agessaman", "FAIL", {"error": str(exc)})
        finally:
            stop_proc(ag_proc, signal.SIGKILL)
            stop_proc(comp_proc, signal.SIGTERM)

        # 1c: Proactive JWT renewal (username_pw_set + reconnect() without disconnect())
        comp_proc, comp_info = spawn_virtual_companion_cli("AgessamanVirt1C")
        ag_proc = None
        try:
            pub = comp_info["pubkey"].upper()
            data_dir = tempfile.mkdtemp(prefix="ag1c_")
            toml_path = os.path.join(data_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "SEA"\nlog_level = "DEBUG"\n\n'
                    f'[capture]\nconnection_type = "tcp"\ntcp_host = "127.0.0.1"\ntcp_port = {comp_info["port"]}\n'
                    f'data_dir = "{data_dir}"\nadvert_interval_hours = 0\ndrain_messages = false\n'
                    f'raw_duplicate_window = 0\njwt_renewal_interval = 5\njwt_renewal_threshold = 8\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nwebsocket_path = "/"\nqos = 0\nretain = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\ntoken_ttl = 12\n'
                )
            idx_a = admin.mark()
            ag_proc = subprocess.Popen(
                ["python3", "-m", "meshcore_packet_capture", "--no-env-files", "--config", toml_path, "--debug"],
                cwd=data_dir,
                env=child_env("/opt/observers/agessaman/src"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            st_init = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online",
                timeout_s=15.0,
            )
            mark_renew = admin.mark()
            time.sleep(8.0)
            send_companion_rx(comp_info["control_port"], "AG1CRENEW")
            pkt_post = admin.wait_for(
                mark_renew,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets"),
                timeout_s=8.0,
            )
            status_during_renew = [
                m["payload_json"]
                for m in admin.since(mark_renew)
                if pub in m["topic"].upper() and m["topic"].endswith("/status")
            ]
            logs_1c = stop_proc(ag_proc, signal.SIGTERM)
            ag_proc = None
            offline_lwt_spurious = any((s or {}).get("status") == "offline" for s in status_during_renew)
            status_kind = "PASS" if (st_init and pkt_post and not offline_lwt_spurious) else "FAIL"
            record("agessaman_1c_proactive_jwt_renewal", "agessaman", status_kind, {
                "pubkey": pub,
                "initial_online": st_init is not None,
                "post_renewal_packet_received": pkt_post is not None,
                "spurious_offline_lwt_during_reconnect": offline_lwt_spurious,
                "status_events_during_window": status_during_renew,
                "log_tail": logs_1c[-800:],
            })
        finally:
            stop_proc(ag_proc, signal.SIGKILL)
            stop_proc(comp_proc, signal.SIGTERM)

        # 1d: Unclean disconnect (SIGKILL) LWT stale-status check
        comp_proc, comp_info = spawn_virtual_companion_cli("AgessamanVirt1D")
        ag_proc = None
        try:
            pub = comp_info["pubkey"].upper()
            data_dir = tempfile.mkdtemp(prefix="ag1d_")
            toml_path = os.path.join(data_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "SEA"\nlog_level = "DEBUG"\n\n'
                    f'[capture]\nconnection_type = "tcp"\ntcp_host = "127.0.0.1"\ntcp_port = {comp_info["port"]}\n'
                    f'data_dir = "{data_dir}"\nadvert_interval_hours = 0\ndrain_messages = false\n'
                    f'stats_refresh_interval = 2\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nwebsocket_path = "/"\nqos = 0\nretain = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\n'
                )
            idx_a = admin.mark()
            ag_proc = subprocess.Popen(
                ["python3", "-m", "meshcore_packet_capture", "--no-env-files", "--config", toml_path, "--debug"],
                cwd=data_dir,
                env=child_env("/opt/observers/agessaman/src"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            st_online = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online",
                timeout_s=15.0,
            )
            time.sleep(2.5)
            mark_kill = admin.mark()
            ag_proc.kill()
            ag_proc.wait(timeout=5.0)
            ag_proc = None
            st_offline = admin.wait_for(
                mark_kill,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "offline",
                timeout_s=5.0,
            )
            record("agessaman_1d_unclean_kill_lwt", "agessaman", "PASS" if st_offline is not None else "FAIL", {
                "pubkey": pub,
                "online_timestamp": ((st_online or {}).get("payload_json") or {}).get("timestamp"),
                "offline_lwt_delivered": st_offline is not None,
                "offline_timestamp": ((st_offline or {}).get("payload_json") or {}).get("timestamp"),
            })
        finally:
            stop_proc(ag_proc, signal.SIGKILL)
            stop_proc(comp_proc, signal.SIGTERM)

        # =====================================================================
        # 2. Cisien/meshcoretomqtt
        # =====================================================================
        pty = VirtualRepeaterPty(name="CisienVirt2A")
        cis_proc: Optional[subprocess.Popen] = None
        try:
            slave_path = pty.start()
            comp_pub_b, comp_prv_b = generate_orlp_keypair(b"audit-remote-serial-companion-01")
            comp_pub_hex = comp_pub_b.hex().upper()
            comp_prv_hex = comp_prv_b.hex().upper()

            cis_dir = tempfile.mkdtemp(prefix="cis2a_")
            toml_path = os.path.join(cis_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "SEA"\nlog_level = "DEBUG"\nsync_time = false\n\n'
                    f'[serial]\nports = ["{slave_path}"]\nbaud_rate = 115200\ntimeout = 1\nwatchdog_timeout = 0\n\n'
                    f'[topics]\nstatus = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/status"\n'
                    f'packets = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/packets"\n'
                    f'debug = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/debug"\n\n'
                    f'[remote_serial]\nenabled = true\nallowed_companions = ["{comp_pub_hex}"]\n'
                    f'nonce_ttl = 120\ncommand_timeout = 5\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nkeepalive = 60\nqos = 0\nretain = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\n'
                )
            idx_a, idx_l = admin.mark(), limited.mark()
            cis_proc = subprocess.Popen(
                ["python3", "/opt/observers/cisien/mctomqtt.py", "--config", toml_path, "--debug"],
                cwd="/opt/observers/cisien",
                env=child_env("/opt/observers/cisien"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            pub = pty.pub_hex
            st_a = admin.wait_for(
                idx_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online",
                timeout_s=15.0,
            )
            # 2a: RX packet + debug drop + second RX packet proving socket stayed open
            pty.emit_rx_packet("1500AABBCCDD01", "AABB0001")
            pty.emit_debug("cisien-debug-payload")
            time.sleep(0.3)
            pty.emit_rx_packet("1500AABBCCDD02", "AABB0002")
            pkt1 = admin.wait_for(idx_a, lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets") and "1500AABBCCDD01" in m["payload_text"], timeout_s=8.0)
            pkt2 = admin.wait_for(idx_a, lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets") and "1500AABBCCDD02" in m["payload_text"], timeout_s=8.0)
            pkt1_l = limited.wait_for(idx_l, lambda m: pub in m["topic"].upper() and m["topic"].endswith("/packets") and "1500AABBCCDD01" in m["payload_text"], timeout_s=6.0)
            dbg_forwarded = any(pub in m["topic"].upper() and m["topic"].endswith("/debug") for m in admin.since(idx_a))
            pkt_json_l = (pkt1_l or {}).get("payload_json") or {}
            ok_2a = all([
                st_a is not None,
                not (st_a or {}).get("retain", True),
                pkt1 is not None,
                pkt2 is not None,
                not dbg_forwarded,
                "SNR" not in pkt_json_l and "RSSI" not in pkt_json_l and "score" not in pkt_json_l,
            ])
            record("cisien_2a_baseline_wss_and_debug", "cisien", "PASS" if ok_2a else "FAIL", {
                "pubkey": pub,
                "status_online": st_a is not None,
                "status_retain": (st_a or {}).get("retain"),
                "packet1_received": pkt1 is not None,
                "debug_silently_dropped": not dbg_forwarded,
                "packet2_after_debug_received": pkt2 is not None,
                "role3_packet_filtered": "SNR" not in pkt_json_l and "RSSI" not in pkt_json_l,
            })

            # 2b: Remote serial commands -> responses
            idx_rs_a, idx_rs_l = admin.mark(), limited.mark()
            now_s = int(time.time())
            cmd_jwt = sign_orlp_jwt(
                comp_pub_hex,
                comp_prv_hex,
                {"publicKey": comp_pub_hex, "command": "ver", "target": pub, "nonce": f"n-{now_s}", "iat": now_s, "exp": now_s + 30},
                uppercase_sig=True,
            )
            admin.client.publish(f"meshcore/SEA/{pub}/serial/commands", cmd_jwt, qos=1)
            resp_a = admin.wait_for(
                idx_rs_a,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/serial/responses"),
                timeout_s=10.0,
            )
            time.sleep(0.3)
            resp_l = any(pub in m["topic"].upper() and m["topic"].endswith("/serial/responses") for m in limited.since(idx_rs_l))
            ok_2b = (resp_a is not None) and (not resp_l) and ("ver" in pty.commands_received) and len((resp_a or {}).get("payload_text", "").split(".")) == 3
            record("cisien_2b_remote_serial", "cisien", "PASS" if ok_2b else "FAIL", {
                "commands_received_by_pty": list(pty.commands_received),
                "response_received_admin": resp_a is not None,
                "response_jwt_parts": len((resp_a or {}).get("payload_text", "").split(".")),
                "limited_blocked_from_responses": not resp_l,
            })

            # 2c: Unclean disconnect (SIGKILL) LWT test
            time.sleep(1.5)
            mark_kill = admin.mark()
            cis_proc.kill()
            cis_proc.wait(timeout=5.0)
            cis_proc = None
            st_off = admin.wait_for(
                mark_kill,
                lambda m: pub in m["topic"].upper() and m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "offline",
                timeout_s=5.0,
            )
            record("cisien_2c_unclean_kill_lwt", "cisien", "PASS" if st_off is not None else "FAIL", {
                "pubkey": pub,
                "online_timestamp": ((st_a or {}).get("payload_json") or {}).get("timestamp"),
                "offline_lwt_delivered": st_off is not None,
                "offline_timestamp": ((st_off or {}).get("payload_json") or {}).get("timestamp"),
            })
        finally:
            stop_proc(cis_proc, signal.SIGKILL)
            pty.stop()

        # 2d: Default iata = "XXX" rejection test
        pty_x = VirtualRepeaterPty(name="CisienVirtXXX")
        cis_x: Optional[subprocess.Popen] = None
        try:
            slave_path = pty_x.start()
            pub = pty_x.pub_hex
            cis_dir = tempfile.mkdtemp(prefix="cis2d_")
            toml_path = os.path.join(cis_dir, "config.toml")
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(
                    f'[general]\niata = "XXX"\nlog_level = "DEBUG"\nsync_time = false\n\n'
                    f'[serial]\nports = ["{slave_path}"]\nbaud_rate = 115200\ntimeout = 1\nwatchdog_timeout = 0\n\n'
                    f'[topics]\nstatus = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/status"\n'
                    f'packets = "meshcore/{{IATA}}/{{PUBLIC_KEY}}/packets"\n\n'
                    f'[remote_serial]\nenabled = true\n\n'
                    f'[[broker]]\nname = "audit-wss"\nenabled = true\nserver = "127.0.0.1"\nport = 8443\n'
                    f'transport = "websockets"\nkeepalive = 60\nqos = 0\nretain = true\n'
                    f'[broker.tls]\nenabled = true\nverify = true\n'
                    f'[broker.auth]\nmethod = "token"\naudience = "{args.audience}"\n'
                )
            idx_a = admin.mark()
            cis_x = subprocess.Popen(
                ["python3", "/opt/observers/cisien/mctomqtt.py", "--config", toml_path, "--debug"],
                cwd="/opt/observers/cisien",
                env=child_env("/opt/observers/cisien"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            time.sleep(2.5)
            logs_2d = stop_proc(cis_x, signal.SIGKILL)
            cis_x = None
            xxx_forwarded = any(pub in m["topic"].upper() and "/XXX/" in m["topic"].upper() for m in admin.since(idx_a))
            record("cisien_2d_default_xxx_iata", "cisien", "EXPECTED_QUIRK" if not xxx_forwarded else "FAIL", {
                "pubkey": pub,
                "xxx_status_forwarded": xxx_forwarded,
                "log_tail": logs_2d[-600:],
            })
        finally:
            stop_proc(cis_x, signal.SIGKILL)
            pty_x.stop()

        # =====================================================================
        # 3. OffbandMesh/meshcore-firmware
        # =====================================================================
        def run_offband(cli_args: list[str], extra_env: Optional[dict[str, str]] = None, timeout_s: float = 15.0) -> tuple[int, dict[str, Any], str]:
            proc = subprocess.Popen(
                ["/harness/shims/offband_host/offband_driver", *cli_args],
                env=child_env(extra=extra_env),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout_s, stderr_s = proc.communicate(timeout=timeout_s)
            parsed = json.loads(stdout_s.strip().splitlines()[-1]) if stdout_s.strip() else {}
            return proc.returncode, parsed, stderr_s[-500:]

        # 3a: Slimmed /packets (#727 sec4 omitting origin_id) over wss://
        idx_a = admin.mark()
        rc, ob_3a, err_3a = run_offband([
            "--url", "wss://127.0.0.1:8443/mqtt",
            "--audience", args.audience,
            "--iata", "SEA",
            "--transport", "wss",
            "--auth", "jwt",
            "--marker", "OB3A",
        ])
        pub = ob_3a.get("pubkey", "")
        st_a = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/status"), timeout_s=4.0)
        pkt_a = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/packets"), timeout_s=1.5)
        raw_a = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/raw"), timeout_s=1.5)
        nbr_a = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/neighbors"), timeout_s=1.5)
        ok_3a = ob_3a.get("connected") and ob_3a.get("stayed_up_after_publishes") and (pkt_a is not None)
        record("offband_3a_slim_packets_wss", "offband", "PASS" if ok_3a else "FAIL", {
            "driver_output": ob_3a,
            "status_received": st_a is not None,
            "slim_packets_received": pkt_a is not None,
            "raw_received": raw_a is not None,
            "neighbors_received": nbr_a is not None,
            "stderr": err_3a,
        })

        # 3b: Multi-transport (--no-slim-packet) over wss, tls, tcp + /neighbors retain check
        transport_cases = [
            ("wss", "wss://127.0.0.1:8443/mqtt", "OB3B_WSS"),
            ("tls", "mqtts://127.0.0.1:8444", "OB3B_TLS"),
            ("tcp", f"mqtt://{args.broker_host}:{args.broker_tcp_port}", "OB3B_TCP"),
        ]
        t_summary: dict[str, Any] = {}
        all_transports_ok = True
        for tr, uri, mark in transport_cases:
            idx_a = admin.mark()
            _, ob_res, ob_err = run_offband([
                "--url", uri,
                "--audience", args.audience,
                "--iata", "SEA",
                "--transport", tr,
                "--auth", "jwt",
                "--marker", mark,
                "--no-slim-packet",
            ])
            pub = ob_res.get("pubkey", "")
            st = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/status"), timeout_s=4.0)
            rw = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/raw"), timeout_s=4.0)
            nb = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/neighbors"), timeout_s=4.0)
            tr_ok = bool(ob_res.get("connected") and st and rw and nb)
            all_transports_ok = all_transports_ok and tr_ok
            entry_3b: dict[str, Any] = {
                "connected": ob_res.get("connected"),
                "status_received": st is not None,
                "raw_received": rw is not None,
                "neighbors_received": nb is not None,
                "neighbors_live_retain": (nb or {}).get("retain"),
                "stderr": ob_err,
            }
            if tr == "wss" and pub:
                probe = SubscriberMonitor("retain_probe", args.broker_host, args.broker_ws_port, args.admin_user, args.admin_pass)
                try:
                    probe.start(timeout_s=5.0)
                    time.sleep(1.5)
                    p_msgs = [m for m in probe.since(0) if pub in m["topic"].upper()]
                    entry_3b["status_persisted_retained"] = any(
                        m["topic"].endswith("/status") and m["retain"] for m in p_msgs
                    )
                    entry_3b["neighbors_persisted_retained"] = any(
                        m["topic"].endswith("/neighbors") and m["retain"] for m in p_msgs
                    )
                finally:
                    probe.stop()
            t_summary[tr] = entry_3b
        record("offband_3b_multi_transport_and_neighbors_retain", "offband", "PASS" if all_transports_ok else "FAIL", t_summary)

        # 3c: Non-UTC TZ=Asia/Tokyo timezone-less localtime_r timestamp check
        idx_a = admin.mark()
        _, ob_3c, err_3c = run_offband(
            ["--url", "wss://127.0.0.1:8443/mqtt", "--audience", args.audience, "--iata", "SEA",
             "--transport", "wss", "--auth", "jwt", "--marker", "OB3C",
             "--no-slim-packet", "--no-raw", "--no-neighbors"],
            extra_env={"TZ": "Asia/Tokyo"},
        )
        pub = ob_3c.get("pubkey", "")
        st_3c = admin.wait_for(idx_a, lambda m: pub and pub in m["topic"].upper() and m["topic"].endswith("/status"), timeout_s=4.0)
        ts_3c = ((st_3c or {}).get("payload_json") or {}).get("timestamp", "")
        has_tz_suffix = ts_3c.endswith("Z") or "+" in ts_3c
        record("offband_3c_non_utc_timezone", "offband", "EXPECTED_QUIRK" if (st_3c and not has_tz_suffix) else "FAIL", {
            "pubkey": pub,
            "tz_env": "Asia/Tokyo",
            "status_received": st_3c is not None,
            "timestamp_value": ts_3c,
            "has_timezone_suffix": has_tz_suffix,
        })

        # =====================================================================
        # 4. openhop-dev/openhop_repeater
        # =====================================================================
        def run_openhop(spec: dict[str, Any], timeout_s: float = 25.0) -> tuple[int, dict[str, Any], str]:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
                json.dump(spec, tf)
                cfg_path = tf.name
            try:
                proc = subprocess.Popen(
                    ["python3", f"{HARNESS_ROOT}/shims/openhop_driver.py", "--config-json", cfg_path],
                    env=child_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout_s, stderr_s = proc.communicate(timeout=timeout_s)
                parsed = json.loads(stdout_s.strip().splitlines()[-1]) if stdout_s.strip() else {}
                return proc.returncode, parsed, stderr_s[-800:]
            finally:
                try:
                    os.unlink(cfg_path)
                except OSError:
                    pass

        # 4a: Baseline WSS (/mqtt), untruncated client_id, packet+raw+neighbors, jwt_renew, clean disconnect
        idx_a = admin.mark()
        oh_rc, oh_res, oh_err = run_openhop({
            "jwt_expiry_minutes": 10,
            "timeout": 10.0,
            "disconnect_mode": "clean",
            "config": {
                "repeater": {"node_name": "OpenHopAudit4A", "mode": "forward"},
                "radio": {"frequency": 910525000, "bandwidth": 62500, "spreading_factor": 7, "coding_rate": 5},
                "mqtt_brokers": {
                    "iata_code": "SEA",
                    "status_interval": 60,
                    "brokers": [{
                        "name": "audit-wss",
                        "enabled": True,
                        "host": "127.0.0.1",
                        "port": 8443,
                        "transport": "websockets",
                        "audience": args.audience,
                        "use_jwt_auth": True,
                        "format": "letsmesh",
                        "retain_status": True,
                        "neighbors": True,
                        "tls": {"enabled": True, "insecure": False},
                    }],
                },
            },
            "actions": [
                {"kind": "packet", "payload": {"type": "PACKET", "direction": "rx", "raw": "1500AA112233", "SNR": "8.5", "RSSI": "-88", "packet_type": "5", "route": "F"}},
                {"kind": "raw", "raw_hex": "1500AA112233"},
                {"kind": "neighbors"},
                {"kind": "jwt_renew", "post_packet": {"type": "PACKET", "direction": "rx", "raw": "1500AA112244", "SNR": "7.5", "RSSI": "-90", "packet_type": "5", "route": "F"}},
            ],
        })
        pub = oh_res.get("pubkey", "")
        msgs_4a = [m for m in admin.since(idx_a) if pub and pub in m["topic"].upper()]
        has_online = any(m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online" for m in msgs_4a)
        has_offline = any(m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "offline" for m in msgs_4a)
        has_pkt1 = any(m["topic"].endswith("/packets") and "1500AA112233" in m["payload_text"] for m in msgs_4a)
        has_pkt2 = any(m["topic"].endswith("/packets") and "1500AA112244" in m["payload_text"] for m in msgs_4a)
        has_raw = any(m["topic"].endswith("/raw") for m in msgs_4a)
        has_nbr = any(m["topic"].endswith("/neighbors") for m in msgs_4a)
        cids = oh_res.get("client_ids", [])
        ok_4a = oh_rc == 0 and has_online and has_offline and has_pkt1 and has_pkt2 and has_raw and has_nbr
        record("openhop_4a_baseline_ws_and_jwt_renew", "openhop", "PASS" if ok_4a else "FAIL", {
            "client_ids": cids,
            "client_id_lengths": [len(c) for c in cids],
            "online_status": has_online,
            "offline_status": has_offline,
            "packet_pre_renew": has_pkt1,
            "packet_post_renew": has_pkt2,
            "raw_received": has_raw,
            "neighbors_received": has_nbr,
            "driver_result": oh_res,
            "stderr": oh_err,
        })

        # 4b: Default iata_code = "TEST" normalization
        idx_a = admin.mark()
        oh_rc_b, oh_res_b, oh_err_b = run_openhop({
            "jwt_expiry_minutes": 10,
            "timeout": 10.0,
            "disconnect_mode": "clean",
            "config": {
                "repeater": {"node_name": "OpenHopAudit4B", "mode": "forward"},
                "radio": {"frequency": 910525000, "bandwidth": 62500, "spreading_factor": 7, "coding_rate": 5},
                "mqtt_brokers": {
                    "iata_code": "TEST",
                    "status_interval": 60,
                    "brokers": [{
                        "name": "audit-test-iata",
                        "enabled": True,
                        "host": "127.0.0.1",
                        "port": 8443,
                        "transport": "websockets",
                        "audience": args.audience,
                        "use_jwt_auth": True,
                        "format": "letsmesh",
                        "retain_status": False,
                        "tls": {"enabled": True, "insecure": False},
                    }],
                },
            },
            "actions": [
                {"kind": "packet", "payload": {"type": "PACKET", "direction": "rx", "raw": "1500BBBB0001", "SNR": "9.0", "RSSI": "-85", "packet_type": "5", "route": "F"}},
            ],
        })
        pub = oh_res_b.get("pubkey", "")
        test_pkt = admin.wait_for(idx_a, lambda m: pub and f"meshcore/test/{pub}/packets" == m["topic"], timeout_s=4.0)
        record("openhop_4b_default_test_iata", "openhop", "PASS" if (oh_rc_b == 0 and test_pkt is not None) else "FAIL", {
            "pubkey": pub,
            "normalized_test_packet_received": test_pkt is not None,
            "observed_topic": (test_pkt or {}).get("topic"),
            "driver_result": oh_res_b,
        })

        # =====================================================================
        # 5. meshcore-dev/meshcore-ha
        # =====================================================================
        def run_ha(
            entry_data: dict[str, Any],
            actions: list[dict[str, Any]],
            disconnect_mode: str = "clean",
            allow_connect_failure: bool = False,
            timeout_s: float = 20.0,
        ) -> tuple[int, dict[str, Any], str, str]:
            vc = ThreadedVirtualCompanion(name="HA_VirtCompanion", allow_key_export=True)
            vc_port = vc.start()
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
                json.dump({
                    "companion_host": "127.0.0.1",
                    "companion_port": vc_port,
                    "entry_data": entry_data,
                    "actions": actions,
                    "disconnect_mode": disconnect_mode,
                    "allow_connect_failure": allow_connect_failure,
                    "timeout": 10.0,
                }, tf)
                cfg_path = tf.name
            try:
                proc = subprocess.Popen(
                    ["python3", f"{HARNESS_ROOT}/shims/ha_driver.py", "--config-json", cfg_path],
                    env=child_env(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                stdout_s, stderr_s = proc.communicate(timeout=timeout_s)
                parsed = json.loads(stdout_s.strip().splitlines()[-1]) if stdout_s.strip() else {}
                return proc.returncode, parsed, vc.pub_hex, stderr_s[-800:]
            finally:
                vc.stop()
                try:
                    os.unlink(cfg_path)
                except OSError:
                    pass

        def ha_broker_entry(iata: str, extra_broker: Optional[dict[str, Any]] = None, ttl: int = 3600) -> dict[str, Any]:
            b1 = {
                "enabled": True,
                "server": "127.0.0.1",
                "port": 8443,
                "transport": "websockets",
                "ws_path": "/",
                "use_tls": True,
                "tls_verify": True,
                "keepalive": 60,
                "use_auth_token": True,
                "token_audience": args.audience,
                "token_ttl_seconds": ttl,
                "payload_mode": "packet",
            }
            if extra_broker:
                b1.update(extra_broker)
            return {"mqtt_iata": iata, "mqtt_token_ttl_seconds": ttl, "mqtt_brokers": {"1": b1}}

        # 5a: Baseline WSS (/), packet mode, clean stop
        idx_a = admin.mark()
        ha_rc, ha_res, ha_pub, ha_err = run_ha(
            ha_broker_entry("SEA"),
            [{"kind": "rx_event", "raw_hex": "1500CC112233", "label": "pkt5a"}],
            disconnect_mode="clean",
        )
        msgs_5a = [m for m in admin.since(idx_a) if ha_pub in m["topic"].upper()]
        st_on = next((m for m in msgs_5a if m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "online"), None)
        st_off = next((m for m in msgs_5a if m["topic"].endswith("/status") and (m["payload_json"] or {}).get("status") == "offline"), None)
        pkt_5a = next((m for m in msgs_5a if m["topic"].endswith("/packets")), None)
        ok_5a = (
            ha_rc == 0
            and st_on is not None
            and not st_on.get("retain", True)
            and ((st_on.get("payload_json") or {}).get("source") == "meshcore-ha")
            and pkt_5a is not None
            and st_off is not None
        )
        record("ha_5a_baseline_wss", "meshcore-ha", "PASS" if ok_5a else "FAIL", {
            "pubkey": ha_pub,
            "online_status": st_on is not None,
            "online_retain": (st_on or {}).get("retain"),
            "source_field": ((st_on or {}).get("payload_json") or {}).get("source"),
            "packet_received": pkt_5a is not None,
            "clean_offline_received": st_off is not None,
            "stderr": ha_err,
        })

        # 5b: Abrupt socket close LWT test
        idx_a = admin.mark()
        _, ha_res_b, ha_pub_b, ha_err_b = run_ha(
            ha_broker_entry("SEA"),
            [{"kind": "sleep", "seconds": 1.5}],
            disconnect_mode="abrupt",
        )
        time.sleep(1.5)
        msgs_5b = [m for m in admin.since(idx_a) if ha_pub_b in m["topic"].upper() and m["topic"].endswith("/status")]
        st_on_b = next((m for m in msgs_5b if (m["payload_json"] or {}).get("status") == "online"), None)
        st_off_b = next((m for m in msgs_5b if (m["payload_json"] or {}).get("status") == "offline"), None)
        record("ha_5b_abrupt_lwt", "meshcore-ha", "PASS" if st_off_b is not None else "FAIL", {
            "pubkey": ha_pub_b,
            "online_timestamp": ((st_on_b or {}).get("payload_json") or {}).get("timestamp"),
            "offline_lwt_delivered": st_off_b is not None,
            "offline_timestamp": ((st_off_b or {}).get("payload_json") or {}).get("timestamp"),
        })

        # 5c: Custom /events topic without letsmesh.net hostname rewrite
        idx_a = admin.mark()
        ha_rc_c, _, ha_pub_c, _ = run_ha(
            ha_broker_entry("SEA", extra_broker={"topic_events": "meshcore/{IATA}/{PUBLIC_KEY}/events"}),
            [{"kind": "rx_event", "raw_hex": "1500DD112233", "label": "pkt5c"}],
            disconnect_mode="clean",
        )
        msgs_5c = [m for m in admin.since(idx_a) if ha_pub_c in m["topic"].upper()]
        events_fwd = any(m["topic"].endswith("/events") for m in msgs_5c)
        packets_fwd = any(m["topic"].endswith("/packets") for m in msgs_5c)
        record("ha_5c_custom_events_topic", "meshcore-ha", "EXPECTED_QUIRK" if (not events_fwd and not packets_fwd) else "FAIL", {
            "pubkey": ha_pub_c,
            "events_forwarded": events_fwd,
            "packets_forwarded": packets_fwd,
        })

        # 5d: Default mqtt_iata = "XYZ" against non-LetsMesh broker
        idx_a = admin.mark()
        _, ha_res_d, ha_pub_d, ha_err_d = run_ha(
            ha_broker_entry("XYZ"),
            [{"kind": "sleep", "seconds": 0.4}],
            disconnect_mode="clean",
            allow_connect_failure=True,
        )
        xyz_st = admin.wait_for(idx_a, lambda m: ha_pub_d in m["topic"].upper() and "/XYZ/" in m["topic"].upper(), timeout_s=2.0)
        record("ha_5d_default_xyz_iata", "meshcore-ha", "EXPECTED_QUIRK" if xyz_st is None else "PASS", {
            "pubkey": ha_pub_d,
            "xyz_status_forwarded": xyz_st is not None,
            "driver_result": ha_res_d,
            "stderr": ha_err_d,
        })

        # 5e: Reactive JWT renewal (TTL=60s clamp)
        if not args.skip_slow:
            auth_fail_before = int(admin.latest_sys_value("$SYS/broker/security/auth_failures") or "0")
            idx_a = admin.mark()
            ha_rc_e, ha_res_e, ha_pub_e, ha_err_e = run_ha(
                ha_broker_entry("SEA", ttl=60),
                [
                    {"kind": "rx_event", "raw_hex": "1500EE112201", "label": "pre_expire"},
                    {"kind": "sleep", "seconds": 63},
                    {"kind": "force_drop_for_reactive_renewal", "wait_seconds": 5},
                    {"kind": "rx_event", "raw_hex": "1500EE112202", "label": "post_renew"},
                ],
                disconnect_mode="clean",
                timeout_s=95.0,
            )
            time.sleep(2.5)
            auth_fail_after = int(admin.latest_sys_value("$SYS/broker/security/auth_failures") or "0")
            post_pkt = any(
                ha_pub_e in m["topic"].upper() and m["topic"].endswith("/packets") and "1500EE112202" in m["payload_text"]
                for m in admin.since(idx_a)
            )
            ok_5e = ha_rc_e == 0 and bool(ha_res_e.get("reactive_reconnected")) and post_pkt
            record("ha_5e_reactive_jwt_renewal", "meshcore-ha", "PASS" if ok_5e else "FAIL", {
                "pubkey": ha_pub_e,
                "reactive_reconnected": ha_res_e.get("reactive_reconnected"),
                "post_renewal_packet_received": post_pkt,
                "auth_failures_before": auth_fail_before,
                "auth_failures_after": auth_fail_after,
                "auth_failures_delta": auth_fail_after - auth_fail_before,
                "stderr": ha_err_e,
            })
        else:
            record("ha_5e_reactive_jwt_renewal", "meshcore-ha", "SKIPPED", {"reason": "--skip-slow enabled"})

        # =====================================================================
        # 6. Negative Auth Boundary Test (LAST, single failed handshake)
        # =====================================================================
        rc_neg, ob_neg, err_neg = run_offband([
            "--url", "wss://127.0.0.1:8443/mqtt",
            "--audience", "wrong.invalid.example",
            "--iata", "SEA",
            "--transport", "wss",
            "--auth", "jwt",
            "--marker", "NEG6",
        ], timeout_s=15.0)
        ok_neg = (rc_neg != 0) and (not ob_neg.get("connected", True))
        record("neg_6_wrong_audience_auth", "offband", "PASS" if ok_neg else "FAIL", {
            "returncode": rc_neg,
            "driver_output": ob_neg,
            "stderr": err_neg,
        })

        return {
            "upstream_repos": upstream_info,
            "total": len(results),
            "summary": {
                s: sum(1 for r in results if r["status"] == s)
                for s in ("PASS", "FAIL", "EXPECTED_QUIRK", "SKIPPED")
            },
            "results": results,
        }
    finally:
        if admin:
            admin.stop()
        if limited:
            limited.stop()
        stop_proc(wss_proxy, signal.SIGTERM)
        stop_proc(tls_proxy, signal.SIGTERM)


def main() -> int:
    parser = argparse.ArgumentParser(description="5-observer compatibility audit runner")
    parser.add_argument("--broker-host", default="meshcore-broker-main")
    parser.add_argument("--broker-ws-port", type=int, default=8883)
    parser.add_argument("--broker-tcp-port", type=int, default=1883)
    parser.add_argument("--audience", default="audit.meshcore.local")
    parser.add_argument("--admin-user", default="audit_admin")
    parser.add_argument("--admin-pass", default="audit_admin_secret")
    parser.add_argument("--limited-user", default="audit_limited")
    parser.add_argument("--limited-pass", default="audit_limited_secret")
    parser.add_argument("--output", default="/tmp/audit_results.json")
    parser.add_argument("--skip-slow", action="store_true")
    args = parser.parse_args()

    report = run_all_tests(args)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
