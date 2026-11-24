#!/usr/bin/env python3
"""
Minimal thin driver exercising unmodified openhop-dev/openhop_repeater MQTT publisher
(repeater/data_acquisition/mqtt_handler.py & neighbors_publisher.py) against a live broker.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

OPENHOP_REPO = "/opt/observers/openhop"
if OPENHOP_REPO not in sys.path:
    sys.path.insert(0, OPENHOP_REPO)

from openhop_core.protocol.identity import LocalIdentity
from repeater.data_acquisition.mqtt_handler import MeshCoreToMqttPusher
from repeater.neighbors_publisher import build_neighbors_payload


def _wait_until(pred, timeout_s: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Drive unmodified openhop_repeater MQTT pusher")
    parser.add_argument("--config-json", required=True)
    args = parser.parse_args()

    with open(args.config_json, "r", encoding="utf-8") as f:
        spec = json.load(f)

    identity = LocalIdentity()
    pub_hex = identity.get_public_key().hex().upper()
    pusher = MeshCoreToMqttPusher(
        identity,
        spec["config"],
        jwt_expiry_minutes=float(spec.get("jwt_expiry_minutes", 10)),
        stats_provider=lambda: {"uptime_secs": 120, "packets_sent": 3, "packets_received": 15},
    )

    result: dict = {
        "observer": "openhop_repeater",
        "pubkey": pub_hex,
        "client_ids": [c.client._client_id.decode("utf-8", errors="replace") for c in pusher.connections],
        "connected": False,
        "reconnected": False,
        "published": {},
        "errors": [],
    }

    try:
        pusher.connect()
        ok = _wait_until(lambda: all(c.is_connected() for c in pusher.connections), timeout_s=spec.get("timeout", 10.0))
        result["connected"] = ok
        if not ok:
            result["errors"].append("Timed out connecting openhop_repeater to broker")
            print(json.dumps(result))
            return 1

        # Wait briefly for initial status heartbeat published in _on_broker_connected
        time.sleep(0.4)

        for action in spec.get("actions", []):
            kind = action["kind"]
            if kind == "packet":
                res = pusher.publish_packet(action["payload"])
                result["published"]["packet"] = len(res)
            elif kind == "raw":
                res = pusher.publish_raw_data(action["raw_hex"])
                result["published"]["raw"] = len(res)
            elif kind == "neighbors":
                nbr_payload = build_neighbors_payload(
                    origin=pusher.node_name,
                    origin_id=pub_hex,
                    self_scopes="sea-mesh",
                    entries=[
                        {
                            "pubkey": "AA" * 32,
                            "snr": 7.5,
                            "heard_secs_ago": 15,
                            "scopes": "sea-mesh",
                            "status": "responded",
                        }
                    ],
                    total_neighbors=1,
                    queried_neighbors=1,
                    self_default_scope="sea-mesh",
                )
                res = pusher.publish_neighbors(nbr_payload)
                result["published"]["neighbors"] = len(res)
            elif kind == "jwt_renew":
                conn = pusher.connections[0]
                conn.reconnect_for_token_expiry()
                time.sleep(0.3)
                # Speed up 5s default reconnect timer for deterministic test or wait up to 10s
                reconn_ok = _wait_until(lambda: conn.is_connected(), timeout_s=10.0)
                result["reconnected"] = reconn_ok
                if not reconn_ok:
                    result["errors"].append("openhop_repeater proactive JWT renewal reconnect failed")
                else:
                    time.sleep(0.2)
                    pusher.publish_packet(action["post_packet"])
                    result["published"]["post_renewal_packet"] = True
            elif kind == "sleep":
                time.sleep(float(action.get("seconds", 1.0)))

        if spec.get("disconnect_mode", "clean") == "clean":
            pusher.disconnect()
            time.sleep(0.3)
        elif spec.get("disconnect_mode") == "abrupt":
            for conn in pusher.connections:
                try:
                    sock = conn.client.socket()
                    if sock:
                        sock.close()
                except Exception:
                    pass
                try:
                    conn.client.loop_stop()
                except Exception:
                    pass
    except Exception as exc:
        result["errors"].append(str(exc))
    finally:
        if spec.get("disconnect_mode", "clean") == "clean":
            try:
                pusher.disconnect()
            except Exception:
                pass

    print(json.dumps(result))
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
