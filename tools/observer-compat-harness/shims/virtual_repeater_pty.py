#!/usr/bin/env python3
"""
Linux PTY emulator for a MeshCore Repeater serial CLI.

Allows unmodified Cisien/meshcoretomqtt to connect over a real TTY device path,
read node identity & keys, poll device stats, execute remote-serial CLI
commands, and receive realistic U RAW: / U: RX / DEBUG log lines.
"""

from __future__ import annotations

import os
import pty
import select
import threading
import time
from typing import Optional

try:
    from .virtual_companion import generate_orlp_keypair
except ImportError:
    from virtual_companion import generate_orlp_keypair


class VirtualRepeaterPty:
    """PTY-backed MeshCore Repeater serial CLI emulator."""

    def __init__(
        self,
        name: str = "VirtRepeater",
        radio_info: str = "910.525,62.5,7,5",
        firmware_version: str = "v1.15.0",
        board_type: str = "RAK4631",
        seed: Optional[bytes] = None,
    ) -> None:
        self.name = name
        self.radio_info = radio_info
        self.firmware_version = firmware_version
        self.board_type = board_type
        self.pub_key, self.prv_key = generate_orlp_keypair(seed)
        self.pub_hex = self.pub_key.hex().upper()
        self.prv_hex = self.prv_key.hex().upper()

        self._master_fd, self._slave_fd = pty.openpty()
        self.slave_path = os.ttyname(self._slave_fd)
        self._stop = threading.Event()
        self._write_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.commands_received: list[str] = []
        self._start_ts = time.monotonic()

    def start(self) -> str:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self.slave_path

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        for fd in (self._master_fd, self._slave_fd):
            try:
                os.close(fd)
            except OSError:
                pass

    def _write(self, text: str) -> None:
        data = text.encode("utf-8")
        with self._write_lock:
            os.write(self._master_fd, data)

    def emit_rx_packet(
        self,
        raw_hex: str,
        hash_hex: str,
        *,
        snr: int = 8,
        rssi: int = -89,
        score: int = 1000,
        duration: int = 142,
        packet_type: str = "5",
        route: str = "F",
        path: Optional[str] = None,
    ) -> None:
        now = time.localtime()
        t_str = time.strftime("%H:%M:%S", now)
        d_str = f"{now.tm_mday}/{now.tm_mon}/{now.tm_year}"
        self._write(f"{t_str} - {d_str} U RAW: {raw_hex}\r\n")
        byte_len = len(raw_hex) // 2
        payload_len = max(1, byte_len - 4)
        line = (
            f"{t_str} - {d_str} U: RX, len={byte_len} (type={packet_type}, route={route}, payload_len={payload_len})"
            f" SNR={snr} RSSI={rssi} score={score} time={duration} hash={hash_hex}"
        )
        if route == "D" and path:
            line += f" [{path}]"
        self._write(line + "\r\n")

    def emit_debug(self, msg: str) -> None:
        self._write(f"DEBUG: {msg}\r\n")

    def _handle_command(self, cmd: str) -> None:
        cmd_clean = cmd.strip()
        if not cmd_clean:
            return
        self.commands_received.append(cmd_clean)
        uptime = max(1, int(time.monotonic() - self._start_ts))

        if cmd_clean.startswith("time "):
            self._write("-> > OK\r\n")
        elif cmd_clean == "get name":
            self._write(f"-> > {self.name}\r\n")
        elif cmd_clean == "get public.key":
            self._write(f"-> > {self.pub_hex}\r\n")
        elif cmd_clean == "get prv.key":
            self._write(f"-> > {self.prv_hex}\r\n")
        elif cmd_clean == "get radio":
            self._write(f"-> > {self.radio_info}\r\n")
        elif cmd_clean == "ver":
            self._write(f"-> {self.firmware_version}\r\n")
        elif cmd_clean == "board":
            self._write(f"-> {self.board_type}\r\n")
        elif cmd_clean == "stats-core":
            self._write(
                f'-> {{"battery_mv":4120,"uptime_secs":{uptime},"errors":0,"queue_len":0}}\r\n'
            )
        elif cmd_clean == "stats-radio":
            self._write('-> {"noise_floor":-109,"tx_air_secs":12,"rx_air_secs":240}\r\n')
        elif cmd_clean == "stats-packets":
            self._write('-> {"recv":42,"sent":3,"recv_errors":0}\r\n')
        elif cmd_clean == "clock":
            self._write(f"-> > {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\r\n")
        else:
            self._write(f"-> > echo:{cmd_clean}\r\n")

    def _loop(self) -> None:
        buf = b""
        while not self._stop.is_set():
            try:
                rlist, _, _ = select.select([self._master_fd], [], [], 0.05)
                if not rlist:
                    continue
                chunk = os.read(self._master_fd, 4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf or b"\r" in buf:
                    idx_n = buf.find(b"\n")
                    idx_r = buf.find(b"\r")
                    indices = [i for i in (idx_n, idx_r) if i >= 0]
                    split_at = min(indices)
                    line_bytes = buf[:split_at]
                    buf = buf[split_at + 1 :]
                    cmd = line_bytes.decode("utf-8", errors="replace").strip()
                    if cmd:
                        self._handle_command(cmd)
            except OSError:
                break
