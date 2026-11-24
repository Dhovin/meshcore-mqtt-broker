#!/usr/bin/env python3
"""
Virtual MeshCore Companion Radio speaking the meshcore_py TCP binary protocol.

Allows unmodified agessaman/meshcore-packet-capture and meshcore-dev/meshcore-ha
to connect via MeshCore.create_tcp(), authenticate via on-device signing or
private-key export, query telemetry stats, run neighbor discovery, and receive
injected RX LoRa frames (PUSH_CODE_LOG_RX_DATA = 0x88).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import struct
import threading
import time
from typing import Optional

from ed25519_orlp import ed25519_create_keypair, ed25519_sign


def generate_orlp_keypair(seed: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Return (public_key_32B, expanded_private_key_64B) in orlp/ed25519 format."""
    if seed is None:
        seed32 = os.urandom(32)
    elif len(seed) != 32:
        seed32 = hashlib.sha256(seed).digest()
    else:
        seed32 = seed
    pub_32, prv_64, _ = ed25519_create_keypair(seed32)
    return pub_32, prv_64


class VirtualCompanionRadio:
    """Asyncio TCP emulator for a MeshCore Companion radio."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        name: str = "VirtCompanion",
        seed: Optional[bytes] = None,
        allow_key_export: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.name = name
        self.pub_key, self.prv_key = generate_orlp_keypair(seed)
        self.pub_hex = self.pub_key.hex().upper()
        self.prv_hex = self.prv_key.hex().upper()
        self.allow_key_export = allow_key_export
        self.neighbor_pub, _ = generate_orlp_keypair(b"virtual-neighbor-repeater-000001")
        self._server: Optional[asyncio.AbstractServer] = None
        self._clients: set[asyncio.StreamWriter] = set()
        self._sign_buf = bytearray()
        self._start_time = time.monotonic()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        return self.port

    async def stop(self) -> None:
        for w in list(self._clients):
            try:
                w.close()
            except OSError:
                pass
        self._clients.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @staticmethod
    def _encode_frame(payload: bytes) -> bytes:
        return b"\x3e" + len(payload).to_bytes(2, "little") + payload

    async def broadcast_frame(self, payload: bytes) -> None:
        frame = self._encode_frame(payload)
        dead: list[asyncio.StreamWriter] = []
        for w in list(self._clients):
            try:
                w.write(frame)
                await w.drain()
            except OSError:
                dead.append(w)
        for w in dead:
            self._clients.discard(w)

    async def push_rx_log_data(self, raw_packet: bytes, snr_db: float = 8.5, rssi_dbm: int = -88) -> None:
        """Push PUSH_CODE_LOG_RX_DATA (0x88) frame matching Companion firmware."""
        snr_scaled = max(-128, min(127, int(round(snr_db * 4.0))))
        rssi_clamped = max(-128, min(127, int(rssi_dbm)))
        frame_payload = struct.pack("<Bbb", 0x88, snr_scaled, rssi_clamped) + raw_packet
        await self.broadcast_frame(frame_payload)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._clients.add(writer)
        try:
            while True:
                marker = await reader.read(1)
                if not marker:
                    break
                if marker != b"\x3c":
                    continue
                len_bytes = await reader.readexactly(2)
                frame_len = int.from_bytes(len_bytes, "little")
                if frame_len == 0 or frame_len > 4096:
                    continue
                payload = await reader.readexactly(frame_len)
                await self._dispatch_command(payload, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            try:
                writer.close()
            except OSError:
                pass

    async def _send(self, writer: asyncio.StreamWriter, payload: bytes) -> None:
        writer.write(self._encode_frame(payload))
        await writer.drain()

    async def _dispatch_command(self, data: bytes, writer: asyncio.StreamWriter) -> None:
        cmd = data[0]

        if cmd == 1:  # CommandType.APP_START -> PacketType.SELF_INFO (5)
            payload = (
                struct.pack(
                    "<BBBB32siiBBBBIIBB",
                    5,
                    1,      # adv_type
                    20,     # tx_power
                    22,     # max_tx_power
                    self.pub_key,
                    int(47.6062 * 1e6),
                    int(-122.3321 * 1e6),
                    0,      # multi_acks
                    0,      # adv_loc_policy
                    0,      # telemetry_mode
                    0,      # manual_add_contacts
                    910525, # freq -> 910.525 MHz
                    62500,  # bw -> 62.5 kHz
                    7,      # sf
                    5,      # cr
                )
                + self.name.encode("utf-8")
            )
            await self._send(writer, payload)

        elif cmd == 4:  # GET_CONTACTS
            await self._send(writer, struct.pack("<BI", 2, 0))
            await self._send(writer, struct.pack("<BI", 4, int(time.time())))

        elif cmd == 5:  # GET_DEVICE_TIME -> CURRENT_TIME (9)
            await self._send(writer, struct.pack("<BI", 9, int(time.time())))

        elif cmd == 6:  # SET_DEVICE_TIME
            await self._send(writer, b"\x00")

        elif cmd == 10:  # SYNC_NEXT_MESSAGE
            await self._send(writer, bytes([10]))  # NO_MORE_MSGS

        elif cmd == 11 or cmd == 12 or cmd == 8 or cmd == 14:  # SET_* -> OK
            await self._send(writer, b"\x00")

        elif cmd == 20:  # GET_BATT_AND_STORAGE -> BATTERY (12)
            await self._send(writer, struct.pack("<BHII", 12, 4120, 128, 1024))

        elif cmd == 22:  # DEVICE_QEURY -> DEVICE_INFO (13)
            fw_build = b"2026-11-01\x00\x00"[:12].ljust(12, b"\x00")
            model = b"Heltec V3\x00".ljust(40, b"\x00")
            ver = b"v1.15.0\x00".ljust(20, b"\x00")
            payload = (
                struct.pack("<BBBBI", 13, 10, 16, 8, 0)
                + fw_build
                + model
                + ver
                + struct.pack("<BB", 0, 0)
            )
            await self._send(writer, payload)

        elif cmd == 23:  # EXPORT_PRIVATE_KEY
            if self.allow_key_export:
                await self._send(writer, bytes([14]) + self.prv_key)
            else:
                await self._send(writer, bytes([15]))  # DISABLED

        elif cmd == 33:  # SIGN_START
            self._sign_buf.clear()
            await self._send(writer, struct.pack("<BBI", 19, 0, 4096))

        elif cmd == 34:  # SIGN_DATA
            self._sign_buf.extend(data[1:])
            await self._send(writer, b"\x00")

        elif cmd == 35:  # SIGN_FINISH
            sig = ed25519_sign(bytes(self._sign_buf), self.pub_key, self.prv_key)
            self._sign_buf.clear()
            await self._send(writer, bytes([20]) + sig)

        elif cmd == 40:  # GET_CUSTOM_VARS
            await self._send(writer, bytes([21]))

        elif cmd == 55:  # SEND_CONTROL_DATA (NODE_DISCOVER_REQ = 0x80)
            await self._send(writer, b"\x00")
            if len(data) >= 7 and (data[1] & 0xF0) == 0x80:
                tag_bytes = data[3:7]
                # Push CONTROL_DATA (0x8E) carrying NODE_DISCOVER_RESP (0x90 | REPEATER=0x02)
                push_payload = (
                    struct.pack("<BbbB", 0x8E, 36, -85, 0)
                    + bytes([0x92])
                    + struct.pack("<b", 32)
                    + tag_bytes
                    + self.neighbor_pub
                )
                await self.broadcast_frame(push_payload)

        elif cmd == 56:  # GET_STATS
            sub = data[1] if len(data) > 1 else 0
            uptime = max(1, int(time.monotonic() - self._start_time))
            if sub == 0:
                await self._send(writer, struct.pack("<BBHIHB", 24, 0, 4120, uptime, 0, 0))
            elif sub == 1:
                await self._send(writer, struct.pack("<BBhbbII", 24, 1, -109, -88, 34, 10, 120))
            elif sub == 2:
                await self._send(writer, struct.pack("<BBIIIIIII", 24, 2, 42, 3, 2, 1, 38, 4, 0))
            else:
                await self._send(writer, struct.pack("<BB", 1, 2))

        elif cmd == 64:  # GET_DEFAULT_FLOOD_SCOPE
            await self._send(writer, bytes([28]))  # 1-byte sentinel (unset)

        else:
            await self._send(writer, b"\x00")


def make_sample_meshcore_packet(marker: str, route: str = "F") -> bytes:
    """Construct a valid minimal MeshCore RF packet for PUSH_CODE_LOG_RX_DATA.

    Layout:
      header (1B): ver=0, payload_type=0x05 (GRP_TXT) -> (0x05 << 2) | route_code
      path_len (1B): 0x00 (flood 0 hops) or 0x02 (direct 2x1B hops)
      path (0 or 2B)
      payload: channel_hash (1B) + cipher_mac (2B) + marker bytes
    """
    route_code = 0x01 if route.upper() == "F" else 0x02
    header = (0x05 << 2) | route_code
    if route_code == 0x02:
        path_bytes = b"\x02\xaa\xbb"
    else:
        path_bytes = b"\x00"
    payload = b"\x11\x22\x33" + marker.encode("utf-8")
    return bytes([header]) + path_bytes + payload


class ThreadedVirtualCompanion:
    """Runs VirtualCompanionRadio in a dedicated background asyncio thread."""

    def __init__(self, name: str = "VirtCompanion", allow_key_export: bool = True) -> None:
        self._radio = VirtualCompanionRadio(name=name, allow_key_export=allow_key_export)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self.port: int = 0

    @property
    def pub_hex(self) -> str:
        return self._radio.pub_hex

    @property
    def prv_hex(self) -> str:
        return self._radio.prv_hex

    def start(self) -> int:
        def _run() -> None:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self.port = self._loop.run_until_complete(self._radio.start())
            self._ready.set()
            try:
                self._loop.run_forever()
            finally:
                self._loop.run_until_complete(self._radio.stop())
                self._loop.close()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)
        return self.port

    def push_rx_packet(self, marker: str, route: str = "F", snr_db: float = 8.5, rssi_dbm: int = -88) -> None:
        if not self._loop:
            return
        pkt = make_sample_meshcore_packet(marker, route=route)
        fut = asyncio.run_coroutine_threadsafe(
            self._radio.push_rx_log_data(pkt, snr_db=snr_db, rssi_dbm=rssi_dbm),
            self._loop,
        )
        fut.result(timeout=3.0)

    def stop(self) -> None:
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=3.0)


async def _run_cli(args: argparse.Namespace) -> int:
    radio = VirtualCompanionRadio(
        host=args.host,
        port=args.port,
        name=args.name,
        allow_key_export=not args.disable_key_export,
    )
    port = await radio.start()

    async def handle_ctrl(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            req = json.loads(line.decode("utf-8"))
            action = req.get("action")
            if action == "rx":
                pkt = make_sample_meshcore_packet(req.get("marker", "test"), route=req.get("route", "F"))
                await radio.push_rx_log_data(pkt, snr_db=float(req.get("snr", 8.5)), rssi_dbm=int(req.get("rssi", -88)))
                writer.write(b'{"ok":true}\n')
            elif action == "info":
                writer.write((json.dumps({"pubkey": radio.pub_hex, "port": port}) + "\n").encode("utf-8"))
            else:
                writer.write(b'{"ok":false,"error":"unknown"}\n')
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    ctrl = await asyncio.start_server(handle_ctrl, "127.0.0.1", args.control_port)
    ctrl_port = ctrl.sockets[0].getsockname()[1]
    print(json.dumps({"port": port, "control_port": ctrl_port, "pubkey": radio.pub_hex}), flush=True)

    stop_event = asyncio.Event()
    try:
        await stop_event.wait()
    finally:
        ctrl.close()
        await ctrl.wait_closed()
        await radio.stop()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Virtual MeshCore Companion TCP server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--control-port", type=int, default=0)
    parser.add_argument("--name", default="VirtCompanion")
    parser.add_argument("--disable-key-export", action="store_true")
    args = parser.parse_args()
    try:
        return asyncio.run(_run_cli(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
