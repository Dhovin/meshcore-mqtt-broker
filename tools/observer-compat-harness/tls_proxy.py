#!/usr/bin/env python3
"""Minimal stdlib asyncio TCP TLS terminator for testing wss:// and mqtts:// links."""

from __future__ import annotations

import argparse
import asyncio
import signal
import ssl


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(target_host, target_port)
    except OSError:
        client_writer.close()
        return

    t1 = asyncio.create_task(_pipe(client_reader, upstream_writer))
    t2 = asyncio.create_task(_pipe(upstream_reader, client_writer))
    await asyncio.gather(t1, t2, return_exceptions=True)


async def _serve(args: argparse.Namespace) -> None:
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    server = await asyncio.start_server(
        lambda r, w: _handle_client(r, w, args.target_host, args.target_port),
        host=args.listen_host,
        port=args.listen_port,
        ssl=ssl_ctx,
    )
    print(
        f"[tls_proxy] Listening TLS on {args.listen_host}:{args.listen_port} -> {args.target_host}:{args.target_port}",
        flush=True,
    )
    try:
        await stop_event.wait()
    finally:
        server.close()
        await server.wait_closed()


def main() -> int:
    parser = argparse.ArgumentParser(description="Asyncio TLS proxy for MQTT/WebSocket audit harness")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    asyncio.run(_serve(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
