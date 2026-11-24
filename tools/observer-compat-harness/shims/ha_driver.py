#!/usr/bin/env python3
"""
Thin Home Assistant + API shim to execute unmodified meshcore-dev/meshcore-ha
(custom_components/meshcore/mqtt_uploader.py) against a live broker and VirtualCompanionRadio.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import logging
import os
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from meshcore import MeshCore


def _install_ha_and_pkg_stubs() -> None:
    """Install minimal homeassistant and custom_components.meshcore package stubs."""
    ha_repo = "/opt/observers/meshcore-ha"
    pkg_dir = os.path.join(ha_repo, "custom_components", "meshcore")

    ha_mod = types.ModuleType("homeassistant")
    ha_core = types.ModuleType("homeassistant.core")
    ha_ce = types.ModuleType("homeassistant.config_entries")
    ha_const = types.ModuleType("homeassistant.const")
    ha_helpers = types.ModuleType("homeassistant.helpers")
    ha_cv = types.ModuleType("homeassistant.helpers.config_validation")
    ha_selector = types.ModuleType("homeassistant.helpers.selector")
    voluptuous = types.ModuleType("voluptuous")

    class HomeAssistant:
        def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
            self.loop = loop
            self._executor = ThreadPoolExecutor(max_workers=4)

        async def async_add_executor_job(self, target, *args):
            return await self.loop.run_in_executor(self._executor, target, *args)

        def async_create_task(self, coro):
            return self.loop.create_task(coro)

    @dataclass
    class ConfigEntry:
        entry_id: str
        data: dict[str, Any]
        options: dict[str, Any] = field(default_factory=dict)

    ha_core.HomeAssistant = HomeAssistant
    ha_ce.ConfigEntry = ConfigEntry
    ha_mod.core = ha_core
    ha_mod.config_entries = ha_ce
    ha_mod.const = ha_const
    ha_mod.helpers = ha_helpers
    ha_const.Platform = types.SimpleNamespace(SENSOR="sensor", BINARY_SENSOR="binary_sensor")

    sys.modules["homeassistant"] = ha_mod
    sys.modules["homeassistant.core"] = ha_core
    sys.modules["homeassistant.config_entries"] = ha_ce
    sys.modules["homeassistant.const"] = ha_const
    sys.modules["homeassistant.helpers"] = ha_helpers
    sys.modules["homeassistant.helpers.config_validation"] = ha_cv
    sys.modules["homeassistant.helpers.selector"] = ha_selector
    sys.modules["voluptuous"] = voluptuous

    cc_mod = types.ModuleType("custom_components")
    cc_mod.__path__ = [os.path.join(ha_repo, "custom_components")]
    cc_mc = types.ModuleType("custom_components.meshcore")
    cc_mc.__path__ = [pkg_dir]
    sys.modules["custom_components"] = cc_mod
    sys.modules["custom_components.meshcore"] = cc_mc


def _load_submodule(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class CompanionApiShim:
    """Adapter exposing the exact `.api` interface MeshCoreMqttUploader calls."""

    def __init__(self, mc: MeshCore) -> None:
        self._mc = mc
        self.self_info = dict(mc.self_info or {})
        self.node_name = str(self.self_info.get("name") or "MeshCore-HA")

    def command_parameters(self, method_name: str):
        mapping = {
            "send_device_query": self._mc.commands.send_device_query,
            "get_stats_core": self._mc.commands.get_stats_core,
            "get_stats_radio": self._mc.commands.get_stats_radio,
            "get_stats_packets": self._mc.commands.get_stats_packets,
            "export_private_key": self._mc.commands.export_private_key,
        }
        return {} if method_name in mapping else None

    async def exchange(self, method_name: str, deadline: float = 5.0):
        fn = getattr(self._mc.commands, method_name)
        return await asyncio.wait_for(fn(), timeout=deadline)


async def _run(spec: dict[str, Any]) -> int:
    _install_ha_and_pkg_stubs()
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

    ha_repo = "/opt/observers/meshcore-ha"
    pkg_dir = os.path.join(ha_repo, "custom_components", "meshcore")
    _load_submodule("custom_components.meshcore.const", os.path.join(pkg_dir, "const.py"))
    _load_submodule("custom_components.meshcore.config", os.path.join(pkg_dir, "config.py"))
    uploader_mod = _load_submodule(
        "custom_components.meshcore.mqtt_uploader",
        os.path.join(pkg_dir, "mqtt_uploader.py"),
    )

    mc = await MeshCore.create_tcp(spec["companion_host"], int(spec["companion_port"]))
    self_info = mc.self_info or {}
    pubkey = str(self_info.get("public_key") or "").upper()
    api = CompanionApiShim(mc)

    hass = HomeAssistant(asyncio.get_running_loop())
    entry = ConfigEntry(
        entry_id="ha-audit-entry",
        data={
            "name": self_info.get("name", "MeshCore-HA"),
            "pubkey": pubkey,
            **spec["entry_data"],
        },
        options={},
    )

    logger = logging.getLogger("ha_driver")
    logging.basicConfig(level=logging.INFO)
    uploader = uploader_mod.MeshCoreMqttUploader(
        hass, logger, entry, api=api, integration_version="3.0.5"
    )

    result: dict[str, Any] = {
        "observer": "meshcore-ha",
        "pubkey": pubkey,
        "client_ids": [],
        "connected": False,
        "published": [],
        "errors": [],
    }

    try:
        await uploader.async_start()
        result["client_ids"] = [
            info["client"]._client_id.decode("utf-8", errors="replace")
            for info in uploader._clients
        ]

        deadline = asyncio.get_running_loop().time() + float(spec.get("timeout", 10.0))
        while asyncio.get_running_loop().time() < deadline:
            if uploader._clients and all(info.get("connected") for info in uploader._clients):
                result["connected"] = True
                break
            await asyncio.sleep(0.1)

        if not result["connected"] and not spec.get("allow_connect_failure", False):
            result["errors"].append("meshcore-ha uploader did not connect to all configured brokers")

        # Give initial online status publish a moment to flush
        await asyncio.sleep(0.3)

        for action in spec.get("actions", []):
            kind = action["kind"]
            if kind == "rx_event":
                await uploader.async_publish_raw_event(
                    "RX_LOG_DATA",
                    {
                        "payload": action["raw_hex"],
                        "snr": 8.5,
                        "rssi": -88,
                        "score": 1000,
                        "duration": 120,
                    },
                )
                result["published"].append(action.get("label", "rx_event"))
            elif kind == "sleep":
                await asyncio.sleep(float(action.get("seconds", 1.0)))
            elif kind == "force_drop_for_reactive_renewal":
                # Drop the underlying socket without clearing tokens so paho auto-reconnects
                # after the short TTL expires, hitting broker auth refusal -> reactive refresh!
                for info in uploader._clients:
                    sock = info["client"].socket()
                    if sock:
                        sock.close()
                wait_s = float(action.get("wait_seconds", 6.0))
                await asyncio.sleep(wait_s)
                deadline2 = asyncio.get_running_loop().time() + 10.0
                reconnected = False
                while asyncio.get_running_loop().time() < deadline2:
                    if uploader._clients and all(info.get("connected") for info in uploader._clients):
                        reconnected = True
                        break
                    await asyncio.sleep(0.2)
                result["reactive_reconnected"] = reconnected
                if not reconnected:
                    result["errors"].append("meshcore-ha reactive JWT renewal failed to reconnect")

        mode = spec.get("disconnect_mode", "clean")
        if mode == "clean":
            await uploader.async_stop()
            await asyncio.sleep(0.2)
        elif mode == "abrupt":
            # Kill underlying sockets WITHOUT sending MQTT DISCONNECT so broker fires LWT
            for info in uploader._clients:
                client = info["client"]
                try:
                    sock = client.socket()
                    if sock:
                        sock.close()
                except Exception:
                    pass
                try:
                    client.loop_stop()
                except Exception:
                    pass
    except Exception as exc:
        result["errors"].append(str(exc))
    finally:
        try:
            await mc.disconnect()
        except Exception:
            pass

    print(json.dumps(result))
    return 0 if not result["errors"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Drive unmodified meshcore-ha MQTT uploader")
    parser.add_argument("--config-json", required=True)
    args = parser.parse_args()
    with open(args.config_json, "r", encoding="utf-8") as f:
        spec = json.load(f)
    return asyncio.run(_run(spec))


if __name__ == "__main__":
    raise SystemExit(main())
