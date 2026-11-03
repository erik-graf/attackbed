"""AttackMate input loading and target enrichment."""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any
from typing import Optional

from attacklog_correlator.config import HostResolver, guess_attacker_host_from_path
from attacklog_correlator.ingestion.discovery import discover_attack_files
from attacklog_correlator.ingestion.timestamps import parse_attack_datetime
from attacklog_correlator.models import Attack
from attacklog_correlator.tokens import extract_ips, extract_tokens


def parse_utc_shift_hours(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return default
    try:
        return float(text)
    except ValueError:
        return default

def apply_timezone_shift(parsed: dt.datetime, shift_hours: float) -> dt.datetime:
    return parsed - dt.timedelta(hours=shift_hours)

def extract_attack_targets(cmd: str, metadata: dict[str, Any], resolver: Optional[HostResolver] = None) -> tuple[list[str], list[str], list[str], list[str]]:
    target_ips: list[str] = []
    target_networks: list[str] = []
    target_tokens: list[str] = []
    target_hosts: list[str] = []

    for token in extract_ips(cmd):
        if "/" in token:
            if token not in target_networks:
                target_networks.append(token)
        else:
            if token not in target_ips:
                target_ips.append(token)
    text_blobs = [cmd]
    for value in metadata.values():
        if isinstance(value, str):
            text_blobs.append(value)
    for blob in text_blobs:
        for tok in extract_tokens(blob):
            if tok not in target_tokens:
                target_tokens.append(tok)
    if resolver:
        for ip in target_ips + target_networks:
            host = resolver.host_for_ip(ip)
            if host and host not in target_hosts:
                target_hosts.append(host)
        for tok in target_tokens:
            host = resolver.alias_to_host.get(tok)
            if host and host not in target_hosts:
                target_hosts.append(host)
    return target_ips, target_networks, target_tokens, target_hosts

def load_attack_file(path: Path, resolver: HostResolver, attack_root: Optional[Path] = None, config: Optional[Any] = None) -> list[Attack]:
    attacks: list[Attack] = []
    attacker_host = guess_attacker_host_from_path(path, attack_root or path.parent)

    raw_cfg: dict[str, Any] = {}
    if isinstance(config, dict):
        raw_cfg = config
    elif hasattr(config, "raw_config") and isinstance(getattr(config, "raw_config"), dict):
        raw_cfg = getattr(config, "raw_config")

    attacker_cfg = (raw_cfg.get("attacker_hosts", {}) or {}).get(attacker_host, {})
    attacker_timezone = str(
        attacker_cfg.get(
            "timezone",
            raw_cfg.get("default_attacker_timezone", "UTC"),
        )
    )
    attacker_shift = parse_utc_shift_hours(
        attacker_cfg.get("utc_offset_hours", raw_cfg.get("default_utc_offset_hours", 0))
    )

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, start=1):
            text_line = line.strip()
            if not text_line:
                continue
            try:
                obj = json.loads(text_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            ts = obj.get("start-datetime")
            if not isinstance(ts, str):
                continue
            parsed = parse_attack_datetime(ts, attacker_timezone)
            if not parsed:
                continue
            parsed = apply_timezone_shift(parsed, attacker_shift)
            attack_type = str(obj.get("type", "unknown"))
            cmd = str(obj.get("cmd", ""))
            metadata = {}
            params = obj.get("parameters")
            if isinstance(params, dict):
                meta = params.get("metadata")
                if isinstance(meta, dict):
                    metadata = meta
            # Extract attack-side target hints immediately so later scoring can
            # compare them against parsed host-log hints.
            target_ips, target_networks, target_tokens, target_hosts = extract_attack_targets(cmd, metadata, resolver)
            attack_id = f"{path}:{line_number}"
            attacks.append(
                Attack(
                    attack_id=attack_id,
                    timestamp=parsed,
                    attack_type=attack_type,
                    cmd=cmd,
                    source_file=str(path),
                    line_number=line_number,
                    metadata=metadata,
                    raw_line=line.rstrip("\n"),
                    target_hosts=target_hosts,
                    target_ips=target_ips,
                    target_networks=target_networks,
                    target_tokens=target_tokens,
                    attacker_host=attacker_host,
                )
            )
    return attacks

def load_all_attacks(attack_root: Path, resolver: HostResolver, config: Optional[dict[str, Any]] = None) -> list[Attack]:
    attacks: list[Attack] = []
    for path in discover_attack_files(attack_root):
        try:
            attacks.extend(load_attack_file(path, resolver, attack_root=attack_root, config=config))
        except Exception as exc:
            print(f"[warn] failed to read attack log: {path}: {exc}", file=sys.stderr)
    return sorted(attacks, key=lambda x: x.timestamp)
