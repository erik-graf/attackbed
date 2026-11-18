"""Host configuration and resolution; no scoring or UI dependencies."""

from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from typing import Optional

from attacklog_correlator.ingestion.discovery import discover_log_files
from attacklog_correlator.ingestion.logtypes import LogTypeRule
from attacklog_correlator.tokens import safe_ip_address, safe_ip_network, sanitize_host_name


MAX_TIME_DELTA_SECONDS = 5.0

CURRENT_YEAR_FALLBACK = dt.datetime.now().year

COMMON_DIR_NAMES = {"logs", "log", "var", "tmp", "journal", "journals", "audit", "audits", "syslog", "host", "hosts", "varlog"}

COMMON_LOG_STEMS = {
    "auth", "authlog", "boot", "btmp", "cloud-init", "container", "daemon", "debug", "dmesg",
    "dpkg", "eve", "faillog", "kern", "lastlog", "messages", "secure", "syslog", "wtmp",
}

@dataclasses.dataclass
class HostProfile:
    name: str
    timezone: str
    clock_skew_seconds: float = 0.0
    aliases: list[str] = dataclasses.field(default_factory=list)
    ip_addresses: list[str] = dataclasses.field(default_factory=list)
    path_hints: list[str] = dataclasses.field(default_factory=list)
    notes: str = ""

@dataclasses.dataclass
class ConfigBundle:
    default_timezone: str
    default_clock_skew_seconds: float
    hosts: dict[str, HostProfile]
    raw_config: dict[str, Any] = dataclasses.field(default_factory=dict)

def normalize_path_host_part(name: str) -> str:
    """
    Normalize directory/file name fragments when inferring hostnames from paths.
    """
    try:
        return sanitize_host_name(name)
    except Exception:
        name = str(name)
        name = re.sub(r"\.(log|txt|json|jsonl|journal|gz|xz|bz2)$", "", name, flags=re.I)
        name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-_.")
        return name or "unknown-host"

def guess_attacker_host_from_path(path: Path, root: Path) -> str:
    # Prefer a path relative to the user-supplied root, because directory
    # components inside that root are meaningful for host inference.  If that
    # fails (for example because paths are on different roots), fall back to the
    # raw path parts rather than aborting.
    try:
        rel_parts = path.resolve().relative_to(root.resolve()).parts
    except Exception:
        rel_parts = path.parts
    # Ignore the filename itself (rel_parts[:-1]) and look for the first
    # non-generic directory.  Example:
    #   attacklogs/attacker-a/step01.json -> attacker-a
    for part in rel_parts[:-1]:
        lowered = part.lower()
        if lowered not in {"attacklogs", "attacks", "attacklog", "logs", "log"}:
            return normalize_path_host_part(part)
    if len(rel_parts) >= 2:
        return normalize_path_host_part(rel_parts[-2])
    return "unknown-attacker"

def looks_like_random_identifier(name: str) -> bool:
    """Return True for path fragments that are probably IDs, not hostnames."""
    text = sanitize_host_name(name)
    compact = text.replace("-", "").replace("_", "").replace(".", "")
    if not compact:
        return True
    # UUID-ish or long hex-ish directory/file names are common in extracted log
    # bundles and should not become generated host names.
    if re.fullmatch(r"[0-9a-f]{12,}", compact, flags=re.I):
        return True
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text, flags=re.I):
        return True
    # Long mostly-numeric strings are usually timestamps, container IDs, or
    # artifact IDs rather than machine names.
    digit_count = sum(ch.isdigit() for ch in compact)
    if len(compact) >= 10 and digit_count / max(1, len(compact)) > 0.60:
        return True
    # Very long opaque tokens with no separators tend to be hashes/container IDs.
    if len(compact) >= 24 and re.fullmatch(r"[a-z0-9]+", compact, flags=re.I):
        return True
    return False

def is_plausible_host_name(name: str) -> bool:
    """Filter path fragments before using them as inferred host names."""
    text = sanitize_host_name(name)
    if not text or text == "unknown-host":
        return False
    if text in COMMON_DIR_NAMES or text in COMMON_LOG_STEMS:
        return False
    if text.isdigit() or len(text) < 3:
        return False
    if safe_ip_address(text) or safe_ip_network(text):
        return False
    if looks_like_random_identifier(text):
        return False
    return True

def host_candidates_from_path(path: Path, root: Path) -> list[str]:
    """Return only the top-level host folder under the log root, if plausible.

    Earlier versions collected many directory names and file stems as path hints.
    That made unrelated hosts share hints such as ``apt``, ``history``,
    ``system``, or ``user-1000``.  For generated config and path-based host
    inference, the only reliable automatic hint is the first path component
    below ``log_root``: for example ``hostlogs/fileshare/var/log/syslog`` should
    produce only ``fileshare``.
    """
    try:
        rel_parts = path.resolve().relative_to(root.resolve()).parts
    except Exception:
        rel_parts = path.parts

    if not rel_parts:
        return []

    top_level = sanitize_host_name(rel_parts[0])
    if is_plausible_host_name(top_level):
        return [top_level]
    return []

class HostResolver:
    # Build lookup indexes once so repeated correlation checks are fast.
    # These maps/lists are used for alias normalization, direct IP lookup,
    # CIDR-network lookup, and path-hint matching.
    def __init__(self, config: ConfigBundle):
        self.config = config
        self.alias_to_host: dict[str, str] = {}
        self.ip_to_host: dict[str, str] = {}
        self.networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        self.path_hints: list[tuple[str, str]] = []
        # Precompute alias/IP/network/path indexes from the config.  This is
        # done once at startup so later line-by-line parsing does not repeatedly
        # traverse the full host config.
        for host, profile in config.hosts.items():
            for alias in {host, *profile.aliases}:
                self.alias_to_host[sanitize_host_name(alias)] = host
            for ip_text in profile.ip_addresses:
                if "/" in ip_text:
                    net = safe_ip_network(ip_text)
                    if net:
                        # Networks are stored as (network, host) pairs because
                        # an event IP may later match by CIDR membership.
                        self.networks.append((net, host))
                else:
                    addr = safe_ip_address(ip_text)
                    if addr:
                        self.ip_to_host[str(addr)] = host
            for hint in profile.path_hints:
                self.path_hints.append((sanitize_host_name(hint), host))

    # Return a host-specific timezone, or the global default if the host is unknown.
    def resolve_timezone(self, host: str) -> str:
        return self.config.hosts.get(host, HostProfile(host, self.config.default_timezone)).timezone

    # Return a host-specific clock skew in seconds, or zero/default if unknown.
    def resolve_clock_skew(self, host: str) -> float:
        profile = self.config.hosts.get(host)
        return profile.clock_skew_seconds if profile else self.config.default_clock_skew_seconds

    # Convert any observed host token/alias into the canonical configured host name.
    def canonicalize_host(self, host: str) -> str:
        return self.alias_to_host.get(sanitize_host_name(host), sanitize_host_name(host))

    # Map an IP address or CIDR network to a configured host.
    # Direct IP matches are tried first; then CIDR membership is checked.  If the
    # input itself is a network, overlapping/subnet networks are considered a match.
    def host_for_ip(self, ip_text: str) -> Optional[str]:
        addr = safe_ip_address(ip_text)
        if not addr:
            net = safe_ip_network(ip_text)
            if net:
                for known_net, host in self.networks:
                    if net.subnet_of(known_net) or known_net.subnet_of(net) or net == known_net:
                        return host
            return None
        direct = self.ip_to_host.get(str(addr))
        if direct:
            return direct
        for net, host in self.networks:
            if addr in net:
                return host
        return None

    # Guess which host a log file belongs to based on its directory/file path.
    # The function prefers configured aliases, then configured path hints, then a
    # best-effort non-generic path component.  This is why directory structure
    # matters for the correlator.
    def host_from_path(self, path: Path, root: Path) -> Optional[str]:
        candidates = host_candidates_from_path(path, root)
        for cand in candidates:
            if cand in self.alias_to_host:
                return self.alias_to_host[cand]
        for cand in reversed(candidates):
            for hint, host in self.path_hints:
                if hint and hint in cand:
                    return host
        if candidates:
            return candidates[0]
        return None

    # Combine all host-resolution hints available for one log line.
    # Tokens can match aliases, IPs can map to hosts, and the file path can provide
    # a fallback host.  The returned list is later used in target-host scoring.
    def candidate_hosts_for_tokens(self, tokens: list[str], path: Optional[Path] = None, root: Optional[Path] = None) -> list[str]:
        found: list[str] = []
        for tok in tokens:
            st = sanitize_host_name(tok)
            host = self.alias_to_host.get(st)
            if host and host not in found:
                found.append(host)
            by_ip = self.host_for_ip(tok)
            if by_ip and by_ip not in found:
                found.append(by_ip)
        if path and root:
            path_host = self.host_from_path(path, root)
            if path_host and path_host not in found:
                found.append(path_host)
        return found

def load_config(config_path: Optional[Path], discovered_hosts: dict[str, HostProfile], default_timezone: str) -> ConfigBundle:
    # Copy discovered profiles so loading config does not mutate the discovery
    # result object passed by the caller.
    base_hosts = {name: dataclasses.replace(profile) for name, profile in discovered_hosts.items()}
    config = ConfigBundle(default_timezone=default_timezone, default_clock_skew_seconds=0.0, hosts=base_hosts, raw_config={})
    if not config_path or not config_path.exists():
        return config
    data = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return config
    config.raw_config = dict(data)
    config.default_timezone = str(data.get("default_timezone", config.default_timezone))
    config.default_clock_skew_seconds = float(data.get("default_clock_skew_seconds", 0.0) or 0.0)
    for profile in config.hosts.values():
        profile.clock_skew_seconds = config.default_clock_skew_seconds
    hosts = data.get("hosts", {})
    if isinstance(hosts, dict):
        for host_name, host_cfg in hosts.items():
            if not isinstance(host_cfg, dict):
                continue
            key = sanitize_host_name(host_name)
            existing = config.hosts.get(key, HostProfile(key, config.default_timezone))
            existing.timezone = str(host_cfg.get("timezone", existing.timezone or config.default_timezone))
            existing.clock_skew_seconds = float(host_cfg.get("clock_skew_seconds", existing.clock_skew_seconds or 0.0) or 0.0)
            # Merge configured values into discovered values.  set() removes
            # duplicates; sorted() gives stable generated config output.
            existing.aliases = sorted(set(existing.aliases + [sanitize_host_name(x) for x in host_cfg.get("aliases", []) if str(x).strip()]))
            existing.ip_addresses = sorted(set(existing.ip_addresses + [str(x).strip() for x in host_cfg.get("ip_addresses", []) if str(x).strip()]))
            existing.path_hints = sorted(set(existing.path_hints + [sanitize_host_name(x) for x in host_cfg.get("path_hints", []) if str(x).strip()]))
            existing.notes = str(host_cfg.get("notes", existing.notes))
            config.hosts[key] = existing
    for host, profile in config.hosts.items():
        if not profile.timezone:
            profile.timezone = config.default_timezone
    return config

def write_generated_config(path: Path, config: ConfigBundle) -> None:
    payload = {
        "default_timezone": config.default_timezone,
        "default_clock_skew_seconds": config.default_clock_skew_seconds,
        "default_attacker_timezone": (config.raw_config or {}).get("default_attacker_timezone", "UTC"),
        "default_utc_offset_hours": (config.raw_config or {}).get("default_utc_offset_hours", 0),
        "attacker_hosts": (config.raw_config or {}).get("attacker_hosts", {}),
        "hosts": {
            host: {
                "timezone": profile.timezone,
                "clock_skew_seconds": profile.clock_skew_seconds,
                "aliases": profile.aliases,
                "ip_addresses": profile.ip_addresses,
                "path_hints": profile.path_hints,
                "notes": profile.notes,
            }
            for host, profile in sorted(config.hosts.items())
        },
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

def discover_hosts_from_logs(log_root: Path, attack_root: Optional[Path], default_timezone: str,
                             log_types: Optional[list[LogTypeRule]] = None) -> dict[str, HostProfile]:
    hosts: dict[str, HostProfile] = {}
    for path in discover_log_files(log_root, attack_root, log_types):
        candidates = host_candidates_from_path(path, log_root)
        if not candidates:
            continue
        host = candidates[0]
        profile = hosts.setdefault(host, HostProfile(name=host, timezone=default_timezone))
        for hint in candidates:
            if hint and hint not in profile.path_hints:
                profile.path_hints.append(hint)
    return hosts
