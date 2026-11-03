"""Shared name, token and IP extraction rules (preserved from the correlator)."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

HOST_TOKEN_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_.-]{2,}\b")

STOP_TOKENS = {
    "sudo", "nmap", "bash", "sh", "python", "python3", "nc", "curl", "wget", "ssh", "scp", "ftp",
    "http", "https", "tcp", "udp", "icmp", "reconnaissance", "discovery", "network", "scan", "ports",
}

def sanitize_host_name(name: str) -> str:
    name = re.sub(r"\.(log|txt|json|journal|gz|xz|bz2)$", "", name, flags=re.I)
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-_.")
    return name.lower() or "unknown-host"

def safe_ip_network(token: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None

def safe_ip_address(token: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        return None

def extract_ips(text: str) -> list[str]:
    seen: list[str] = []
    for token in IP_RE.findall(text):
        if token not in seen:
            seen.append(token)
    return seen

def extract_tokens(text: str) -> list[str]:
    seen: list[str] = []
    for token in HOST_TOKEN_RE.findall(text):
        st = sanitize_host_name(token)
        if st in STOP_TOKENS or st.isdigit() or len(st) < 3:
            continue
        if st not in seen:
            seen.append(st)
    return seen
