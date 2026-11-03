"""Correlation scoring and ordering; runtime time limits are explicit inputs."""

from __future__ import annotations

import datetime as dt
import re
import shlex
from collections import defaultdict
from pathlib import Path

from attacklog_correlator.config import MAX_TIME_DELTA_SECONDS
from attacklog_correlator.models import Attack, Correlation, LogEvent
from attacklog_correlator.tokens import (
    STOP_TOKENS,
    extract_tokens,
    safe_ip_address,
    safe_ip_network,
    sanitize_host_name,
)


BINARY_MATCH_BASE = 40.0

BINARY_MATCH_PER_HIT = 25.0

BINARY_MATCH_MAX = 120.0

LEXICAL_EXACT_PER_HIT = 10.0

LEXICAL_EXACT_MAX = 80.0

LEXICAL_OVERLAP_PER_TERM = 6.0

LEXICAL_OVERLAP_MAX = 40.0

METADATA_LEXICAL_PER_HIT = 3.0

METADATA_LEXICAL_MAX = 18.0

LEXICAL_MULTI_MIN_MATCHES = 3

LEXICAL_MULTI_PER_MATCH = 5.0

LEXICAL_MULTI_MAX = 25.0

TARGET_HOST_EXACT_SCORE = 45.0

TARGET_HOST_CANDIDATE_SCORE = 25.0

IP_LITERAL_BASE = 20.0

IP_LITERAL_PER_HIT = 10.0

IP_LITERAL_MAX = 50.0

NETWORK_MATCH_BASE = 15.0

NETWORK_MATCH_PER_HIT = 10.0

NETWORK_MATCH_MAX = 35.0

SOURCE_TYPE_HINT_SCORE = 6.0

TIME_PROXIMITY_MAX_SCORE = 40.0

POST_ATTACK_BONUS_WINDOW_SECONDS = 10.0

POST_ATTACK_BONUS_SCORE = 12.0

PRE_ATTACK_CONTEXT_WINDOW_SECONDS = 5.0

PRE_ATTACK_CONTEXT_BONUS_SCORE = 4.0

RELEVANCE_SCORE_THRESHOLD = 60.0

RELEVANCE_TARGET_HOST_THRESHOLD = 45.0

RELEVANCE_IP_NETWORK_THRESHOLD = 40.0

CONTENT_SCORE_WEIGHT = 2.0

LEXICAL_STOP_TOKENS = STOP_TOKENS | {
    "bin", "usr", "var", "tmp", "etc", "log", "logs", "root", "system", "service", "session",
    "shell", "command", "interactive", "background", "error", "metadata", "description",
    "the", "and", "for", "with", "from", "into", "that", "this", "false", "true", "null",
}

LEXICAL_MATCH_SCORE_KEYS = (
    "binary_name_match",
    "lexical_exact_match",
    "lexical_token_overlap",
    "metadata_lexical_match",
    "lexical_multi_signal_bonus",
)

def extract_command_binaries(cmd: str) -> list[str]:
    try:
        parts = shlex.split(cmd)
    except Exception:
        parts = cmd.split()

    binaries: list[str] = []
    command_starters = {"sudo", "env", "nohup", "time", "command", "builtin", "exec", "doas"}
    shell_separators = {"|", "||", "&&", ";", "&"}
    expect_command = True

    # Walk shell tokens and collect probable command positions.  This is a
    # heuristic, not a full shell parser, but handles common wrappers and
    # separators well enough for scoring.
    for raw in parts:
        token = raw.strip()
        if not token:
            continue
        if token in shell_separators:
            # After a pipe/&&/; etc., the next non-option token is probably a
            # new command binary.
            expect_command = True
            continue
        if token in command_starters:
            expect_command = True
            continue
        if token.startswith("-"):
            # Command-line options are not binaries and should not become
            # lexical signals.
            continue
        if "=" in token and not token.startswith("/"):
            continue

        candidate = sanitize_host_name(Path(token).name if "/" in token else token)
        if not candidate or candidate.isdigit() or len(candidate) < 2:
            continue
        if safe_ip_address(candidate) or safe_ip_network(candidate):
            continue

        if expect_command:
            # The first meaningful token after a separator/wrapper is treated as
            # the executable name.
            if candidate not in binaries:
                binaries.append(candidate)
            expect_command = False
            continue

        if candidate.endswith((".py", ".pl", ".sh")):
            stem = sanitize_host_name(Path(candidate).stem)
            if stem and stem not in binaries:
                binaries.append(stem)
        elif "/" in token:
            if candidate not in binaries:
                binaries.append(candidate)

    return binaries

def extract_attack_command_lexical_terms(attack: Attack) -> list[str]:
    """Return lexical tokens that come from the attack command only.

    These are the primary lexical signals.  A correlation may only survive when
    at least one of these command-side tokens appears visibly in the host log.
    """
    terms: list[str] = []

    for binary in extract_command_binaries(attack.cmd):
        if binary not in terms and binary not in LEXICAL_STOP_TOKENS:
            terms.append(binary)

    for tok in extract_tokens(attack.cmd):
        if tok in LEXICAL_STOP_TOKENS or tok.isdigit() or len(tok) < 3:
            continue
        if tok not in terms:
            terms.append(tok)

    return terms[:40]

def extract_attack_metadata_lexical_terms(attack: Attack) -> list[str]:
    """Return weaker lexical tokens that come from attack metadata values.

    Metadata can contain useful context such as target role, scenario label, or
    technique notes, but it is also much noisier than the command.  Therefore
    metadata terms are only scored after a command term has already matched.
    """
    terms: list[str] = []

    for value in attack.metadata.values():
        if not isinstance(value, str):
            continue
        for tok in extract_tokens(value):
            if tok in LEXICAL_STOP_TOKENS or tok.isdigit() or len(tok) < 3:
                continue
            if tok not in terms:
                terms.append(tok)

    return terms[:40]

def extract_attack_lexical_terms(attack: Attack) -> list[str]:
    """Return all attack lexical terms, command first, then metadata.

    Kept as a compatibility helper for UI highlighting and older call sites.
    Scoring uses the split command/metadata helpers above so metadata cannot
    create a correlation by itself.
    """
    terms: list[str] = []
    for tok in extract_attack_command_lexical_terms(attack) + extract_attack_metadata_lexical_terms(attack):
        if tok not in terms:
            terms.append(tok)
    return terms[:40]

def event_lexical_terms(event: LogEvent) -> set[str]:
    return set(extract_tokens(event.raw_line + " " + event.message))

def lexical_token_in_event_text(token: str, event_text: str, event_terms: set[str]) -> bool:
    """Return True only when an attack token visibly appears in host-log text.

    The old scoring code used plain substring checks, so short tokens could match
    inside unrelated longer words.  It also allowed token-overlap evidence from
    derived candidate host/IP metadata.  This helper keeps lexical matching tied
    to what a reviewer can actually see in the matched log line.
    """
    tok = sanitize_host_name(token)
    if not tok or tok.isdigit():
        return False
    if tok in event_terms:
        return True
    # Fall back to a component-boundary check for cases where extract_tokens()
    # and the raw text disagree around punctuation.  Host/path characters are
    # treated as part of a token, so "sh" will not match inside "shell" and
    # "apt" will not match inside "/var/log/aptitude".
    pattern = r"(?<![A-Za-z0-9_.-])" + re.escape(tok) + r"(?![A-Za-z0-9_.-])"
    return re.search(pattern, event_text, flags=re.I) is not None

def _append_unique_token(out: list[str], token: str) -> None:
    tok = sanitize_host_name(token)
    if tok and tok not in out:
        out.append(tok)

def lexical_overlap_score(attack: Attack, event: LogEvent) -> tuple[float, dict[str, float], list[str], list[str], list[str]]:
    breakdown: dict[str, float] = {}
    score = 0.0
    matched_terms: list[str] = []
    matched_command_terms: list[str] = []
    matched_metadata_terms: list[str] = []

    event_text = (event.message + " " + event.raw_line).lower()
    event_terms = event_lexical_terms(event)

    command_terms = extract_attack_command_lexical_terms(attack)
    metadata_terms = extract_attack_metadata_lexical_terms(attack)

    # Strongest lexical signal: the executable from the attack command appears
    # as a visible token in the host log text.
    binary_hits: list[str] = []
    for binary in extract_command_binaries(attack.cmd):
        if binary and binary not in LEXICAL_STOP_TOKENS and lexical_token_in_event_text(binary, event_text, event_terms):
            binary_hits.append(binary)
            _append_unique_token(matched_terms, binary)
            _append_unique_token(matched_command_terms, binary)
    if binary_hits:
        val = min(BINARY_MATCH_MAX, BINARY_MATCH_BASE + BINARY_MATCH_PER_HIT * len(set(binary_hits)))
        breakdown["binary_name_match"] = val
        score += val

    # Command matches are the required gate for lexical evidence.  These are
    # derived only from attack.cmd, never from JSON keys or metadata values.
    command_exact_hits: list[str] = []
    for tok in command_terms:
        if tok in LEXICAL_STOP_TOKENS or tok.isdigit() or len(tok) < 3:
            continue
        if lexical_token_in_event_text(tok, event_text, event_terms):
            command_exact_hits.append(tok)
            _append_unique_token(matched_terms, tok)
            _append_unique_token(matched_command_terms, tok)
    if command_exact_hits:
        val = min(LEXICAL_EXACT_MAX, LEXICAL_EXACT_PER_HIT * len(set(command_exact_hits)))
        breakdown["command_lexical_match"] = val
        # Keep the old key as a compatibility alias for existing UI/export
        # helpers that look for generic lexical evidence.
        breakdown["lexical_exact_match"] = val
        score += val

    command_overlap_terms = sorted((set(command_terms) - set(command_exact_hits)) & event_terms)
    command_overlap_terms = [tok for tok in command_overlap_terms if tok not in LEXICAL_STOP_TOKENS and len(tok) >= 3]
    for tok in command_overlap_terms:
        _append_unique_token(matched_terms, tok)
        _append_unique_token(matched_command_terms, tok)
    if command_overlap_terms:
        val = min(LEXICAL_OVERLAP_MAX, LEXICAL_OVERLAP_PER_TERM * len(command_overlap_terms))
        breakdown["command_token_overlap"] = val
        breakdown["lexical_token_overlap"] = val
        score += val

    command_matched = bool(binary_hits or command_exact_hits or command_overlap_terms)

    # Metadata is weaker supporting evidence only.  It is deliberately ignored
    # unless a command token has already matched, so a command like "sleep" can
    # no longer correlate solely because metadata contained "dhcp".
    metadata_hits: list[str] = []
    if command_matched:
        command_term_set = set(command_terms)
        for tok in metadata_terms:
            if tok in command_term_set or tok in LEXICAL_STOP_TOKENS or tok.isdigit() or len(tok) < 3:
                continue
            if lexical_token_in_event_text(tok, event_text, event_terms):
                metadata_hits.append(tok)
                _append_unique_token(matched_terms, tok)
                _append_unique_token(matched_metadata_terms, tok)
        if metadata_hits:
            val = min(METADATA_LEXICAL_MAX, METADATA_LEXICAL_PER_HIT * len(set(metadata_hits)))
            breakdown["metadata_lexical_match"] = val
            score += val

    matched_total = len(set(binary_hits)) + len(set(command_exact_hits)) + len(set(command_overlap_terms)) + len(set(metadata_hits))
    if command_matched and matched_total >= LEXICAL_MULTI_MIN_MATCHES:
        bonus = min(LEXICAL_MULTI_MAX, LEXICAL_MULTI_PER_MATCH * matched_total)
        breakdown["lexical_multi_signal_bonus"] = bonus
        score += bonus

    return score, breakdown, matched_terms, matched_command_terms, matched_metadata_terms

def content_overlap_score(attack: Attack, event: LogEvent) -> tuple[float, dict[str, float], list[str], list[str], list[str], list[str]]:
    breakdown: dict[str, float] = {}
    matched_hosts: list[str] = []
    score = 0.0

    lexical_score, lexical_breakdown, matched_lexical_terms, matched_command_terms, matched_metadata_terms = lexical_overlap_score(attack, event)
    score += lexical_score
    breakdown.update(lexical_breakdown)

    if attack.target_hosts:
        # Exact target-host evidence is strong: the attack was aimed at a known
        # host and the event belongs to that same host.
        if event.host in attack.target_hosts:
            breakdown["target_host_exact"] = TARGET_HOST_EXACT_SCORE
            score += TARGET_HOST_EXACT_SCORE
            matched_hosts.append(event.host)
        overlap = sorted(set(attack.target_hosts) & set(event.candidate_hosts))
        if overlap:
            breakdown["target_host_candidate"] = TARGET_HOST_CANDIDATE_SCORE
            score += TARGET_HOST_CANDIDATE_SCORE
            matched_hosts.extend(h for h in overlap if h not in matched_hosts)

    ip_hits = 0
    for ip_text in attack.target_ips:
        if ip_text in event.candidate_ips:
            ip_hits += 1
    if ip_hits:
        val = min(IP_LITERAL_MAX, IP_LITERAL_BASE + IP_LITERAL_PER_HIT * ip_hits)
        breakdown["ip_literal_match"] = val
        score += val

    network_hits = 0
    # Network target matching lets an attack against 10.0.0.0/24 match an event
    # that contains a concrete IP such as 10.0.0.17.
    for net_text in attack.target_networks:
        net = safe_ip_network(net_text)
        if not net:
            continue
        for ip_text in event.candidate_ips:
            addr = safe_ip_address(ip_text.split("/")[0])
            if addr and addr in net:
                network_hits += 1
                break
    if network_hits:
        val = min(NETWORK_MATCH_MAX, NETWORK_MATCH_BASE + NETWORK_MATCH_PER_HIT * network_hits)
        breakdown["network_match"] = val
        score += val

    if attack.attack_type and attack.attack_type.lower() in event.source_type.lower():
        breakdown["source_type_hint"] = SOURCE_TYPE_HINT_SCORE
        score += SOURCE_TYPE_HINT_SCORE

    return score, breakdown, matched_hosts, matched_lexical_terms, matched_command_terms, matched_metadata_terms

def time_score(delta_seconds: float, window_before: float, window_after: float) -> tuple[float, dict[str, float]]:
    max_window = max(window_before, window_after, 1.0)
    # Linear decay: zero delta gets full time score, while events at the edge
    # of the window get little or no time score.
    decay = max(0.0, 1.0 - min(abs(delta_seconds), max_window) / max_window)
    base = TIME_PROXIMITY_MAX_SCORE * decay
    breakdown = {"time_proximity": base}
    if 0 <= delta_seconds <= min(POST_ATTACK_BONUS_WINDOW_SECONDS, window_after):
        breakdown["post_attack_bonus"] = POST_ATTACK_BONUS_SCORE
        base += POST_ATTACK_BONUS_SCORE
    elif -PRE_ATTACK_CONTEXT_WINDOW_SECONDS <= delta_seconds < 0:
        breakdown["pre_attack_context_bonus"] = PRE_ATTACK_CONTEXT_BONUS_SCORE
        base += PRE_ATTACK_CONTEXT_BONUS_SCORE
    return base, breakdown

def lexical_score_from_breakdown(breakdown: dict[str, float]) -> float:
    """Return only the lexical portion of a score breakdown.

    The total correlation score also contains time, target-host, IP/network, and
    source-type hints.  This helper isolates the part that proves the attack-log
    text actually appears in the host-log text.
    """
    total = 0.0
    for key in LEXICAL_MATCH_SCORE_KEYS:
        try:
            total += float((breakdown or {}).get(key, 0.0))
        except Exception:
            pass
    return total

def has_lexical_match(correlation: Correlation) -> bool:
    """Require at least one lexical match before a correlation can survive.

    Without this gate, a row could be kept because of time proximity, host/IP
    hints, or source-type hints even though no attack-log token appeared in the
    host-log line.  Those non-lexical signals are useful as supporting evidence,
    but they are too weak to count as a match on their own.
    """
    command_terms = getattr(correlation, "matched_command_terms", None)
    if command_terms is not None:
        return bool(command_terms)
    return bool(getattr(correlation, "matched_lexical_terms", []))

def relevance_threshold(correlation: Correlation, *, max_time_delta: float = MAX_TIME_DELTA_SECONDS) -> bool:
    breakdown_keys = set(correlation.score_breakdown)

    # First require actual lexical evidence.  Time-only, host-only, IP-only, or
    # source-type-only matches are discarded even if their total score would have
    # crossed one of the thresholds below.
    if not has_lexical_match(correlation):
        return False

    # Outside the immediate execution window, one command word alone is too
    # weak: require a second command term or matching target/IP evidence.
    has_target_evidence = bool(correlation.target_host_matches) or bool(
        {"ip_literal_match", "network_match"} & breakdown_keys
    )
    if (correlation.abs_delta_seconds > 1.0
            and len(set(correlation.matched_command_terms)) < 2
            and not has_target_evidence):
        return False

    # A binary match passes the threshold, but only after the lexical gate above.
    if "binary_name_match" in breakdown_keys:
        return True
    if "lexical_exact_match" in breakdown_keys and correlation.abs_delta_seconds <= max_time_delta:
        return True
    if correlation.score >= RELEVANCE_SCORE_THRESHOLD:
        return True
    if correlation.score >= RELEVANCE_TARGET_HOST_THRESHOLD and correlation.target_host_matches:
        return True
    if correlation.score >= RELEVANCE_IP_NETWORK_THRESHOLD and any(k in breakdown_keys for k in ("ip_literal_match", "network_match")):
        return True
    return False

def correlate(attacks: list[Attack], events: list[LogEvent], window_before: float, window_after: float, max_per_attack: int, *, max_time_delta: float = MAX_TIME_DELTA_SECONDS) -> list[Correlation]:
    correlations: list[Correlation] = []

    # Timestamped events keep the original efficient sliding-window scan.
    # Untimestamped events are kept separately because the window comparison
    # cannot apply to them; they are scored against each attack with time score
    # forced to zero.
    timed_events = [e for e in events if not (e.extra or {}).get("timestamp_missing")]
    untimed_events = [e for e in events if (e.extra or {}).get("timestamp_missing")]

    # Sort events once so each attack can scan a contiguous time window.
    # start_idx advances monotonically as attacks move forward in time, avoiding
    # a full scan from the beginning for every timestamped attack/event pair.
    events_sorted = sorted(timed_events, key=lambda e: e.timestamp)
    start_idx = 0

    def build_correlation(attack: Attack, event: LogEvent, force_zero_time_score: bool = False) -> Correlation:
        # The synthetic delta for untimestamped rows is deliberately larger
        # than the configured windows/cap.  That prevents relevance_threshold()
        # from treating a lexical match as time-close, while still keeping the
        # numeric output finite and JSON/CSV-friendly.
        if force_zero_time_score:
            delta = max(window_before, window_after, max_time_delta) + 1.0
            abs_delta = delta
            t_score = 0.0
            t_breakdown = {"time_proximity": 0.0}
        else:
            delta = (event.timestamp - attack.timestamp).total_seconds()
            abs_delta = abs(delta)
            t_score, t_breakdown = time_score(delta, window_before, window_after)

        c_score, c_breakdown, matched_hosts, matched_lexical_terms, matched_command_terms, matched_metadata_terms = content_overlap_score(attack, event)
        raw_lexical_score = lexical_score_from_breakdown(c_breakdown)

        # Content evidence is doubled relative to the raw content score.
        # Time still contributes for timestamped events, but lexical/target
        # evidence dominates the final total.  raw_lexical_score is recorded
        # separately so correlations with no attack-log text match can be
        # discarded by relevance_threshold().
        weighted_time_score = t_score
        weighted_content_score = c_score * CONTENT_SCORE_WEIGHT
        weighted_lexical_score = raw_lexical_score * CONTENT_SCORE_WEIGHT
        total = weighted_time_score + weighted_content_score
        breakdown = {
            **t_breakdown,
            **c_breakdown,
            "raw_lexical_score": raw_lexical_score,
            "weighted_time_score": weighted_time_score,
            "weighted_content_score": weighted_content_score,
            "weighted_lexical_score": weighted_lexical_score,
        }

        return Correlation(
            correlation_id=f"{attack.attack_id}|{event.event_id}",
            attack_id=attack.attack_id,
            event_id=event.event_id,
            attacker_host=attack.attacker_host,
            attack_time=attack.timestamp,
            event_time=event.timestamp,
            delta_seconds=delta,
            abs_delta_seconds=abs_delta,
            attack_file=attack.source_file,
            attack_line=attack.line_number,
            attack_raw_line=attack.raw_line,
            event_file=str(event.file_path),
            event_line=event.line_number,
            host=event.host,
            attack_type=attack.attack_type,
            attack_cmd=attack.cmd,
            attack_targets=attack.target_hosts + attack.target_ips + attack.target_networks + attack.target_tokens,
            target_host_matches=matched_hosts,
            event_message=event.message,
            event_source_type=event.source_type,
            score=total,
            score_breakdown=breakdown,
            matched_lexical_terms=matched_lexical_terms,
            matched_command_terms=matched_command_terms,
            matched_metadata_terms=matched_metadata_terms,
        )

    for attack in sorted(attacks, key=lambda a: a.timestamp):
        # Build the broad user-configured time window around the attack.  A
        # later hard cap (MAX_TIME_DELTA_SECONDS) further restricts timestamped
        # candidates.
        lower = attack.timestamp - dt.timedelta(seconds=window_before)
        upper = attack.timestamp + dt.timedelta(seconds=window_after)

        # Discard timestamped events that are too old for this and all later
        # attacks.  Untimestamped events are handled after this window scan.
        while start_idx < len(events_sorted) and events_sorted[start_idx].timestamp < lower:
            start_idx += 1

        matches: list[Correlation] = []
        idx = start_idx

        while idx < len(events_sorted) and events_sorted[idx].timestamp <= upper:
            event = events_sorted[idx]
            delta = (event.timestamp - attack.timestamp).total_seconds()
            abs_delta = abs(delta)

            if abs_delta > max_time_delta:
                # Even inside the broad window, this strict cap rejects
                # timestamped events before spending time on content scoring.
                idx += 1
                continue

            corr = build_correlation(attack, event)
            if relevance_threshold(corr, max_time_delta=max_time_delta):
                matches.append(corr)
            idx += 1

        # Lines without parseable timestamps cannot be filtered by time.  By
        # default they are not loaded at all, because comparing every such line
        # against every attack can be very expensive.  If the user enables
        # --process-untimestamped-lines, they are scored here with zero time
        # contribution instead of being dropped.
        for event in untimed_events:
            corr = build_correlation(attack, event, force_zero_time_score=True)
            if relevance_threshold(corr, max_time_delta=max_time_delta):
                matches.append(corr)

        # Keep only the strongest matches for this attack.  Ties prefer smaller
        # time deltas, then stable host/file/line ordering.
        matches.sort(key=lambda c: (-c.score, c.abs_delta_seconds, c.host, c.event_file, c.event_line))
        correlations.extend(matches[:max_per_attack])

    correlations.sort(key=lambda c: (c.attack_time, -c.score, c.abs_delta_seconds))
    return correlations

def correlations_by_host(correlations: list[Correlation]) -> dict[str, list[Correlation]]:
    grouped: dict[str, list[Correlation]] = defaultdict(list)
    for corr in correlations:
        if corr.host:
            grouped[corr.host].append(corr)
        for host in corr.target_host_matches:
            if corr not in grouped[host]:
                grouped[host].append(corr)
    for host in grouped:
        grouped[host].sort(key=lambda c: (c.attack_time, -c.score, c.abs_delta_seconds))
    return dict(grouped)
