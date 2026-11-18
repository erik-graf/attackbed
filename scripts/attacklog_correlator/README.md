# Attack Log Correlator

`attacklog-correlator` correlates AttackMate-style JSON attack logs with heterogeneous Linux host logs. It discovers attack-log files and host-log files, normalizes timestamps, infers candidate target hosts, scores lexical and timing evidence, exports JSON/CSV summaries, and optionally opens an ncurses browser for reviewing the matches.

## Basic usage

The `--root` working directory contains the `attacklogs`, `hostlogs`, and `output` subdirectories. Missing subdirectories are created automatically.

Put the attackmate log files in folders named after the attacker hosts in `root/attacklogs`, so e.g. `root/attacklogs/attacker/attackmate.json`, and the hostlogs in `root/hostlogs/inetfw/..` accordingly. Then run it with `uv run attacklog-correlator --root root`.

Be aware if your machines were set to different timezones during data collection: the first run of the program will generate the file `output/host_config.generated.json`, where you can adapt time zone differences. For the next run, save that file to a different path, e.g. `output/host_config.json`, and pass it as an argument via `--host-config output/host_config.json`, as the generated json is overwritten each run. This is intended behavior.

```bash
uv run attacklog-correlator --root /path/to/workdir
```

Review previously computed output without reparsing or rescoring:

```bash
uv run attacklog-correlator --root /path/to/workdir --view-existing
```

## Manual evidence review

Run the separate curses browser after automatic correlation:

```bash
uv run attacklog-correlator --root /path/to/workdir --manual
# Restrict discovery and parsing to the configured log types:
uv run attacklog-correlator --root /path/to/workdir --manual --strict
```

The manual interface has three vertical panes: **AttackMate steps** on the left,
**logfiles** in the middle, and **log lines** on the right. The right pane also
shows the activated attack's time, command and metadata description (no raw JSON).

Move through attack steps with the arrow keys, Home/End, or `[` / `]`. **Press
Enter to activate the highlighted attack**; moving the highlight alone does not
scan or load logfiles. On the first activation, the browser indexes timestamps
from every discovered logfile once and calculates the matching file lists for
**all attacks**. This initial indexing pass can take time for large datasets.
Subsequent attack switches use the index, and changing a time window recalculates
matching ranges without re-indexing all logfiles. The right pane rereads only
the selected logfile's raw lines on demand (including untimestamped continuation
lines). The selected logfile stays selected when it has entries for the new attack.

Manual review defaults to **0 seconds before and 30 seconds after** the selected
attack. The automatic correlator still runs once before the UI with its own
unchanged defaults (60s before, 240s after, and a strict 5s scoring limit).
`--window-before` and `--window-after` can override both modes' defaults.

Automatic matches are shown in cyan with an `A` marker and are **selected by
default**. `*` means the line will be exported. Space toggles selection for
both automatic and manually chosen lines. Selections are tracked per attack step;
automatic selections outside the visible time window remain in the export unless
you expand the window and deselect them.

The timestamp heatmap is enabled by default: the timestamp closest to the
attack time is **red**, the farthest timestamp in the displayed file/window is
**blue**, and intermediate timestamps receive cooler shades. Only the timestamp
is shaded. Toggle the heatmap with `c`.

Keys: `Tab` or left/right arrows switches between three panes; up/down (or
`j/k`) navigates; **Home/End (Pos1/End)** jumps to the first/last entry;
`[` / `]` (or `p/n`) highlights the previous/next attack; `Enter` activates
it. `+` / `-` adjusts the **post-attack** window by 10 seconds, leaving
the pre-attack window unchanged; `t` lets you enter separate *before* and
*after* offsets in seconds. `h/l` scrolls long lines horizontally; `s`
saves and `q` saves and exits.

The browser writes **one new text file per session** at
`output/manual_selection_<timestamp>.txt`. It contains the selected raw lines,
grouped under AttackMate step and source-logfile headings. Previous selection
files are not overwritten. Automatic JSON/CSV correlation exports remain
unchanged. `--manual` cannot be used with `--view-existing` or `--no-ui`.

## Important options

- `--host-config`: JSON config for host timezones, aliases, clock skew, IP addresses, and attacker timezones.
- `--manual`: open the separate manual evidence-review browser after automatic correlation.
- `--strict`: opt in to reading only files matching the log-type configuration; use only their configured timestamp parser (no fallback guessing).
- `--log-config`: JSON filename-pattern configuration for strict mode (default: the bundled `logtypes.json`). This flag requires `--strict`.
- `--max-time-delta`: strict maximum absolute timestamp delta for timestamped attack/log pairs before content scoring is attempted; defaults to `5.0`.
- `--default-timezone`: timezone for naive host-log timestamps.
- `--window-before` / `--window-after`: broad correlation time window around each attack.
- `--max-per-attack`: maximum saved correlations per attack step.
- `--process-untimestamped-lines`: opt in to loading lines that have no parseable timestamp. By default, those lines are counted but skipped for performance.
- `--view-existing`: open `correlations.json` from the working directory's `output` subdirectory without recomputing.
- `--history [FILE]`: append one indented JSON record per computation, separated by a blank line, including package version, Git revision (when available), source checksum, scoring settings and a copy of `summary.json`. With no FILE argument, writes to `<root>/run-history.jsonl`; relative FILE paths are resolved under `--root`. The file must end in `.jsonl` to avoid corrupting ordinary JSON or CSV exports. No entry is appended in `--view-existing` mode.

## Log-type configuration

Without `--strict`, the correlator keeps its previous recursive file discovery and per-line timestamp parsing behavior. It does not consult the log-type configuration.

For a predictable selection of host logs, enable strict mode:

```bash
uv run attacklog-correlator --root /path/to/workdir --strict --no-ui
uv run attacklog-correlator --root /path/to/workdir --strict --log-config my-log-types.json --no-ui
```

Strict mode recursively searches `hostlogs` but reads **only files** matching a configured filename glob (or a path glob such as `*/apache2/error.log`). The same rule matches files under every host, e.g. both `hostlogs/web/syslog` and `hostlogs/router/syslog.1`. Rules are evaluated in order; the first matching rule determines how to parse that file. A nonmatching file is ignored, and a line the assigned parser cannot read remains untimestamped—other parsers are **not** tried. `--process-untimestamped-lines` continues to control whether those lines are scored without timing evidence.

Copy the bundled `logtypes.json` to customize the rules. Each text log type defines an ordered set of timestamp regexes with **one capture group** containing the timestamp, plus a format (`iso8601`, `epoch`, or Python `strptime`). For example:

```json
{
  "log_types": [
    {
      "name": "syslog",
      "patterns": ["syslog", "syslog.*"],
      "timestamps": [
        {"regex": "^([A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2})\\s+", "format": "%b %d %H:%M:%S"},
        {"regex": "^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2}))\\s+", "format": "iso8601"}
      ]
    },
    {"name": "auditd", "patterns": ["audit.log"], "timestamps": [
      {"regex": "audit\\(([0-9]+(?:\\.[0-9]+)?):[0-9]+\\)", "format": "epoch"}
    ]},
    {"name": "suricata-eve", "patterns": ["eve.json"], "timestamp_key": "timestamp"}
  ]
}
```

Patterns use case-sensitive filename globs, with optional path globs for ambiguous filenames. The first matching log type wins. Within that type, the first *successfully parsed* timestamp pattern wins; no other log types or automatic parsers are consulted. JSON lines are handled by `timestamp_key` instead of regex matching. A timestamp format without a year uses `--default-year`. Naive timestamps still pass through per-host timezone and clock-skew normalization. Compressed files are skipped in strict mode. The default rules also cover CRON, kernel and mail syslog files, dpkg, Apache errors, FTP, Nextcloud, Suricata fast alerts and Wazuh JSON alerts; they deliberately do not select `wtmp`, `btmp`, `pacct`, `.pcap`, `stats.log`, `alerts.log`, Metasploit or RustDesk logs. Apart from journals, binary conversion is not yet implemented.

## Host and attacker timezone config

The generated config can be edited and reused with `--host-config`:

```json
{
  "default_timezone": "Europe/Vienna",
  "default_attacker_timezone": "UTC",
  "hosts": {
    "fileshare": {
      "timezone": "Europe/Vienna",
      "clock_skew_seconds": 0.0,
      "aliases": [],
      "ip_addresses": [],
      "path_hints": ["fileshare"],
      "notes": ""
    }
  },
  "attacker_hosts": {
    "attacker-utc": {
      "timezone": "UTC",
      "utc_offset_hours": 0
    },
    "attacker-vienna": {
      "timezone": "Europe/Vienna",
      "utc_offset_hours": 0
    }
  }
}
```

Attack timestamps with explicit offsets keep their own offset. Naive attack timestamps are interpreted using the matching attacker timezone.

## Run history

Keep a versioned run history:

```bash
uv run attacklog-correlator --root /path/to/workdir --history --no-ui
# Or share one history file across workdirs:
uv run attacklog-correlator --root /path/to/workdir --history /path/to/history.jsonl --no-ui
```

Each run is a pretty-printed JSON object separated from the next by a blank line. The `.jsonl` filename is kept for compatibility with existing histories, but multiline records are **not strict JSON Lines**; `jq -s '.' /path/to/workdir/run-history.jsonl` can still read the whole history. Older single-line entries remain readable. The history contains summary statistics, not full matched log records.

## Outputs

The output directory contains:

- `correlations.json`: all attack steps, matched host-log events, and correlations (with total processed-event counts).
- `correlations.csv`: flat table for spreadsheets.
- `correlations_human.txt`: text report for review.
- `summary.json`: counts and run metadata.
- `host_config.generated.json`: discovered host config template.
- `per_host/`: per-host JSON/CSV/text views.

## Installation for development

```bash
uv sync --extra dev
```

## Development checks

```bash
uv run python -m py_compile src/attacklog_correlator/cli.py
uv run --extra dev pytest
```

## Code structure

The existing CLI options remain available, with strict log-type selection added
as an opt-in. Implementation helpers live in modules instead of `cli.py`:

```text
attacklog_correlator/
  cli.py                 arguments and orchestration
  models.py              Attack, LogRecord, LogEvent, Correlation, RunStats
  config.py              host profiles, aliases, timezones and clock skew
  tokens.py              shared name/token/IP extraction rules
  attacks.py             AttackMate loading and target enrichment
  ingestion/
    discovery.py         existing file-discovery rules
    timestamps.py        existing timestamp parsers
    readers.py           streaming text/journal LogRecords
    logtypes.py          filename-pattern configuration and strict timestamp parsing
  events.py              host enrichment and early candidate filtering
  correlation.py         scoring, relevance and deterministic ranking
  output.py              serialization, saved-output loading and history
  tui.py                 curses browser, search and highlighting
```

The reader has no attack, scoring, host-config or UI dependency. It yields full
source lines with file/line provenance and an optional `ParsedTimestamp`.
Naive timestamps keep their wall-clock value and `naive` flag until `events.py`
applies the host timezone and clock skew. This happens **before** time-window
pruning; expensive token/host-candidate extraction still happens **after** pruning.
Discovery and timestamp recognition retain their original behavior by default;
strict mode adds configurable file selection and assigned timestamp parsing.

```python
from contextlib import closing
from pathlib import Path
from attacklog_correlator.ingestion.readers import iter_log_records
from attacklog_correlator.models import RunStats

stats = RunStats()
with closing(iter_log_records(Path("syslog"), 2026, stats=stats)) as records:
    for record in records:
        print(record.line_number, record.parsed_timestamp, record.raw_line)
```

The iterator preserves file order, including untimestamped records. It does not
sort or impose a correlation window. Read/parse errors propagate; a streaming
consumer may have seen records before an error. The correlation adapter retains
the previous policy of discarding a failed journal's partial results. Closing a
reader early releases its source and terminates an unfinished journal export.

Runtime counters belong to a `RunStats` instance. The `max_time_delta` keyword is
passed explicitly to candidate loading, correlation and export; changing a
module global is no longer a supported way to configure a run. The CLI still
defaults to five seconds, independently on every invocation. Curses is imported
only when opening the UI, so headless use does not require it.

History keeps the same fields and pretty-printed append format. `source_sha256`
now covers all package `.py` files and their relative paths in sorted order,
including ingestion, scoring and TUI changes; it is no longer a checksum of
`cli.py` alone. Old history entries remain readable but used the old hash scope.

This is the boundary for later LogReach functionality, not a LogReach integration:
no new parser fallbacks, inspection commands, dependencies or shared package
were added. Scoring and display matching remain deliberately distinct policies.

### Refactor regression checks

The original 51 tests are retained with imports/patch targets updated to their
owning modules. Four additional end-to-end cases compare fingerprints of the
complete output set against fixes commit `0ada3ee`: default/strict time limits,
untimestamped processing and top-one selection. The fingerprints cover scores,
matched terms, ordering, counters, JSON/CSV/text reports and generated config;
only output creation times and temporary root paths are normalized.

These are synthetic fixtures, not a real collected-log accuracy benchmark.
Additional tests cover the independent streaming API, normalization before
filtering, early cleanup, failed journals, repeated-run isolation, package-wide
source hashing, headless imports and both Python entry points. Python 3.10 syntax
compatibility is checked without adding dependencies.
