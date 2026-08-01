"""priority_data.py - single source of truth for htb-decision-tree's
per-service priority data. Merges the committed heuristic baseline
(data/baseline-priority-order.json) with live calibrated rates (from
skills/session-management/scripts/attempt-aggregator.sh) when enough real
session history exists.

Imported directly by service-prioritizer.py, and via a sys.path insert by
success-calculator.sh's embedded python (a heredoc can't do a normal
same-directory import, so that script passes its own directory in as an
extra argv - see that script).

Never fabricates precision: a service only gets basis="measured" once its
recorded attempt count crosses min_sample_threshold (skills/session-
management/scripts/state-persistence.sh's record_attempt is what
populates that data - see agents/exploit-agent.md, privesc-agent.md,
loot-agent.md). Everything else is basis="heuristic" and comes from
baseline-priority-order.json's ordinal weight, which is never presented
as a measured percentage by any caller of this module.
"""
import json
import os
import pathlib
import subprocess

HERE = pathlib.Path(__file__).resolve().parent
BASELINE_PATH = HERE / ".." / "data" / "baseline-priority-order.json"
AGGREGATOR = HERE / ".." / ".." / "session-management" / "scripts" / "attempt-aggregator.sh"


def _load_baseline():
    with open(BASELINE_PATH) as f:
        return json.load(f)


def _load_calibrated(min_samples):
    try:
        result = subprocess.run(
            ["bash", str(AGGREGATOR), "compute", "--min-samples", str(min_samples)],
            capture_output=True, text=True, timeout=10, check=True,
        )
        return json.loads(result.stdout)
    except Exception:
        # Calibration unavailable (aggregator missing, no sessions yet,
        # timeout, bad output) -> pure heuristic fallback. Never let a
        # calibration hiccup crash the caller.
        return None


def load_merged_services(min_samples=None):
    """Returns (merged: {service: {...}}, threshold: int)."""
    baseline = _load_baseline()
    threshold = min_samples if min_samples is not None else int(
        os.environ.get("CLAUDE_PLUGIN_OPTION_CALIBRATION_MIN_SAMPLE_SIZE", baseline.get("min_sample_threshold", 5))
    )
    calibrated = _load_calibrated(threshold)
    by_service = (calibrated or {}).get("by_service", {})

    merged = {}
    for entry in baseline["services"]:
        svc = entry["service"]
        measured = by_service.get(svc)
        if measured and measured.get("basis") == "measured":
            merged[svc] = {
                "display_name": entry["display_name"],
                "ports": entry["ports"],
                "notes": entry["notes"],
                "value": measured["rate"],
                "basis": "measured",
                "samples": measured["attempts"],
            }
        else:
            merged[svc] = {
                "display_name": entry["display_name"],
                "ports": entry["ports"],
                "notes": entry["notes"],
                "value": entry["weight"],
                "basis": "heuristic",
                "samples": measured["attempts"] if measured else 0,
            }
    return merged, threshold


def port_to_service_map(merged):
    return {port: svc for svc, entry in merged.items() for port in entry["ports"]}


def format_entry(svc, entry):
    if entry["basis"] == "measured":
        return f"{entry['display_name']} (measured: {entry['value']:.0%} success over {entry['samples']} attempts)"
    return f"{entry['display_name']} (heuristic priority, no measured data yet)"
