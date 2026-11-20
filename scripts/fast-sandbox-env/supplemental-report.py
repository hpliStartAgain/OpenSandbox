#!/usr/bin/env python3
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Pure, closed-field report builders for the optional OSEP-0023 supplement.

Run: supplemental-report.py MEASUREMENT SPEC OUT. Raw specs stay private.
M10 uses adjacent A/B blocks as paired experimental units (B minus A),
Student t 95% intervals, never individual sandbox creates as replicates.
"""
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys

_module = importlib.util.spec_from_file_location("bench_report", Path(__file__).with_name("bench-report.py"))
base = importlib.util.module_from_spec(_module)
_module.loader.exec_module(base)


def quantiles(values):
    out = base.latency_summary(values)
    if values:
        out["p99_9"] = base.nearest_rank(sorted(values), 99.9)
    return out


def memory_mix(unbound, bound, fraction):
    return (1 - fraction) * unbound + fraction * bound


def paired_blocks(blocks):
    differences = []
    for i in range(0, len(blocks)-1, 2):
        pair = blocks[i:i+2]
        if {b.get("mode") for b in pair} != {"A", "B"}:
            continue
        values = {b["mode"]: b.get("p50_ms") for b in pair}
        if all(isinstance(v, (int, float)) for v in values.values()):
            differences.append(values["B"] - values["A"])
    n = len(differences)
    mean = statistics.mean(differences) if n else None
    interval = None
    if n >= 2:
        # Student t(.975, df); beyond the table use a conservative df=30.
        critical = [0, 12.706205, 4.302653, 3.182446, 2.776445, 2.570582,
                    2.446912, 2.364624, 2.306004, 2.262157, 2.228139,
                    2.200985, 2.178813, 2.160369, 2.144787, 2.131450,
                    2.119905, 2.109816, 2.100922, 2.093024, 2.085963,
                    2.079614, 2.073873, 2.068658, 2.063899, 2.059539,
                    2.055529, 2.051831, 2.048407, 2.045230, 2.042272]
        half = critical[min(n-1, 30)] * statistics.stdev(differences) / math.sqrt(n)
        interval = [mean-half, mean+half]
    return {"unit": "adjacent A/B block pair", "difference": "B minus A", "n_pairs": n,
            "differences_ms": differences, "mean_ms": mean, "ci95_ms": interval}


def burst_rejections(errors, server_denials):
    # Socket close alone does not establish a budget refusal. Only matching
    # server admission events in this isolated window can attribute closes.
    eligible = sum(v for k, v in errors.items() if k in (
        "handshake/tls_closed", "handshake/reset", "handshake/tls_error", "recv/eof", "recv/reset"))
    attributed = min(max(0, server_denials), eligible)
    return {"budget": attributed, "unattributed": sum(errors.values())-attributed}


def histogram_summary(hist):
    points = sorted((float(k), v) for k, v in hist.items())
    n = sum(v for _, v in points)
    if not n:
        return {"n": 0}
    out = {"n": n, "mean": sum(k*v for k, v in points)/n}
    for pct, label in [(50, "p50"), (90, "p90"), (99, "p99"), (99.9, "p99_9")]:
        rank = math.ceil(n*pct/100); count = 0
        for value, number in points:
            count += number
            if count >= rank:
                out[label] = value
                break
    return out


def run_row(raw):
    fields = ("attempted", "success", "failed", "wall_s", "cpu_s", "concurrency", "connection",
              "body_bytes", "bound_percent", "repeat", "mode", "cpu_limit", "path", "errors",
              "contradictions", "verified", "leaf", "cred", "connections", "released_alive", "group", "total_concurrency", "latency_resolution_ms", "minute_windows")
    row = {k: raw[k] for k in fields if k in raw}
    row["latency_ms"] = histogram_summary(raw["request_histogram_ms"]) if raw.get("request_histogram_ms") else quantiles(raw.get("request_ms", []))
    row["handshake_ms"] = quantiles(raw.get("handshake_ms", []))
    wall = raw.get("wall_s", 0)
    row["rps"] = raw.get("success", 0)/wall if wall > 0 else None
    return row


def run_status(raw):
    if raw.get("contradictions", 0):
        return "INVALID"
    if not raw.get("success", 0):
        return "FAILED"
    if raw.get("failed", 0) or raw.get("verified", raw.get("success")) != raw.get("success"):
        return "PARTIAL"
    return "OK"


def build_m3x(spec):
    paths, statuses = [], []
    for raw in spec.get("paths", []):
        points = [{k: p.get(k) for k in ("k", "held", "alive", "anon", "memory_current", "same_process")}
                  for p in raw.get("points", [])]
        good = [p for p in points if p["held"] == p["k"] == p["alive"] and p["same_process"]]
        fit = {f: base.least_squares([(p["k"], p[f]) for p in good if isinstance(p[f], (int, float))])
               for f in ("anon", "memory_current")}
        status = ("INVALID" if raw.get("contradictions") else "FAILED" if not points else
                  "PARTIAL" if len(good) != len(points) or any(v["slope"] is None for v in fit.values()) else "OK")
        paths.append({"mode": raw.get("mode"), "target": raw.get("target"), "status": status,
                      "points": points, "fit": fit})
        statuses.append(status)
    mixtures = []
    indexed = {(p["mode"], p["target"]): p for p in paths if p["status"] == "OK"}
    for mode in ("all", "credential-bound"):
        if all((mode, t) in indexed for t in ("bound", "unbound")):
            for f in (0, .05, .25, .5, 1):
                mixtures.append({"mode": mode, "bound_fraction": f, "method": "derived from measured slopes",
                                 "bytes_per_connection": {field: memory_mix(indexed[mode, "unbound"]["fit"][field]["slope"],
                                    indexed[mode, "bound"]["fit"][field]["slope"], f) for field in ("anon", "memory_current")}})
    return {"status": base.worst(statuses), "paths": paths, "mixtures": mixtures}


def saturation_points(groups):
    configurations = {}
    for g in groups:
        config = tuple(g.get(k) for k in ("mode", "cpu_limit", "connection", "body_bytes", "bound_percent"))
        if g.get("concurrency") is not None:
            configurations.setdefault(config, {}).setdefault(g["concurrency"], []).append(g)
    results = []
    for config, levels in configurations.items():
        ordered = sorted(levels)
        row = dict(zip(("mode", "cpu_limit", "connection", "body_bytes", "bound_percent"), config))
        row.update(status="NOT_ESTABLISHED", concurrency=None, rps=None, bottleneck=[])
        for previous, current in zip(ordered, ordered[1:]):
            low = statistics.mean(g["rps"] for g in levels[previous])
            high = statistics.mean(g["rps"] for g in levels[current])
            if current >= previous*2 and low > 0 and high/low < 1.1:
                row.update(status="OBSERVED_PLATEAU", concurrency=previous, rps=low,
                           next_concurrency=current, throughput_gain=high/low-1,
                           bottleneck=sorted({v for g in levels[current] for v in g["cpu_bottleneck_candidates"]}))
                break
        results.append(row)
    return results


def build_m5(spec):
    runs = spec.get("runs", [])
    # Saturation attribution requires independent CPU evidence; preserve only
    # measured counters, never guess from RPS alone.
    windows = [{k: x.get(k) for k in ("egress_start", "egress_end", "origin_cpu_s", "client_cpu_s", "wall_s", "group", "concurrency", "bound_percent")}
               for x in spec.get("resource_windows", [])]
    groups = []
    for group in sorted({x.get("group", 0) for x in runs}):
        members = [x for x in runs if x.get("group", 0)==group]
        first = members[0]
        window = next((w for w in windows if w.get("group")==group), {})
        wall = window.get("wall_s") or max([x.get("wall_s", 0) for x in members] or [0])
        cpu = sum(x.get("cpu_s", 0) for x in members)
        e0, e1 = window.get("egress_start") or {}, window.get("egress_end") or {}
        egress_cores = (e1.get("usage_usec", 0)-e0.get("usage_usec", 0))/1e6/wall if wall else None
        candidates = []
        limit = .5 if first.get("cpu_limit")=="500m" else 2
        throttled = e1.get("nr_throttled", 0)-e0.get("nr_throttled", 0)
        if egress_cores is not None and egress_cores >= .9*limit and throttled>0:
            candidates.append("egress")
        if wall and (window.get("origin_cpu_s") or 0)/wall >= .9:
            candidates.append("origin")
        if wall and cpu/wall >= .9*len(members):
            candidates.append("client")
        groups.append({"group": group, "mode": first.get("mode"), "cpu_limit": first.get("cpu_limit"),
                       "concurrency": first.get("total_concurrency"), "connection": first.get("connection"),
                       "body_bytes": first.get("body_bytes"), "bound_percent": first.get("bound_percent"), "repeat": first.get("repeat"),
                       "success": sum(x.get("success", 0) for x in members),
                       "rps": sum(x.get("success", 0)/x["wall_s"] for x in members if x.get("wall_s", 0)>0),
                       "egress_cpu_cores": egress_cores, "client_cpu_cores": cpu/wall if wall else None,
                       "origin_cpu_cores": (window.get("origin_cpu_s") or 0)/wall if wall else None,
                       "cpu_bottleneck_candidates": candidates,
                       "latency_ms": quantiles([v for x in members for v in x.get("request_ms", [])]),
                       "errors": sum(x.get("failed", 0) for x in members)})
    return {"status": base.worst([run_status(r) for r in runs]), "runs": [run_row(r) for r in runs],
            "groups": groups, "saturation": saturation_points(groups), "resource_windows": windows,
            "bottleneck_method": "CPU >=90% of limit (egress also throttled); origin/client >=90% of one core per Python process; candidates require a throughput plateau for attribution"}


def build_time(spec):
    samples = [{k: x.get(k) for k in ("t_s", "memory_current", "anon", "usage_usec", "nr_throttled",
               "throttled_usec", "fd", "conntrack", "oom_kill", "restarts", "origin_cpu_usec")}
               for x in spec.get("samples", [])]
    window = [s for s in samples if s["t_s"] >= spec.get("analysis_start_s", 0)]
    trend = {f: base.least_squares([(s["t_s"], s[f]) for s in window if isinstance(s.get(f), (int, float))])
             for f in ("memory_current", "anon", "fd")}
    status = "MISSING"
    if samples:
        first, last = samples[0], samples[-1]
        invalid = any(s.get("oom_kill") != first.get("oom_kill") or s.get("restarts") != first.get("restarts") for s in samples)
        missing = any(s.get(f) is None for s in samples for f in ("memory_current", "anon", "fd", "oom_kill", "restarts"))
        status = "INVALID" if invalid else "PARTIAL" if missing or len(window)<2 or last["t_s"] < spec.get("duration_s", 0) else "OK"
    runs = spec.get("runs", [])
    if runs:
        status = base.worst([status] + [run_status(r) for r in runs])
    recovery = spec.get("recovery") or {}
    delta = {f: recovery[f]-samples[0][f] for f in ("memory_current", "anon", "fd")
             if samples and isinstance(recovery.get(f), (int, float)) and isinstance(samples[0].get(f), (int, float))}
    minute_windows = [w for raw in runs for w in raw.get("minute_windows", [])]
    usable = [w.get("latency_ms", {}).get("p50") for w in minute_windows if w.get("latency_ms", {}).get("n", 0)>0]
    drift = ((usable[-1]-usable[0])/usable[0]*100) if len(usable)>1 and usable[0] else None
    return {"status": status, "samples": samples, "latency_p50_drift_percent": drift, "analysis_start_s": spec.get("analysis_start_s", 0),
            "trend": trend, "recovery_delta": delta, "runs": [run_row(r) for r in runs],
            "slope_unit": "bytes/second for memory, descriptors/second for FD"}


def build_m7(spec):
    runs = spec.get("runs", [])
    errors = {}
    for r in runs:
        for k, v in r.get("errors", {}).items():
            errors[k] = errors.get(k, 0)+v
    status = base.worst([run_status(r) for r in runs])
    refusal = burst_rejections(errors, spec.get("server_budget_denials", 0))
    if status != "INVALID" and runs:
        if spec.get("passthrough_contradictions", 0):
            status = "INVALID"
        elif (not spec.get("recovered") or spec.get("passthrough_ok") is False
              or any(r.get("released_alive", r.get("success")) != r.get("success") for r in runs)):
            status = base.worst([status, "PARTIAL"])
        elif not refusal["unattributed"] and spec.get("recovered"):
            status = "OK"
    same_subject = spec.get("same_subject_passthrough_runs", [])
    if same_subject:
        status = base.worst([status]+[run_status(r) for r in same_subject])
    return {"status": status, "same_subject_passthrough_runs": [run_row(r) for r in same_subject], "runs": [run_row(r) for r in runs], "rejections": refusal,
            "server_budget_denials": spec.get("server_budget_denials", 0),
            "established_alive": spec.get("established_alive"), "passthrough_ok": spec.get("passthrough_ok"),
            "recovered": spec.get("recovered", False), "recovery_ms": spec.get("recovery_ms")}


def build_m9(spec):
    points, statuses = [], []
    for p in spec.get("points", []):
        row = {k: p.get(k) for k in ("target", "registered", "acked", "active", "capacity_rejections",
                    "registration_ms", "activation_ms", "memory_current", "anon", "usage_usec", "nft_rules")}
        counts = [p.get(k, 0) for k in ("registered", "acked", "active")]
        target = p["target"]
        expected = min(target, 4096)
        if any(type(n) is not int or n < 0 for n in counts) or counts[2] > counts[1] or counts[1] > counts[0] or counts[0] > target:
            status = "INVALID"
        elif counts[0] != target or counts[1:] != [expected, expected] or (target>4096 and not p.get("capacity_rejections")):
            status = "PARTIAL"
        else:
            status = "OK"
        row["status"] = status
        points.append(row); statuses.append(status)
    if points and not spec.get("cleanup_ok"):
        statuses.append("PARTIAL")
    real = spec.get("real_connections") or {}
    if real.get("status") in ("INVALID", "FAILED", "MISSING", "PARTIAL"):
        statuses.append(real["status"])
    if spec.get("recovery_ok") is False:
        statuses.append("PARTIAL")
    return {"status": base.worst(statuses), "recovery_ok": spec.get("recovery_ok"), "points": points, "cleanup_ok": bool(spec.get("cleanup_ok")),
            "real_connections": spec.get("real_connections", {"status": "NOT_RUN"}),
            "per_subject_fit": {field: base.least_squares([(p["acked"], p[field]) for p in points
                if p["status"]=="OK" and p["target"]<=4096 and isinstance(p.get(field), (int, float))])
                for field in ("memory_current", "anon")},
            "ack_method": "successful data-plane-ready is gated by the current registration/fence/generation/digest ACK"}


def build_m10(spec):
    blocks = [{k: b.get(k) for k in ("mode", "p50_ms", "status", "switch_ms", "pod_uid", "live_mode", "warm_ready", "segments")}
              for b in spec.get("blocks", [])]
    sequence = ''.join(b.get("mode") or '?' for b in blocks)
    paired = paired_blocks(blocks)
    status = "MISSING" if not blocks else "INVALID" if not "ABBAABBA".startswith(sequence) else "OK"
    if any(b.get("live_mode") is not None and b["live_mode"] != ("all" if b["mode"]=="A" else "credential-bound") for b in blocks):
        status = "INVALID"
    uids = [b["pod_uid"] for b in blocks if b.get("pod_uid")]
    if len(uids) != len(set(uids)):
        status = "INVALID"
    if status == "OK" and any(b.get("warm_ready") is False for b in blocks):
        status = "PARTIAL"
    if status == "OK" and (len(blocks)!=8 or paired["n_pairs"]!=4 or any(b.get("status", "OK")!="OK" for b in blocks)):
        status = "PARTIAL"
    return {"status": status, "blocks": blocks, "paired": paired,
            "scope": "same cluster, rebuilt Pool per block; no ACK timing attribution"}


BUILDERS = {"m3x": build_m3x, "m5": build_m5, "m6": build_time, "m7": build_m7,
            "m8": build_time, "m9": build_m9, "m10": build_m10}


def build(key, spec):
    if spec.get("not_run"):
        return {"measurement": key.upper(), "status": "NOT_RUN"}
    result = BUILDERS[key](spec)
    result.update(measurement=key.upper(), settings=spec.get("settings", {}), smoke=bool(spec.get("smoke", False)))
    return result


def main(argv):
    key, src, dest = argv
    spec = base.load_json(src)
    out = {"measurement": key.upper(), "status": "MISSING"} if spec is None else build(key, spec)
    base.write(dest, out)
    print(key + " " + out["status"])
    return 1 if out["status"] in ("INVALID", "FAILED", "MISSING") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
