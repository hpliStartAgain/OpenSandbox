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
from collections import Counter
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
              "contradictions", "verified", "leaf", "cred", "connections", "released_alive", "group", "total_concurrency", "latency_resolution_ms", "minute_windows", "max_requests", "start_at_s", "end_at_s", "scheduled_start_s", "start_lag_s")
    row = {k: raw[k] for k in fields if k in raw}
    row["latency_ms"] = histogram_summary(raw["request_histogram_ms"]) if raw.get("request_histogram_ms") else quantiles(raw.get("request_ms", []))
    row["handshake_ms"] = quantiles(raw.get("handshake_ms", []))
    row["latency_inputs"] = {"request_histogram_ms": raw.get("request_histogram_ms") or dict(Counter(str(v) for v in raw.get("request_ms", []))),
                             "handshake_histogram_ms": dict(Counter(str(v) for v in raw.get("handshake_ms", []))),
                             "resolution_ms": raw.get("latency_resolution_ms", .001)}
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
    identities = [(p["mode"], p["target"]) for p in paths]
    if len(identities) != len(set(identities)):
        statuses.append("INVALID")
    elif paths and set(identities) != {(mode, target) for mode in ("all", "credential-bound") for target in ("bound", "unbound")}:
        statuses.append("PARTIAL")
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


RESOURCE_FIELDS = ("memory_current", "anon", "fd", "conntrack", "usage_usec", "nr_throttled",
                   "throttled_usec", "oom_kill", "restarts")
COUNTERS = ("usage_usec", "nr_throttled", "throttled_usec", "oom_kill", "restarts", "origin_cpu_usec")

def resource_status(samples):
    if not samples:
        return "MISSING"
    missing = False
    previous = None
    for row in samples:
        missing |= not row.get("identity") or any(row.get(k) is None for k in RESOURCE_FIELDS)
        for k in RESOURCE_FIELDS + ("origin_cpu_usec",):
            v = row.get(k)
            if v is not None and (type(v) not in (int, float) or not math.isfinite(v) or v < 0):
                return "INVALID"
        if previous:
            if row.get("identity") and previous.get("identity") and row["identity"] != previous["identity"]:
                return "INVALID"
            for k in COUNTERS:
                a, b = previous.get(k), row.get(k)
                if a is not None and b is not None and (b < a or (k in ("oom_kill", "restarts") and b != a)):
                    return "INVALID"
        previous = row
    return "PARTIAL" if missing else "OK"


def resource_recovery(tier):
    samples = [{k:s.get(k) for k in RESOURCE_FIELDS+("identity","captured_at_s","t_s","phase","release_elapsed_s","origin_cpu_usec") if k in s} for s in tier.get("resource_samples", [])]
    status = resource_status(samples)
    fields = ("memory_current", "anon", "fd", "conntrack")
    baseline = next((s for s in samples if s.get("phase")=="baseline"), None)
    held = [s for s in samples if s.get("phase")=="held"]
    released = [s for s in samples if s.get("phase")=="released"]
    tolerances = tier.get("resource_tolerances", {})
    recovered = None
    if baseline and held and released and all(k in tolerances for k in fields):
        recovered = next((s for s in released if all(isinstance(s.get(k),(int,float)) and
            isinstance(baseline.get(k),(int,float)) and s[k]-baseline[k] <= tolerances[k] for k in fields)), None)
    if status == "OK" and recovered is None:
        status = "PARTIAL"
    delta = {k: released[-1][k]-baseline[k] for k in fields if baseline and released and
             isinstance(baseline.get(k),(int,float)) and isinstance(released[-1].get(k),(int,float))}
    return dict(status=status, samples=samples, tolerances=tolerances, final_delta=delta,
                recovered=recovered is not None, recovery_s=recovered.get("release_elapsed_s") if recovered else None,
                timeout_s=tier.get("resource_timeout_s"))


def build_m5(spec):
    runs = spec.get("runs", [])
    windows = [{k: x.get(k) for k in ("egress_start", "egress_end", "origin_cpu_s", "wall_s",
                "group", "concurrency", "bound_percent", "scheduled_start_s", "origin_start_s", "origin_end_s")}
               for x in spec.get("resource_windows", [])]
    groups, statuses = [], []
    for group in sorted({x.get("group", 0) for x in runs}):
        members = [x for x in runs if x.get("group", 0)==group]
        first = members[0]
        window = next((w for w in windows if w.get("group")==group), {})
        wall = window.get("wall_s") or 0
        e0, e1 = window.get("egress_start") or {}, window.get("egress_end") or {}
        status = resource_status([e0,e1]) if window else "PARTIAL"
        if window.get("origin_cpu_s") is not None and window["origin_cpu_s"] < 0:
            status = "INVALID"
        if status == "OK" and (wall <= 0 or window.get("origin_cpu_s") is None):
            status = "PARTIAL"
        if window.get("origin_start_s") is not None and window.get("origin_end_s") is not None:
            overlap_origin = max(0,min(e1.get("captured_at_s",0),window["origin_end_s"])-max(e0.get("captured_at_s",0),window["origin_start_s"]))
            if wall <= 0 or overlap_origin/wall < .90:
                status = base.worst([status,"PARTIAL"])
        times = [(x.get("start_at_s"),x.get("end_at_s")) for x in members]
        overlap = None
        if all(isinstance(a,(int,float)) and isinstance(b,(int,float)) and b>a for a,b in times):
            start, end = max(a for a,b in times), min(b for a,b in times)
            # All processes use a scheduled common start. Also verify overlap
            # against the sampled steady window, not only against one another.
            start = max(start, e0.get("captured_at_s",start))
            end = min(end, e1.get("captured_at_s",end))
            overlap = max(0,end-start)
            if not wall or overlap/wall < .90:
                status = base.worst([status,"PARTIAL"])
        else:
            status = base.worst([status,"PARTIAL"])
        if any(not isinstance(x.get("cpu_s"),(int,float)) or x["cpu_s"]<0 or x.get("wall_s",0)<=0 for x in members):
            status = base.worst([status,"PARTIAL"])
        client_cores = sum(x["cpu_s"]/x["wall_s"] for x in members) if all(x.get("wall_s",0)>0 and isinstance(x.get("cpu_s"),(int,float)) for x in members) else None
        egress_cores = (e1["usage_usec"]-e0["usage_usec"])/1e6/wall if status=="OK" else None
        origin_cores = window["origin_cpu_s"]/wall if status=="OK" else None
        candidates = []
        if status == "OK":
            limit = .5 if first.get("cpu_limit")=="500m" else 2
            if egress_cores >= .9*limit and e1["nr_throttled"]>e0["nr_throttled"]:
                candidates.append("egress")
            if origin_cores >= .9:
                candidates.append("origin")
            if client_cores >= .9*len(members):
                candidates.append("client")
        status = base.worst([status]+[run_status(x) for x in members])
        if status != "OK":
            candidates = []
        statuses.append(status)
        groups.append({"group": group, "status":status, "mode": first.get("mode"), "cpu_limit": first.get("cpu_limit"),
                       "concurrency": first.get("total_concurrency"), "connection": first.get("connection"),
                       "body_bytes": first.get("body_bytes"), "bound_percent": first.get("bound_percent"), "repeat": first.get("repeat"),
                       "success": sum(x.get("success", 0) for x in members),
                       "rps": sum(x.get("success",0)/x["wall_s"] for x in members if x.get("wall_s",0)>0),
                       "egress_cpu_cores":egress_cores, "client_cpu_cores":client_cores, "origin_cpu_cores":origin_cores,
                       "overlap_s":overlap, "cpu_bottleneck_candidates":candidates,
                       "latency_ms":quantiles([v for x in members for v in x.get("request_ms",[])]),
                       "errors":sum(x.get("failed",0) for x in members)})
    return {"status":base.worst(statuses), "runs":[run_row(r) for r in runs], "groups":groups,
            "saturation":saturation_points([g for g in groups if g["status"]=="OK"]), "resource_windows":windows,
            "bottleneck_method":"same scheduled steady window; client CPU divided by each process actual active window; >=90% CPU and egress throttling; only OK groups enter plateau inference"}


def build_time(spec):
    samples = [{k: x.get(k) for k in ("t_s", "memory_current", "anon", "usage_usec", "nr_throttled",
               "throttled_usec", "fd", "conntrack", "oom_kill", "restarts", "origin_cpu_usec", "identity", "captured_at_s")}
               for x in spec.get("samples", [])]
    window = [s for s in samples if spec.get("analysis_start_s", 0) <= s["t_s"] <= spec.get("duration_s", math.inf)]
    trend = {f: base.least_squares([(s["t_s"], s[f]) for s in window if isinstance(s.get(f), (int, float))])
             for f in ("memory_current", "anon", "fd")}
    status = "MISSING"
    if samples:
        first, last = samples[0], samples[-1]
        invalid = resource_status(samples) == "INVALID"
        missing = resource_status(samples) != "OK"
        status = "INVALID" if invalid else "PARTIAL" if missing or len(window)<2 or last["t_s"] < spec.get("duration_s", 0) else "OK"
    runs = spec.get("runs", [])
    if runs:
        status = base.worst([status] + [run_status(r) for r in runs])
    recovery = spec.get("recovery") or {}
    idle=(spec.get("resource_windows") or [{}])[0].get("egress_start") or (samples[0] if samples else {})
    baseline={k:idle.get(k) for k in RESOURCE_FIELDS+("identity","captured_at_s","origin_cpu_usec") if k in idle}
    if recovery:
        status=base.worst([status,resource_status([baseline]+samples+[recovery])])
    delta = {f: recovery[f]-baseline[f] for f in ("memory_current", "anon", "fd")
             if baseline and isinstance(recovery.get(f), (int, float)) and isinstance(baseline.get(f), (int, float))}
    minute_windows = [w for raw in runs for w in raw.get("minute_windows", [])]
    usable = [w.get("latency_ms", {}).get("p50") for w in minute_windows if w.get("latency_ms", {}).get("n", 0)>0]
    drift = ((usable[-1]-usable[0])/usable[0]*100) if len(usable)>1 and usable[0] else None
    return {"status": status, "samples": samples, "latency_p50_drift_percent": drift, "analysis_start_s": spec.get("analysis_start_s", 0),
            "trend": trend, "baseline":baseline, "recovery_delta": delta, "runs": [run_row(r) for r in runs],
            "slope_unit": "bytes/second for memory, descriptors/second for FD"}


def build_m7(spec):
    runs, tiers = spec.get("runs", []), spec.get("tiers", [])
    rows, statuses = [], []
    total_refusal = dict(budget=0, unattributed=0)
    for i, raw in enumerate(runs):
        tier = next((t for t in tiers if t.get("group")==raw.get("group",i)), {})
        refusal = burst_rejections(raw.get("errors",{}),tier.get("server_budget_denials",0))
        for k in total_refusal:
            total_refusal[k] += refusal[k]
        status = run_status(raw)
        expected, rejects = tier.get("expected_success"), tier.get("expected_rejections")
        recovery = resource_recovery(tier)
        success, failed = raw.get("success",0), raw.get("failed",0)
        budget=tier.get("budget",{})
        attempted=raw.get("attempted",0)
        numeric_budget=all(type(budget.get(k)) is int and budget[k]>0 for k in ("per_subject","process","available"))
        available=min(budget['per_subject'],budget['process']) if numeric_budget and budget.get('admission_enabled') is True else attempted
        expected_count=min(attempted,available)
        budget_matches=(numeric_budget and budget.get('available')==available and
                        expected==[expected_count,expected_count] and rejects==[attempted-expected_count,attempted-expected_count])
        good = (expected and rejects and success>0 and expected[0]<=success<=expected[1] and
                rejects[0]<=failed<=rejects[1] and raw.get("attempted")==success+failed and
                raw.get("verified")==success and raw.get("released_alive")==success and
                not refusal["unattributed"] and refusal["budget"]==failed and
                tier.get("passthrough_ok") is True and tier.get("same_subject_passthrough_ok") is True and
                tier.get("recovered") is True and budget_matches)
        if raw.get("contradictions") or tier.get("passthrough_contradictions"):
            status = "INVALID"
        elif good:
            status = "OK"
        else:
            status = base.worst([status,"PARTIAL"])
        status = base.worst([status,recovery["status"] if tier else "PARTIAL"])
        statuses.append(status)
        rows.append(dict(group=raw.get("group",i),status=status,budget=tier.get("budget"),
            expected_success=expected,expected_rejections=rejects,rejections=refusal,
            passthrough_ok=tier.get("passthrough_ok"),same_subject_passthrough_ok=tier.get("same_subject_passthrough_ok"),
            injection_recovery_ms=tier.get("injection_recovery_ms"),resource_recovery=recovery))
    if spec.get("passthrough_contradictions"):
        statuses.append("INVALID")
    same_subject = spec.get("same_subject_passthrough_runs",[])
    statuses.extend(run_status(r) for r in same_subject)
    return dict(status=base.worst(statuses),runs=[run_row(r) for r in runs],tiers=rows,
                same_subject_passthrough_runs=[run_row(r) for r in same_subject],rejections=total_refusal,
                passthrough_ok=all(t.get("passthrough_ok") is True for t in tiers) if tiers else None,
                recovered=all(t.get("recovered") is True for t in tiers) if tiers else False)


def build_m9(spec):
    points, statuses = [], []
    for p in spec.get("points", []):
        row = {k: p.get(k) for k in ("target", "registered", "acked", "active", "capacity_rejections",
                    "registration_ms", "activation_ms", "memory_current", "anon", "usage_usec", "nft_rules", "nft_enumeration", "driver_cost", "resource_sample", "usage_excluding_prior_enumeration_usec")}
        counts = [p.get(k, 0) for k in ("registered", "acked", "active")]
        target = p["target"]
        expected = min(target, 4096)
        if any(type(n) is not int or n < 0 for n in counts) or counts[2] > counts[1] or counts[1] > counts[0] or counts[0] > target:
            status = "INVALID"
        elif counts[0] != target or counts[1:] != [expected, expected] or (target>4096 and not p.get("capacity_rejections")):
            status = "PARTIAL"
        else:
            status = "OK"
        if spec.get("resource_scope")=="egress_only_external_driver":
            evidence = [q.get("resource_sample",{}) for q in spec.get("points",[]) if q.get("target",0)<=target]
            evidence_status=resource_status(evidence)
            status=base.worst([status,"PARTIAL" if evidence_status=="MISSING" else evidence_status])
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
            ("egress_per_subject_fit" if spec.get("resource_scope")=="egress_only_external_driver" else "container_total_including_fixture_fit"): {field: base.least_squares([(p["acked"], p[field]) for p in points
                if p["status"]=="OK" and p["target"]<=4096 and isinstance(p.get(field), (int, float))])
                for field in ("memory_current", "anon")},
            "resource_scope":spec.get("resource_scope","container_total_including_fixture"),
            "ack_method": "successful data-plane-ready is gated by the current registration/fence/generation/digest ACK"}


def build_m10(spec):
    blocks = [{k: b.get(k) for k in ("mode", "p50_ms", "status", "switch_ms", "pod_uid", "live_mode", "warm_ready", "segments", "create_latency_ms_inputs")}
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
