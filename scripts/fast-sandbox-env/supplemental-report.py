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
    counts = dict(budget=attributed, handshake_timeout=0, response_timeout=0,
                  connection_refused=0, client_failure=0, unattributed=0)
    left_budget = attributed
    for key, count in errors.items():
        if key in ("handshake/tls_closed", "handshake/reset", "handshake/tls_error", "recv/eof", "recv/reset"):
            used = min(count, left_budget); left_budget -= used
            counts["unattributed"] += count-used
        elif key == "handshake/timeout": counts["handshake_timeout"] += count
        elif key == "recv/timeout": counts["response_timeout"] += count
        elif key.endswith("/refused"): counts["connection_refused"] += count
        elif key.startswith("client/"): counts["client_failure"] += count
        else: counts["unattributed"] += count
    return counts


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
              "contradictions", "verified", "leaf", "cred", "connections", "released_alive", "group", "total_concurrency", "latency_resolution_ms", "minute_windows", "max_requests", "start_at_s", "end_at_s", "scheduled_start_s", "start_lag_s", "memory_preflight", "participant")
    row = {k: raw[k] for k in fields if k in raw}
    row["latency_ms"] = histogram_summary(raw["request_histogram_ms"]) if raw.get("request_histogram_ms") else quantiles(raw.get("request_ms", []))
    row["handshake_ms"] = quantiles(raw.get("handshake_ms", []))
    row["latency_inputs"] = {"request_histogram_ms": raw.get("request_histogram_ms") or dict(Counter(str(v) for v in raw.get("request_ms", []))),
                             "handshake_histogram_ms": dict(Counter(str(v) for v in raw.get("handshake_ms", []))),
                             "resolution_ms": raw.get("latency_resolution_ms", .001)}
    wall = raw.get("wall_s") or 0
    row["rps"] = (raw.get("success") or 0)/wall if wall > 0 else None
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
    paths, statuses, seen = [], [], set()
    for raw in spec.get("paths", []):
        points = [{k: p.get(k) for k in ("k", "held", "alive", "anon", "memory_current", "same_process")}
                  for p in raw.get("points", [])]
        good = [p for p in points if p["held"] == p["k"] == p["alive"] and p["same_process"]]
        fit = {f: base.least_squares([(p["k"], p[f]) for p in good if isinstance(p[f], (int, float))])
               for f in ("anon", "memory_current")}
        status = ("INVALID" if raw.get("contradictions") or any(p["same_process"] is False for p in points) else "FAILED" if not points else
                  "PARTIAL" if len(good) != len(points) or any(v["slope"] is None for v in fit.values()) else "OK")
        identity = (raw.get("pod_uid"), raw.get("process_identity"))
        baseline_check = {"threshold": "max(32 MiB, 20% of reference)", "comparisons": []}
        if not all(identity) or not raw.get("fresh_baseline") or not raw.get("mode_baseline"):
            status = base.worst([status, "PARTIAL"])
        else:
            if identity in seen or any(identity[0]==x[0] or identity[1]==x[1] for x in seen):
                status = "INVALID"
            seen.add(identity)
            zero = next((p for p in points if p["k"]==0), {})
            for source in ("fresh_baseline", "mode_baseline"):
                for field in ("anon", "memory_current"):
                    reference, actual = raw[source].get(field), zero.get(field)
                    if not isinstance(reference,(int,float)) or not isinstance(actual,(int,float)):
                        status=base.worst([status,"PARTIAL"]); continue
                    threshold=max(32*1024*1024, .2*reference)
                    ok=abs(actual-reference)<=threshold
                    baseline_check["comparisons"].append(dict(source=source,field=field,reference=reference,actual=actual,threshold_bytes=threshold,ok=ok))
                    if not ok: status="INVALID"
        paths.append({"pod_uid":raw.get("pod_uid"),"process_identity":raw.get("process_identity"),"baseline_check":baseline_check,"mode": raw.get("mode"), "target": raw.get("target"), "status": status,
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
        if len(indexed)==4 and len(paths)==4 and all(x=="OK" for x in statuses):
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
        if any(g.get('status','OK')!='OK' for rows in levels.values() for g in rows):
            continue
        means={c:statistics.mean(g['rps'] for g in levels[c]) for c in ordered}
        row['tolerance_fraction']=.1
        row['review_reason']='no_sustained_plateau'
        if any(not math.isfinite(v) or v<=0 for v in means.values()):
            results.append(row);continue
        if any(means[b]<.9*means[a] for a,b in zip(ordered,ordered[1:])):
            row['review_reason']='throughput_drop';results.append(row);continue
        for previous,current in zip(ordered,ordered[1:]):
            low,high=means[previous],means[current]
            if current>=previous*2 and .9<=high/low<=1.1:
                tail=[g for c in ordered if c>=previous for g in levels[c]]
                row['checked_concurrencies']=[c for c in ordered if c>=previous]
                if all(math.isfinite(g['rps']) and .9<=g['rps']/low<=1.1 for g in tail):
                    row.update(status='OBSERVED_PLATEAU',concurrency=previous,rps=low,
                        next_concurrency=current,throughput_gain=high/low-1,review_reason=None,
                        bottleneck=sorted({v for g in tail for v in g['cpu_bottleneck_candidates']}))
                else:
                    row['review_reason']='later_points_or_repeats_outside_band'
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
    samples = [{k:s.get(k) for k in RESOURCE_FIELDS+("identity","captured_at_s","t_s","phase","release_elapsed_s","origin_cpu_usec") if k in s} for s in (tier.get("resource_samples") or [])]
    status = resource_status(samples)
    fields = ("memory_current", "anon", "fd", "conntrack")
    baseline = next((s for s in samples if s.get("phase")=="baseline"), None)
    held = [s for s in samples if s.get("phase")=="held"]
    released = [s for s in samples if s.get("phase")=="released"]
    tolerances = tier.get("resource_tolerances") or {}
    recovered = None
    if baseline and held and released and all(type(tolerances.get(k)) in (int,float) for k in fields):
        final = released[-1]
        if all(isinstance(final.get(k),(int,float)) and isinstance(baseline.get(k),(int,float)) and
               final[k]-baseline[k] <= tolerances[k] for k in fields):
            recovered = final
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
        if type(wall) not in (int,float) or not math.isfinite(wall):
            wall=0
        origin_cpu=window.get("origin_cpu_s")
        if origin_cpu is not None and (type(origin_cpu) not in (int,float) or not math.isfinite(origin_cpu) or origin_cpu<0):
            status="INVALID"
        if status=="OK" and (wall<=0 or origin_cpu is None):
            status="PARTIAL"
        boundaries=[e0.get("captured_at_s"),e1.get("captured_at_s"),window.get("origin_start_s"),window.get("origin_end_s")]
        origin_wall=0
        if all(type(v) in (int,float) and math.isfinite(v) for v in boundaries):
            es,ee,os,oe=boundaries
            origin_wall=oe-os
            tolerance=max(.1,.01*wall)
            if origin_wall<=0 or abs(os-es)>tolerance or abs(oe-ee)>tolerance:
                status=base.worst([status,"PARTIAL"])
        else:
            status=base.worst([status,"PARTIAL"])
        times = [(x.get("start_at_s"),x.get("end_at_s")) for x in members]
        overlap = None
        if all(isinstance(a,(int,float)) and isinstance(b,(int,float)) and b>a for a,b in times):
            start, end = max(a for a,b in times), min(b for a,b in times)
            # All processes use a scheduled common start. Also verify overlap
            # against the sampled steady window, not only against one another.
            start = max(start, e0.get("captured_at_s",start))
            end = min(end, e1.get("captured_at_s",end))
            overlap = max(0,end-start)
            if not wall or overlap/max([wall]+[b-a for a,b in times]) < .90:
                status = base.worst([status,"PARTIAL"])
        else:
            status = base.worst([status,"PARTIAL"])
        if any(not isinstance(x.get("cpu_s"),(int,float)) or x["cpu_s"]<0 or x.get("wall_s",0)<=0 for x in members):
            status = base.worst([status,"PARTIAL"])
        client_cores = sum(x["cpu_s"]/x["wall_s"] for x in members) if all(x.get("wall_s",0)>0 and isinstance(x.get("cpu_s"),(int,float)) for x in members) else None
        egress_cores = (e1["usage_usec"]-e0["usage_usec"])/1e6/wall if status=="OK" else None
        origin_cores = origin_cpu/origin_wall if status=="OK" else None
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
            "saturation":saturation_points(groups), "resource_windows":windows,
            "bottleneck_method":"same scheduled steady window; observed egress/origin boundaries within max(0.1 s, 1% of window); CPU divided by each actual counter/process window; >=90% CPU and egress throttling; only OK groups enter plateau inference"}


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
    idle=spec.get("idle_baseline") or {}
    baseline={k:idle.get(k) for k in RESOURCE_FIELDS+("identity","captured_at_s","origin_cpu_usec") if k in idle}
    if recovery:
        status=base.worst([status,resource_status([baseline]+samples+[recovery])])
        if not baseline:
            status=base.worst([status,"PARTIAL"])
    delta = {f: recovery[f]-baseline[f] for f in ("memory_current", "anon", "fd")
             if baseline and isinstance(recovery.get(f), (int, float)) and isinstance(baseline.get(f), (int, float))}
    latency_segments=[]
    for raw in runs:
        usable=[w.get("latency_ms",{}).get("p50") for w in raw.get("minute_windows",[]) if w.get("latency_ms",{}).get("n",0)>0]
        drift=((usable[-1]-usable[0])/usable[0]*100) if len(usable)>1 and usable[0] else None
        latency_segments.append(dict(group=raw.get("group"),concurrency=raw.get("total_concurrency",raw.get("concurrency")),
            p50_first_ms=usable[0] if usable else None,p50_last_ms=usable[-1] if usable else None,
            window_count=len(usable),p50_drift_percent=drift))
    groups = {x.get("group",0) for x in runs}
    active_s = sum(max([x.get("wall_s",0) for x in runs if x.get("group",0)==g] or [0]) for g in groups)
    actual_rps = sum(x.get("success",0) for x in runs)/active_s if active_s>0 else None
    target_rate = spec.get("settings",{}).get("rate_rps")
    return {"status": status, "samples": samples, "actual_rps":actual_rps,
            "actual_to_target_rate_ratio":actual_rps/target_rate if actual_rps is not None and isinstance(target_rate,(int,float)) and target_rate>0 else None,
            "latency_segments": latency_segments, "analysis_start_s": spec.get("analysis_start_s", 0),
            "trend": trend, "baseline":baseline, "recovery_delta": delta, "runs": [run_row(r) for r in runs],
            "slope_unit": "bytes/second for memory, descriptors/second for FD"}


def m7_members(members, tier):
    budget=tier.get("budget") or {}; allocations=tier.get("allocations")
    if allocations is None:
        allocations=[x.get("attempted",0) for x in members]
    allocations=[n if type(n) is int and n>0 else 0 for n in allocations]
    declared=tier.get("members") or [dict(participant="guest-"+str(i),allocation=n) for i,n in enumerate(allocations)]
    strict=tier.get("allocations") is not None
    expected={x.get("participant"):x.get("allocation") for x in declared}
    identities=[x.get("participant") for x in members]
    identity_ok=(not strict or (len(expected)==len(declared)==len(members) and [x.get("allocation") for x in declared]==allocations and None not in identities and
                 len(set(identities))==len(members) and set(identities)==set(expected)))
    admission=budget.get("admission_enabled") is True
    numeric=all(type(budget.get(k)) is int and budget[k]>0 for k in ("per_subject","process"))
    caps=[min(n,budget["per_subject"]) if admission and numeric else n for n in allocations]
    process_shared=bool(admission and numeric and budget["process"]<sum(caps))
    rows=[]
    for i,member in enumerate(members):
        n=expected.get(member.get("participant")) if strict else allocations[i]
        fields=("attempted","success","failed","verified","released_alive")
        good=identity_ok and numeric and type(n) is int and n>0 and all(type(member.get(k)) is int and member[k]>=0 for k in fields)
        cap=min(n,budget["per_subject"]) if good and admission else n
        errors=member.get("errors")
        good=good and isinstance(errors,dict) and all(type(v) is int and v>=0 for v in errors.values())
        if good:
            good=(member["attempted"]==n==member["success"]+member["failed"] and member["verified"]==member["released_alive"]==member["success"] and
                  member["success"]<=cap and sum(errors.values())==member["failed"] and (process_shared or member["success"]==cap))
        rows.append(dict(participant=member.get("participant"),allocation=n,success=member.get("success"),subject_upper_bound=cap,
                         process_shared=process_shared,status="OK" if good else "PARTIAL"))
    return rows


def build_m7_fill(spec):
    runs=spec.get('runs') or [];tiers=spec.get('tiers') or []
    raw=runs[0] if len(runs)==1 else {};tier=tiers[0] if len(tiers)==1 else {}
    mode=spec.get('mode');cap=(tier.get('budget') or {}).get('per_subject',0)
    fill=raw.get('fill') or {};batches=fill.get('batches') or []
    errors=raw.get('errors') or {};proof=spec.get('large_guest') or {}
    pool=proof.get('pool') or {};pre=proof.get('full_boundary_preflight') or {}
    probes=spec.get('overflow_probes') or {};unbound=probes.get('unbound') or {};bound=probes.get('new_bound') or {}
    def successful(p):
        return p.get('attempted')==p.get('success')==p.get('verified')==1 and p.get('failed')==0 and not p.get('contradictions') and not p.get('errors')
    numeric=lambda x:type(x) is int and x>=0
    counters=all(numeric(raw.get(k)) for k in ('attempted','success','failed','verified','released_alive','held','boundary_verified'))
    config=(type(fill.get('batch_size')) is int and 1<=fill['batch_size']<=2048 and
        isinstance(fill.get('batch_interval_s'),(int,float)) and math.isfinite(fill['batch_interval_s']) and fill['batch_interval_s']>=0 and
        type(fill.get('max_retries')) is int and 0<=fill['max_retries']<=10 and
        fill.get('attempt_limit')==cap*(1+fill['max_retries']))
    batch_ok=bool(batches) and config and all(isinstance(b,dict) and all(numeric(b.get(k)) for k in ('attempted','verified','failed','held')) and
        0<b['attempted']<=fill['batch_size'] and b['attempted']==b['verified']+b['failed'] and b['held']<=cap and
        isinstance(b.get('errors'),dict) and all(numeric(v) for v in b['errors'].values()) and sum(b['errors'].values())==b['failed'] for b in batches)
    count_ok=(counters and config and batch_ok and raw['attempted']<=fill['attempt_limit'] and
        raw['attempted']==raw['success']+raw['failed'] and raw['success']==raw['verified']==raw['held']==raw['boundary_verified']==raw['released_alive']==cap and
        isinstance(errors,dict) and all(numeric(v) for v in errors.values()) and sum(errors.values())==raw['failed'] and
        all(sum(b[k] for b in batches)==raw[k] for k in ('attempted','verified','failed')) and
        dict(sum((Counter(b['errors']) for b in batches),Counter()))==errors and
        all(b['held']==sum(x['verified'] for x in batches[:i+1]) for i,b in enumerate(batches)))
    server=tier.get('server_held') or {}
    client_pre=raw.get('memory_preflight') or {}
    client_memory_ok=(client_pre.get('status')=='OK' and client_pre.get('concurrency')==cap and
        client_pre.get('required_bytes')==cap*384*1024+64*1024*1024 and client_pre.get('available_bytes',0)>=client_pre.get('required_bytes',1))
    full=(raw.get('mode')==mode and (tier.get('budget') or {}).get('admission_enabled')==(mode=='credential-bound') and
        raw.get('fill_status')=='FULL' and count_ok and cap>0 and (spec.get('smoke') is True or cap==2048) and
        client_memory_ok and server.get('source')=='egress_tcp_peer_match' and server.get('established')==server.get('matched_endpoints')==cap)
    guest_ok=(proof.get('mem_total_bytes',0)>=int(1.8*1024**3) and pool.get('scheduled') is True and pool.get('budget_sufficient') is True and
        pool.get('sandbox_limit_memory_bytes')==2*1024**3 and pre.get('status')=='OK' and pre.get('concurrency')==2049 and
        pre.get('required_bytes')==2049*384*1024+64*1024*1024 and pre.get('available_bytes',0)>=pre.get('required_bytes',1))
    denial=tier.get('probe_server_budget_denials',0)
    be=bound.get('errors') or {}
    rejected=(bound.get('attempted')==bound.get('failed')==1 and bound.get('success')==bound.get('verified',0)==0 and
        not bound.get('contradictions') and isinstance(be,dict) and all(numeric(v) for v in be.values()) and sum(be.values())==1 and
        denial==1 and burst_rejections(be,denial)['budget']==1)
    ids=[raw.get('participant'),unbound.get('participant'),bound.get('participant')]
    probe_ok=(tier.get('probe_sent') is True and None not in ids and len(set(ids))==3 and probes.get('target_participant')==ids[0] and
        successful(unbound) and (rejected if mode=='credential-bound' else successful(bound) and denial==0))
    recovery=resource_recovery(tier)
    ok=(mode in ('all','credential-bound') and full and guest_ok and probe_ok and tier.get('recovered') is True and recovery['status']=='OK')
    invalid=any(x.get('contradictions',0) or x.get('status')=='INVALID' for x in (raw,unbound,bound))
    status='INVALID' if invalid or recovery['status']=='INVALID' else 'OK' if ok else 'PARTIAL'
    reason=raw.get('fill_reason') if raw.get('fill_reason') in ('capacity_reached','retry_limit_reached','non_retryable_failure') else 'fill_evidence_incomplete'
    summary=dict(status=status,mode=mode,expected='budget_rejection' if mode=='credential-bound' else 'no_per_subject_budget',
        capacity=cap,full_boundary=cap==2048,held=raw.get('held'),boundary_verified=raw.get('boundary_verified'),fill_reason=reason,
        fill={k:fill.get(k) for k in ('batch_size','batch_interval_s','max_retries','attempt_limit')},
        batches=[{k:b.get(k) for k in ('attempted','verified','failed','held','errors')} for b in batches],
        server_held={k:server.get(k) for k in ('source','established','matched_endpoints')},probe_sent=tier.get('probe_sent',False),
        probe_server_budget_denials=denial,large_guest=proof,probes=dict(target_participant=probes.get('target_participant'),unbound=run_row(unbound),new_bound=run_row(bound)))
    return dict(status=status,mode=mode,runs=[run_row(x) for x in runs],single_subject_overflow=summary,
        tiers=[dict(status=status,budget=tier.get('budget'),resource_recovery=recovery,injection_recovery_ms=tier.get('injection_recovery_ms'))],
        recovered=tier.get('recovered') is True,rejections=burst_rejections(be,denial))


def build_m7(spec):
    if spec.get('gradual_fill') is True:return build_m7_fill(spec)
    source_runs, tiers = spec.get("runs") or [], spec.get("tiers") or []
    runs=[]; member_results={}
    for group in dict.fromkeys(x.get("group",i) for i,x in enumerate(source_runs)):
        members=[x for i,x in enumerate(source_runs) if x.get("group",i)==group]
        tier=next((t for t in tiers if t.get("group")==group),{})
        member_results[group]=m7_members(members,tier)
        if len(members)==1:
            runs.append(members[0]);continue
        merged=dict(members[0],group=group)
        for field in ("attempted","success","failed","verified","released_alive","contradictions","connections","cpu_s","concurrency"):
            merged[field]=sum(x.get(field) if isinstance(x.get(field),(int,float)) else 0 for x in members)
        complete=all(isinstance(x.get("errors"),dict) and all(type(v) is int and v>=0 for v in x["errors"].values()) for x in members)
        merged["errors"]=dict(sum((Counter(x["errors"]) for x in members),Counter())) if complete else None
        merged["wall_s"]=max(x.get("wall_s",0) for x in members)
        for field in ("request_ms","handshake_ms"):
            merged[field]=[v for x in members for v in x.get(field,[])]
        runs.append(merged)
    rows, statuses = [], []
    total_refusal = burst_rejections({},0)
    for i, raw in enumerate(runs):
        tier = next((t for t in tiers if t.get("group")==raw.get("group",i)), {})
        errors=raw.get("errors")
        errors_complete=isinstance(errors,dict) and all(type(v) is int and v>=0 for v in errors.values())
        refusal = burst_rejections(errors if errors_complete else {},tier.get("server_budget_denials") or 0)
        for k in total_refusal:
            total_refusal[k] += refusal[k]
        status = run_status(raw)
        expected, rejects = tier.get("expected_success"), tier.get("expected_rejections")
        recovery = resource_recovery(tier)
        success, failed = (raw.get(k) if type(raw.get(k)) is int else 0 for k in ("success","failed"))
        budget=tier.get("budget") or {}
        attempted=raw.get("attempted") if type(raw.get("attempted")) is int else 0
        numeric_budget=all(type(budget.get(k)) is int and budget[k]>0 for k in ("per_subject","process","available"))
        allocations=tier.get("allocations")
        subject_available=sum(min(budget['per_subject'],n) for n in allocations) if numeric_budget and allocations else budget.get('per_subject',0)
        available=min(subject_available,budget['process']) if numeric_budget and budget.get('admission_enabled') is True else attempted
        expected_count=min(attempted,available)
        budget_matches=(numeric_budget and budget.get('available')==available and
                        expected==[expected_count,expected_count] and rejects==[attempted-expected_count,attempted-expected_count])
        member_checks=member_results[raw.get("group",i)]
        good = (all(x["status"]=="OK" for x in member_checks) and errors_complete and expected and rejects and success>0 and expected[0]<=success<=expected[1] and
                rejects[0]<=failed<=rejects[1] and raw.get("attempted")==success+failed and
                raw.get("verified")==success and raw.get("released_alive")==success and
                not refusal["unattributed"] and refusal["budget"]==failed and sum(errors.values())==failed and
                tier.get("passthrough_ok") is True and tier.get("same_subject_passthrough_ok") is True and
                tier.get("recovered") is True and budget_matches)
        members=[x for j,x in enumerate(source_runs) if x.get("group",j)==raw.get("group",i)]
        synchronized=None
        if tier.get("allocations"):
            starts=[x.get("scheduled_start_s") for x in members]
            synchronized=(len(members)==len(tier["allocations"]) and all(isinstance(t,(int,float)) for t in starts) and
                          len(set(starts))==1 and all(0<=x.get("start_lag_s",-1)<=1 for x in members))
            memory_ok=True
            declared=tier.get("members") or [dict(participant="guest-"+str(j),allocation=n) for j,n in enumerate(tier["allocations"])]
            assigned={x["participant"]:x["allocation"] for x in declared}
            for member in members:
                count=assigned.get(member.get("participant"),0)
                check=member.get("memory_preflight") or {}
                required=count*384*1024+64*1024*1024
                memory_ok=memory_ok and (check.get("status")=="OK" and check.get("concurrency")==count and
                    check.get("required_bytes")==required and isinstance(check.get("available_bytes"),(int,float)) and check["available_bytes"]>=required)
            if not synchronized or not memory_ok or sum(tier["allocations"])!=attempted:good=False
        if raw.get("contradictions") or tier.get("passthrough_contradictions") or any(x.get("status")=="INVALID" for x in members):
            status = "INVALID"
        elif good:
            status = "OK"
        else:
            status = base.worst([status,"PARTIAL"])
        status = base.worst([status,recovery["status"] if tier else "PARTIAL"])
        statuses.append(status)
        rows.append(dict(group=raw.get("group",i),status=status,member_checks=member_checks,synchronized_start=synchronized,allocations=tier.get("allocations"),client_memory_preflights=[x.get("memory_preflight") for x in members],budget=tier.get("budget"),
            expected_success=expected,expected_rejections=rejects,rejections=refusal,
            passthrough_ok=tier.get("passthrough_ok"),same_subject_passthrough_ok=tier.get("same_subject_passthrough_ok"),
            injection_recovery_ms=tier.get("injection_recovery_ms"),resource_recovery=recovery))
    if spec.get("passthrough_contradictions"):
        statuses.append("INVALID")
    same_subject = spec.get("same_subject_passthrough_runs",[])
    statuses.extend(run_status(r) for r in same_subject)
    out=dict(status=base.worst(statuses),runs=[run_row(r) for r in source_runs],tiers=rows,
                same_subject_passthrough_runs=[run_row(r) for r in same_subject],rejections=total_refusal,
                passthrough_ok=all(t.get("passthrough_ok") is True for t in tiers) if tiers else None,
                recovered=all(t.get("recovered") is True for t in tiers) if tiers else False)
    if spec.get("single_subject_overflow"):
        proof=spec.get("large_guest") or {}; budget_proof=proof.get("pool") or {}; full=proof.get("full_boundary_preflight") or {}
        probes=spec.get("overflow_probes") or {}; unbound=probes.get("unbound") or {}; denied=probes.get("new_bound") or {}
        tier=tiers[0] if len(tiers)==1 else {}; budget=tier.get("budget") or {}; cap=budget.get("per_subject",0)
        participants={x.get("participant") for x in source_runs}
        guest_ok=(proof.get("mem_total_bytes",0)>=int(1.8*1024**3) and budget_proof.get("scheduled") is True and
            budget_proof.get("sandbox_limit_memory_bytes")==2*1024**3 and budget_proof.get("budget_sufficient") is True and
            full.get("status")=="OK" and full.get("concurrency")==2049 and full.get("required_bytes")==2049*384*1024+64*1024*1024 and
            full.get("available_bytes",0)>=full.get("required_bytes",1))
        boundary_ok=(len(source_runs)==1 and tier.get("allocations")==[cap+1] and cap>0 and
                     source_runs[0].get("mode")=="credential-bound" and (spec.get("smoke") is True or cap==2048))
        probe_ids={unbound.get("participant"),denied.get("participant")}
        probe_ok=(None not in probe_ids and len(probe_ids)==2 and not participants.intersection(probe_ids) and
            probes.get("target_participant") in participants and unbound.get("attempted")==unbound.get("success")==unbound.get("verified")==1 and
            unbound.get("failed")==0 and not unbound.get("contradictions") and denied.get("attempted")==denied.get("failed")==1 and
            denied.get("success")==denied.get("verified",0)==0 and not denied.get("contradictions") and isinstance(denied.get("errors"),dict) and all(type(v) is int and v>=0 for v in denied["errors"].values()) and sum(denied["errors"].values())==1 and
            burst_rejections(denied["errors"],max(0,(tier.get("server_budget_denials") or 0)-sum(x.get("failed",0) for x in source_runs)))["budget"]==1)
        coverage="OK" if guest_ok and boundary_ok and probe_ok and out["status"]=="OK" else "PARTIAL"
        out["status"]=base.worst([out["status"],coverage]);out["single_subject_overflow"]={"status":coverage,"large_guest":proof,"probes":{
            "target_participant":probes.get("target_participant"),"unbound":run_row(unbound),"new_bound":run_row(denied)},
            "capacity":cap,"burst":cap+1,"full_boundary":cap==2048}
    if spec.get("require_single_subject_overflow"):
        child=spec.get("overflow_spec") or {}
        overflow=build_m7(child) if child.get("single_subject_overflow") is True and not child.get("require_single_subject_overflow") else {"status":"MISSING"}
        out["overflow_coverage"]=overflow
        out["status"]=base.worst([out["status"],overflow["status"] if overflow["status"]!="MISSING" else "PARTIAL"])
    return out



def build_m9(spec):
    points, statuses = [], []
    for p in spec.get("points", []):
        row = {k: p.get(k) for k in ("target", "registered", "acked", "active", "capacity_rejections",
                    "registration_ms", "activation_ms", "rejections", "initial_capacity_log_count", "recovery_capacity_log_count", "memory_current", "anon", "usage_usec", "nft_rules", "nft_enumeration", "driver_cost", "resource_sample", "usage_excluding_prior_enumeration_usec")}
        counts = [p.get(k, 0) for k in ("registered", "acked", "active")]
        target = p["target"]
        expected = min(target, 4096)
        rejected=p.get('rejections') or []
        recovery=spec.get('recovery') or {}
        overflow_good=False
        if target>4096 and len(rejected)==target-4096==1:
            refusal=rejected[0]
            index=refusal.get('object_index')
            stage=refusal.get('stage')
            stage_good=(stage=='SET' and refusal.get('set_status')==503 and counts[0]==expected or
                        stage=='ready' and refusal.get('set_status')==200 and refusal.get('ready_status')==503 and
                        bool(refusal.get('ready_attempt_statuses')) and all(c==503 for c in refusal['ready_attempt_statuses']) and counts[0]==target)
            attempts=recovery.get('attempts') or []
            release=recovery.get('release_attempts') or []
            final=recovery.get('final_counts') or {}
            overflow_good=(type(index) is int and index>=0 and stage_good and
                refusal.get('phase')=='initial' and refusal.get('reason')=='subject_capacity_exhausted' and
                refusal.get('capacity_before') is False and refusal.get('capacity_after') is True and
                refusal.get('attribution')=='isolated_serial_action_status_transition' and
                p.get('capacity_rejections')==1 and counts[1:]==[expected,expected] and
                all(type(p.get(k)) is int and p[k]>=0 for k in ('initial_capacity_log_count','recovery_capacity_log_count')) and
                recovery.get('object_index')==index and recovery.get('release_confirmed') is True and
                release and release[-1].get('remove_status')==200 and release[-1].get('ready_status')==409 and
                type(recovery.get('released_object_index')) is int and recovery['released_object_index']>=0 and
                recovery['released_object_index']!=index and all(final.get(k)==expected for k in ('registered','acked','active')) and
                attempts and attempts[-1].get('set_status')==200 and attempts[-1].get('ready_status')==200 and
                spec.get('recovery_ok') is True)
        if any(type(n) is not int or n < 0 for n in counts) or counts[2] > counts[1] or counts[1] > counts[0] or counts[0] > target:
            status = 'INVALID'
        elif target>4096 and not overflow_good or target<=4096 and counts!=[target]*3:
            status = 'PARTIAL'
        else:
            status = 'OK'
        if spec.get("resource_scope")=="egress_only_external_driver":
            evidence = [q.get("resource_sample",{}) for q in spec.get("points",[]) if q.get("target",0)<=target]
            evidence_status=resource_status(evidence)
            status=base.worst([status,"PARTIAL" if evidence_status=="MISSING" else evidence_status])
        row["status"] = status
        row["outcome"] = "expected_overflow" if target>4096 and status=="OK" else "within_capacity" if status=="OK" else "incomplete"
        points.append(row); statuses.append(status)
    if points and not spec.get("cleanup_ok"):
        statuses.append("PARTIAL")
    real = spec.get("real_connections") or {}
    if real.get("status") in ("INVALID", "FAILED", "MISSING", "PARTIAL"):
        statuses.append(real["status"])
    if spec.get("recovery_ok") is False:
        statuses.append("PARTIAL")
    return {"status": base.worst(statuses), "recovery_ok": spec.get("recovery_ok"), "recovery":spec.get("recovery"), "points": points, "cleanup_ok": bool(spec.get("cleanup_ok")),
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
