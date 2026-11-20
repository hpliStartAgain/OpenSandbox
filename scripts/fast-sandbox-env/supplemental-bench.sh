#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
# SPDX-License-Identifier: Apache-2.0
# Optional bench only. Sourced after integration-env.sh has loaded its helpers.
SUP_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=credential-bound-bench.sh
source "$SUP_SELF_DIR/credential-bound-bench.sh"

sup_report() {
	python3 "$SUP_SELF_DIR/supplemental-report.py" "$1" "$SUP_RAW/$1-spec.json" "$SUP_DIR/$1.json"
	[[ "$(jq -r .status "$SUP_DIR/$1.json")" != INVALID ]] || fail "supplemental $1 INVALID"
}

sup_spec() {
	jq -n --argjson smoke "$SUP_SMOKE" --arg mem "$BENCH_EGRESS_MEMORY_LIMIT" --argjson cap "$BENCH_FSB_TLS_CAPACITY" \
		--argjson guests "$SUP_LOAD_GUESTS" --argjson load "$SUP_LOAD_S" --argjson idle "$SUP_IDLE_S" \
		'{smoke:$smoke, settings:{egress_memory_limit:$mem,per_subject_tls_capacity:$cap,load_guests:$guests,load_seconds:$load,idle_seconds:$idle}, runs:[], samples:[], paths:[], blocks:[], points:[]}'  > "$SUP_RAW/$1-spec.json"
}

sup_sample() { # -> closed counters for the selected egress + origin
	local counters extra origin identity reading
	counters="$(bench_egress_cgroup "$BENCH_POD")" || { printf '{"status":"MISSING","reason":"egress counters unavailable"}\n' > "$SUP_DIR/missing-resource.json"; return 1; }
	extra="$(kubectl -n "$RESOURCE_NS" exec "$BENCH_POD" -c egress -- sh -c '
		fd=0; for p in /proc/[0-9]*; do n=$(ls "$p/fd" 2>/dev/null | wc -l); fd=$((fd+n)); done
		printf "%s " "$fd"
		cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo null' 2>/dev/null)" || return 1
	identity="$(bench_egress_identity "$BENCH_POD")" || identity=""
	if [[ -n "$identity" && "$identity" != "$SUP_SAMPLE_ID" ]]; then
		printf '{"status":"INVALID","reason":"egress container identity changed"}\n' > "$SUP_DIR/invalid-resource.json"; return 1
	fi
	[[ -z "$identity" ]] || identity=initial
	origin="$(docker exec "$CB_ORIGIN_CONTAINER" sh -c 'cat /sys/fs/cgroup/cpu.stat' | awk '$1=="usage_usec" {print $2}')" || origin=null
	reading="$(jq -c --arg identity "$identity" --argjson captured "$(python3 -c 'import time; print(time.time())')" --argjson fd "${extra%% *}" --argjson ct "${extra##* }" --argjson o "${origin:-null}" \
		--argjson r "$(bench_egress_restarts "$BENCH_POD")" \
		'. + {fd:$fd,conntrack:$ct,restarts:$r,origin_cpu_usec:$o,identity:$identity,captured_at_s:$captured}' <<< "$counters")"
	printf '%s' "$reading" | python3 "$SUP_SELF_DIR/supplemental-tools.py" sample-check "${SUP_RESOURCE_LAST:-$SUP_RAW/resource-last.json}" "$SUP_DIR/invalid-resource.json"
}

sup_sample_loop() { # measurement start_ns stop-file interval
	local key="$1" start="$2" stop="$3" interval="$4" reading elapsed
	python3 - "$start" <<'WAIT'
import sys,time
time.sleep(max(0,int(sys.argv[1])/1e9-time.time()))
WAIT
	while [[ ! -e "$stop" ]]; do
		reading="$(sup_sample)" || { kill -TERM "$SUP_OWNER_PID"; return 1; }
		elapsed="$(bench_elapsed_ms "$start")"
		jq -c --argjson t "$elapsed" --argjson offset "${SUP_TIME_OFFSET:-0}" '. + {t_s:($t/1000+$offset)}' <<< "$reading" >> "$SUP_RAW/$key-samples.jsonl"
		sleep "$interval"
	done
}

sup_scan() {
	cb_log_scan "$CB_WORK_DIR/values" "$SUP_SINCE"
}

sup_pool() { # mode cpu-limit; each block gets a new Pool and live env readback
	local mode="$1" cpu="$2" id
	for id in ${CB_SANDBOXES[@]+"${CB_SANDBOXES[@]}"}; do cb_kill_sandbox "$id"; done
	sup_scan
	EGRESS_INTERCEPTION_MODE="$mode"; BENCH_LEG="$mode"
	bench_render_pool
	awk -v cpu="$cpu" '
		/^      - name: / { e=($0=="      - name: egress"); l=0 }
		e && /^          limits:$/ { l=1 }
		e && /^          requests:$/ { l=0 }
		e && l && /^            cpu:/ { print "            cpu: " cpu; next }
		{ print }
	' "$GEN_DIR/$POOL_PROFILE.bench.yaml" > "$GEN_DIR/supplemental-pool.yaml"
	# shellcheck disable=SC2034 # read by bench_pool_restore
	BENCH_POOL_RENDERED=1
	bench_pool_apply "$GEN_DIR/supplemental-pool.yaml" "$BENCH_EGRESS_MEMORY_LIMIT" "$BENCH_FSB_TLS_CAPACITY"
	kubectl -n "$RESOURCE_NS" get pods -l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" -o json \
		| jq -e --arg m "$mode" --arg cpu "$cpu" 'all(.items[]; (.spec.containers[] | select(.name=="egress")) as $e |
			([$e.env[]? | select(.name=="OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE") | .value] == [$m]) and $e.resources.limits.cpu==$cpu)' >/dev/null \
		|| fail "supplemental: live mode/CPU mismatch"
	wait_for "supplemental: template cached on every warm Fastlet" 300 sup_warm_ready
	sleep "$SUP_IDLE_S"
}

sup_warm_ready() {
	kubectl -n "$RESOURCE_NS" get sandboxpool "$POOL_NAME" -o json | jq -e --argjson n "$POOL_MIN" \
		'(.status.warmImages | length)>0 and all(.status.warmImages[]; .cachedFastlets >= $n)' >/dev/null
}

sup_pair() {
	bench_pair "$SUP_CRED" "$SUP_CODE"
	SUP_SAMPLE_ID="$(bench_egress_identity "$BENCH_POD")"
	rm -f "$SUP_RAW/resource-last.json"
	local id
	for id in "$BENCH_U" "$BENCH_B"; do
		osb_api file upload "$id" "$SUP_SELF_DIR/supplemental-client.py" "$CB_GUEST_DIR/supplemental.py" >/dev/null
	done
}

sup_start() { # id name path concurrency connection duration body [extra args]
	local id="$1" name="$2" path="$3" c="$4" connection="$5" duration="$6" body="$7" leaf=mitm code="$SUP_CODE" out
	shift 7
	if [[ "$path" == unbound ]]; then
		code=absent
		[[ "$BENCH_LEG" != credential-bound ]] || leaf=origin
	fi
	out="$(osb_api command run "$id" --background -o json -- python3 "$CB_GUEST_DIR/supplemental.py" \
		"$@" --host "$MITM_ECHO_DOMAIN" --ip "$CB_ORIGIN_IP" --port "$MITM_ECHO_PORT" --cafile "$CB_GUEST_CAFILE" \
		--origin-leaf "$CB_ORIGIN_LEAF" --expect-leaf "$leaf" --expect-cred "$code" \
		--unbound-host "unbound.$MITM_ECHO_DOMAIN" --unbound-leaf "$([[ "$BENCH_LEG" == credential-bound ]] && echo origin || echo mitm)" \
		--out "$CB_GUEST_DIR/$name.json" --concurrency "$c" --connection "$connection" --duration "$duration" --body-bytes "$body" 2>>"$LOGS_DIR/supplemental-guest.err")" \
		|| fail "supplemental: client launch failed"
	[[ -n "$(jq -r '.execution_id // empty' <<< "$out")" ]] || fail "supplemental: no execution id"
}

sup_fetch() { # id name -> file
	bench_wait "$SUP_CLIENT_ATTEMPTS" bench_guest_fetch "$1" "$CB_GUEST_DIR/$2.json" "$SUP_RAW/$2.json" \
		|| fail "supplemental: no client result for $2"
}

sup_append_run() { # key raw-file path concurrency connection body repeat cpu
	bench_json_set "$SUP_RAW/$1-spec.json" '.runs += [$raw[0] + {path:$path,mode:$mode,concurrency:$c,connection:$conn,body_bytes:$body,repeat:$rep,cpu_limit:$cpu,group:$group,total_concurrency:$total}]' \
		--slurpfile raw "$2" --arg path "$3" --arg mode "$BENCH_LEG" --argjson c "$4" --arg conn "$5" \
		--argjson body "$6" --argjson rep "$7" --arg cpu "$8" --argjson group "$SUP_SEQ" --argjson total "$SUP_TOTAL_CONCURRENCY"
}

sup_lifetime_readback() {
	local readback
	readback="$(osb_api sandbox get "$1" -o json | python3 "$SUP_SELF_DIR/supplemental-tools.py" lifetime-readback "$SUP_REQUIRED_TTL_S")" || fail "supplemental: API lifetime readback failed"
	printf '%s\n' "$readback" >> "$SUP_DIR/lifetime-readback.jsonl"
}

sup_gate() {
	python3 "$SUP_SELF_DIR/supplemental-tools.py" gate "$SUP_GATE_URL" "$1" "$2" "${3:-host}"
}

sup_gate_ready() {
	[[ "$(sup_gate status "$1" | jq -r .ready)" == "$2" ]]
}

sup_load_pair() { # measurement concurrency connection seconds body repeat cpu mix
	local key="$1" c="$2" conn="$3" seconds="$4" body="$5" rep="$6" cpu="$7" mix="$8" \
		i n name phase duration rate gate expected e_pid o_pid identity egress origin window time_pid time_start stop
	local -a ids=("$BENCH_B") names=() counts=()
	if [[ "$key" == m5 ]]; then ids=("${SUP_LOAD_IDS[@]}"); fi
	SUP_TOTAL_CONCURRENCY="$c"
	for phase in warm measured; do
		duration="$seconds"; [[ "$phase" != warm ]] || duration="$SUP_WARMUP_S"
		gate="$key-$phase-$SUP_SEQ"; names=(); counts=()
		for i in "${!ids[@]}"; do
			n=$((c/${#ids[@]}+(i<c%${#ids[@]}?1:0))); ((n>0)) || continue
			name="$key-$phase-$SUP_SEQ-$i"; names+=("$name"); counts+=("$n")
			rate="$SUP_RATE_B"
			sup_start "${ids[$i]}" "$name" bound "$n" "$conn" "$duration" "$body" load --bound-percent "$mix" --churn-every "$SUP_CHURN_EVERY" --rate "$rate" \
				--gate-url "$SUP_GATE_URL" --gate-key "$gate" --participant "guest-$i"
		done
		expected="${#names[@]}"
		if [[ "$phase" == measured ]]; then
			identity="$(bench_egress_identity "$BENCH_POD")"
			if [[ -n "$identity" && "$identity" != "$SUP_SAMPLE_ID" ]]; then
				printf '{"status":"INVALID","reason":"egress container identity changed before window"}\n' > "$SUP_DIR/invalid-resource.json"; fail "egress identity changed"
			fi
			kubectl -n "$RESOURCE_NS" exec -i "$BENCH_POD" -c egress -- python3 - \
				--gate-url "$SUP_GATE_URL" --gate-key "$gate" --participant egress --duration "$duration" \
				< "$SUP_SELF_DIR/supplemental-sampler.py" > "$SUP_RAW/$gate-egress.json" & e_pid=$!
			docker exec -i "$CB_ORIGIN_CONTAINER" python3 - \
				--gate-url "$SUP_GATE_URL" --gate-key "$gate" --participant origin --duration "$duration" \
				< "$SUP_SELF_DIR/supplemental-sampler.py" > "$SUP_RAW/$gate-origin.json" & o_pid=$!
			SUP_WINDOW_PIDS="$e_pid $o_pid"; expected=$((expected+2))
		fi
		bench_wait "$SUP_CLIENT_ATTEMPTS" sup_gate_ready "$gate" "$expected" || fail "supplemental: common gate readiness missing"
		sup_gate release "$gate" > "$SUP_RAW/$gate-release.json"
		if [[ "$phase" == measured && -n "${SUP_TIME_KEY:-}" ]]; then
			time_start="$(jq -r '.start_at_s*1000000000 | floor' "$SUP_RAW/$gate-release.json")"; stop="$SUP_RAW/$gate-stop"
			: > "$SUP_RAW/$key-samples.jsonl"; rm -f "$stop" "$SUP_RAW/$key-loop-last.json"
			(SUP_RESOURCE_LAST="$SUP_RAW/$key-loop-last.json"; sup_sample_loop "$key" "$time_start" "$stop" "$SUP_TIME_INTERVAL") & time_pid=$!; SUP_SAMPLER="$time_pid"
		fi
		if [[ "$phase" == measured ]]; then
			wait "$e_pid" || fail "egress steady sampler failed"; wait "$o_pid" || fail "origin steady sampler failed"; SUP_WINDOW_PIDS=""
			if [[ -n "${SUP_TIME_KEY:-}" ]]; then
				touch "$stop"; wait "$time_pid" || fail "time series sampler failed"; SUP_SAMPLER=""
			fi
			egress=initial; [[ "$identity" == "$(bench_egress_identity "$BENCH_POD")" ]] || egress=changed
			origin="$(cat "$SUP_RAW/$gate-origin.json")"
			window="$(jq --arg identity "$egress" --argjson r "$(bench_egress_restarts "$BENCH_POD")" --argjson origin "$origin" \
				--argjson c "$c" --argjson mix "$mix" --argjson group "$SUP_SEQ" \
				'{egress_start:(.start+{identity:"initial",restarts:$r}),egress_end:(.end+{identity:$identity,restarts:$r}),
				origin_cpu_s:(($origin.end.usage_usec-$origin.start.usage_usec)/1000000),
				wall_s:(.end.captured_at_s-.start.captured_at_s),scheduled_start_s:.scheduled_start_s,
				origin_start_s:$origin.start.captured_at_s,origin_end_s:$origin.end.captured_at_s,concurrency:$c,bound_percent:$mix,group:$group}' "$SUP_RAW/$gate-egress.json")"
			# Check lifecycle/counters before downloading any guest results.
			jq -c .egress_start <<< "$window" | python3 "$SUP_SELF_DIR/supplemental-tools.py" sample-check "$SUP_RAW/resource-last.json" "$SUP_DIR/invalid-resource.json" >/dev/null
			jq -c .egress_end <<< "$window" | python3 "$SUP_SELF_DIR/supplemental-tools.py" sample-check "$SUP_RAW/resource-last.json" "$SUP_DIR/invalid-resource.json" >/dev/null
			bench_json_set "$SUP_RAW/$key-spec.json" '.resource_windows=((.resource_windows // [])+[$w])' --argjson w "$window"
		fi
		if [[ "$phase" == measured && -n "${SUP_TIME_KEY:-}" ]]; then
			bench_json_set "$SUP_RAW/$key-spec.json" '.samples+=[$s[] | select(.t_s<=$end)]' --argjson end "$((SUP_TIME_OFFSET+duration))" --slurpfile s "$SUP_RAW/$key-samples.jsonl"
			bench_json_set "$SUP_RAW/$key-spec.json" '.samples+=[$w.egress_end+{origin_cpu_usec:$o.end.usage_usec,t_s:$t}]' \
				--argjson w "$window" --argjson o "$origin" --argjson t "$((SUP_TIME_OFFSET+duration))"
			SUP_TIME_OFFSET=$((SUP_TIME_OFFSET+duration))
		fi
		# Result polling, JSON assembly and downloads are outside the window.
		for i in "${!names[@]}"; do
			sup_fetch "${ids[$i]}" "${names[$i]}"
			if [[ "$phase" == measured ]]; then sup_append_run "$key" "$SUP_RAW/${names[$i]}.json" mixed "${counts[$i]}" "$conn" "$body" "$rep" "$cpu"; fi
		done
	done
	SUP_SEQ=$((SUP_SEQ+1))
}

sup_m3x_path() { # bound or unbound on the current mode
	local target="$1" k inc per rem i n id dir raw got alive tcode leaf=mitm contrad=0 identity reading baseline_oom \
		held_total=0 points='[]'
	local -a ids=() codes=() dirs=()
	[[ "$BENCH_LEG" != credential-bound || "$target" != unbound ]] || leaf=origin
	for i in $(seq 1 "$BENCH_MEM_SANDBOXES"); do
		if [[ "$i" == 1 ]]; then
			cb_create_sandbox m3x "$BENCH_POLICY"; id="$CB_LAST_ID"
			cb_placement "$id" || fail "M3x placement missing"
			BENCH_POD="$CB_POD_NAME"; BENCH_POD_UID="$CB_POD_UID"
		else cb_create_colocated m3x "$BENCH_POLICY" "$BENCH_POD_UID"; id="$CB_LAST_ID"; fi
		tcode=absent
		if [[ "$target" == bound ]]; then
			bench_bind "$id" "$SUP_CRED" m3x-bind; tcode="$SUP_CODE"
			cb_until "M3x injection ready" 60 "$id" m3x-ready "$tcode"
		else bench_until_reachable "$id" m3x-ready "$leaf"; fi
		ids+=("$id"); codes+=("$tcode")
	done
	identity="$(bench_egress_identity "$BENCH_POD")"
	sleep "$BENCH_MEM_SETTLE_SECONDS"
	reading="$(bench_egress_cgroup "$BENCH_POD")"
	baseline_oom="$(jq -r .oom_kill <<< "$reading")"
	points="$(jq -n --argjson r "$reading" '[{k:0,held:0,alive:0,anon:$r.anon,memory_current:$r.memory_current,same_process:true}]')"
	for k in $BENCH_MEM_STEPS; do
		inc=$((k-held_total)); per=$((inc/BENCH_MEM_SANDBOXES)); rem=$((inc%BENCH_MEM_SANDBOXES))
		got=0
		for i in "${!ids[@]}"; do
			n=$((per+(i<rem?1:0))); (( n > 0 )) || continue
			dir="$CB_GUEST_DIR/m3x-$target-$k"
			bench_guest_start "${ids[$i]}" hold-many --tag m3x --conns "$n" --dir "$dir" --wait-timeout 7200 || fail "M3x holder launch"
			dirs+=("${ids[$i]}|$dir")
		done
		for i in "${!ids[@]}"; do
			n=$((per+(i<rem?1:0))); (( n > 0 )) || continue
			raw="$SUP_RAW/m3x-$target-$k-$i.json"
			bench_wait "$SUP_CLIENT_ATTEMPTS" bench_guest_fetch "${ids[$i]}" "$CB_GUEST_DIR/m3x-$target-$k/status.json" "$raw" || fail "M3x holder result missing"
			got=$((got+$(jq -r .held "$raw")))
			# classify with the existing closed evidence vocabulary, privately.
			contrad=$((contrad+$(python3 "$SUP_SELF_DIR/supplemental-tools.py" classify "$raw" "$CB_ORIGIN_LEAF" "$leaf" "${codes[$i]}")))
		done
		held_total=$((held_total+got)); sleep "$BENCH_MEM_SETTLE_SECONDS"
		reading="$(bench_egress_cgroup "$BENCH_POD")"
		points="$(jq --argjson k "$k" --argjson h "$held_total" --argjson r "$reading" \
			--argjson same "$([[ "$(bench_egress_identity "$BENCH_POD")" == "$identity" && "$(jq -r .oom_kill <<< "$reading")" == "$baseline_oom" ]] && echo true || echo false)" \
			'. + [{k:$k,held:$h,alive:null,anon:$r.anon,memory_current:$r.memory_current,same_process:$same}]' <<< "$points")"
		(( held_total == k )) || break
	done
	alive=0
	for dir in "${dirs[@]}"; do
		IFS='|' read -r id dir <<< "$dir"
		osb_api command run "$id" -- touch "$dir/go" >/dev/null
	done
	for dir in "${dirs[@]}"; do
		IFS='|' read -r id dir <<< "$dir"
		bench_wait "$SUP_CLIENT_ATTEMPTS" bench_guest_fetch "$id" "$dir/done.json" "$SUP_RAW/m3x-done.json" || fail "M3x release result missing"
		alive=$((alive+$(jq -r .alive_at_release "$SUP_RAW/m3x-done.json")))
	done
	# Full final release proves every preceding cumulative point alive. If it
	# fails, no earlier point receives an invented alive count.
	points="$(jq --argjson a "$alive" --argjson h "$held_total" 'map(if .k==0 then . else .alive=(if $a==$h then .held else null end) end)' <<< "$points")"
	bench_json_set "$SUP_RAW/m3x-spec.json" '.paths += [{mode:$mode,target:$target,points:$points,contradictions:$bad}]' \
		--arg mode "$BENCH_LEG" --arg target "$target" --argjson points "$points" --argjson bad "$contrad"
	for id in "${ids[@]}"; do cb_kill_sandbox "$id"; done
}

sup_m3x() {
	sup_spec m3x
	local mode target
	for mode in all credential-bound; do
		sup_pool "$mode" 500m
		for target in unbound bound; do sup_m3x_path "$target"; done
	done
	sup_report m3x
}

sup_load_guests() {
	SUP_LOAD_IDS=("$BENCH_B")
	local i id
	for i in $(seq 2 "$SUP_LOAD_GUESTS"); do
		cb_create_colocated "load-$i" "$BENCH_POLICY" "$BENCH_POD_UID"; id="$CB_LAST_ID"
		bench_bind "$id" "$SUP_CRED" load-bind
		cb_until "supplemental load guest injected" 60 "$id" load-ready "$SUP_CODE"
		osb_api file upload "$id" "$SUP_SELF_DIR/supplemental-client.py" "$CB_GUEST_DIR/supplemental.py" >/dev/null
		SUP_LOAD_IDS+=("$id")
	done
}

sup_m5() {
	sup_spec m5
	local mode cpu c conn body rep mix
	for mode in all credential-bound; do
		for cpu in $SUP_CPU_LIMITS; do
			sup_pool "$mode" "$cpu"; sup_pair; sup_load_guests
			for c in $SUP_CONCURRENCIES; do
				for conn in new keep-alive; do
					for mix in 5 100; do
						for body in $SUP_BODY_BYTES; do
							[[ "$mix" != 100 || "$body" == 0 ]] || continue
							for rep in $(seq 1 "$SUP_REPEATS"); do sup_load_pair m5 "$c" "$conn" "$SUP_LOAD_S" "$body" "$rep" "$cpu" "$mix"; done
						done
					done
				done
			done
		done
	done
	bench_json_set "$SUP_RAW/m5-spec.json" '.settings.traffic_mix_method="per-request 100-request cycle in each guest: 95 unbound / 5 bound or 100 bound; actual counts retained"'
	sup_report m5
}

sup_time() { # m6 or m8 on both modes
	local key="$1" seconds="$SUP_CHURN_S" analysis=0 mode
	SUP_TIME_INTERVAL=5
	[[ "$key" != m8 ]] || { seconds="$SUP_SOAK_S"; SUP_TIME_INTERVAL=10; analysis="$SUP_SOAK_ANALYSIS_S"; }
	for mode in all credential-bound; do
		sup_spec "$key"
		bench_json_set "$SUP_RAW/$key-spec.json" '.duration_s=$d | .analysis_start_s=$a | .settings.mode=$mode' --argjson d "$seconds" --argjson a "$analysis" --arg mode "$mode"
		sup_pool "$mode" 500m; sup_pair
		SUP_TIME_KEY="$key"; SUP_TIME_OFFSET=0
		if [[ "$key" == m6 ]]; then
			SUP_CHURN_EVERY=1
			local stage stage_s=$((seconds/3))
			((stage_s>0)) || stage_s=1
			for stage in 1 4 16; do sup_load_pair "$key" "$stage" new "$stage_s" 0 1 500m 100; done
		else
			SUP_CHURN_EVERY=100
			SUP_RATE_B="$SUP_SOAK_RATE_ALL"; [[ "$mode" != credential-bound ]] || SUP_RATE_B="$SUP_SOAK_RATE_CB"
			bench_json_set "$SUP_RAW/$key-spec.json" '.settings.rate_rps=$rate' --argjson rate "$SUP_RATE_B"
			sup_load_pair "$key" "$SUP_SOAK_CONCURRENCY" keep-alive "$seconds" 0 1 500m 5
		fi
		SUP_TIME_KEY=""
		sleep "$SUP_RECOVERY_S"
		bench_json_set "$SUP_RAW/$key-spec.json" '.recovery=$s' --argjson s "$(sup_sample)"
		sup_report "$key"
		mv "$SUP_DIR/$key.json" "$SUP_DIR/$key-$mode.json"
		cp "$SUP_RAW/$key-spec.json" "$SUP_RAW/$key-$mode-spec.json"
	done
	SUP_CHURN_EVERY=0
}

sup_m7_resources_ready() {
	python3 - "$SUP_RAW/m7-tier.json" <<'CHECK'
import json,sys
p=json.load(open(sys.argv[1])); samples=p['resource_samples']; baseline=samples[0]; last=samples[-1]
raise SystemExit(0 if all(last.get(k) is not None and last[k]-baseline[k]<=v for k,v in p['resource_tolerances'].items()) else 1)
CHECK
}

sup_m7() {
	local mode burst name since denials t0 leaf p_ok bad probe_json rep per process available expected tier_start reading released_start recovered
	SUP_TOTAL_CONCURRENCY=0
	for mode in all credential-bound; do
		sup_spec m7; sup_pool "$mode" 500m; sup_pair
		for burst in $SUP_BURSTS; do
			for rep in $(seq 1 "$SUP_BURST_REPEATS"); do
				name="m7-$mode-$burst-$rep"; since="$(date -u +%FT%TZ)"; tier_start="$(bench_ns)"
				per="$(kubectl -n "$RESOURCE_NS" get pod "$BENCH_POD" -o json | jq -r '.spec.containers[] | select(.name=="egress") | [.env[]? | select(.name=="OPENSANDBOX_EGRESS_FSB_TLS_CAPACITY") | .value][0] // "1024"')"
				process="$(kubectl -n "$RESOURCE_NS" get pod "$BENCH_POD" -o json | jq -r '.spec.containers[] | select(.name=="egress") | [.env[]? | select(.name=="OPENSANDBOX_EGRESS_FSB_PROCESS_TLS_CAPACITY") | .value][0] // "32768"')"
				available="$burst"
				if [[ "$mode" == credential-bound ]]; then available="$per"; (( process>=available )) || available="$process"; fi
				expected="$burst"; (( expected<=available )) || expected="$available"
				reading="$(sup_sample)"
				jq -n --argjson g "$SUP_SEQ" --argjson per "$per" --argjson process "$process" --argjson avail "$available" \
					--argjson admission "$([[ "$mode" == credential-bound ]] && echo true || echo false)" --argjson expected "$expected" --argjson rejected "$((burst-expected))" \
					--argjson s "$reading" --argjson timeout "$SUP_RESOURCE_RECOVERY_S" \
					'{group:$g,budget:{admission_enabled:$admission,per_subject:$per,process:$process,available:$avail,source:"live Pod env; absent process env uses product default 32768; idle pair"},
					expected_success:[$expected,$expected],expected_rejections:[$rejected,$rejected],resource_samples:[$s+{phase:"baseline",t_s:0}],
					resource_timeout_s:$timeout,resource_tolerances:{memory_current:33554432,anon:16777216,fd:4,conntrack:64}}' > "$SUP_RAW/m7-tier.json"
				sup_start "$BENCH_B" "$name" bound "$burst" keep-alive 1 0 burst \
					--ready-file "$CB_GUEST_DIR/$name-ready.json" --release-file "$CB_GUEST_DIR/$name-go" --hold-s 120
				bench_wait "$SUP_CLIENT_ATTEMPTS" bench_guest_fetch "$BENCH_B" "$CB_GUEST_DIR/$name-ready.json" "$SUP_RAW/$name-ready.json" || fail "M7 burst readiness missing"
				reading="$(sup_sample)"
				bench_json_set "$SUP_RAW/m7-tier.json" '.resource_samples+=[$s+{phase:"held",t_s:($t/1000)}]' --argjson s "$reading" --argjson t "$(bench_elapsed_ms "$tier_start")"
				cb_guest_once "$BENCH_U" m7-passthrough
				leaf=mitm; [[ "$mode" != credential-bound ]] || leaf=origin
				probe_json="$CB_RESULT"; [[ -n "$probe_json" ]] || probe_json='{}'
				bad="$(jq --arg origin "$CB_ORIGIN_LEAF" --arg leaf "$leaf" 'if (.last.origin.cred != null and .last.origin.cred != "absent") or (.leaf_sha256 != null and ((.leaf_sha256==$origin) != ($leaf=="origin"))) then 1 else 0 end' <<< "$probe_json")"
				p_ok=false; if [[ "$CB_RC" == 0 && "$bad" == 0 ]]; then p_ok=true; fi
				bench_json_set "$SUP_RAW/m7-tier.json" '.passthrough_ok=$ok | .passthrough_contradictions=$bad' --argjson ok "$p_ok" --argjson bad "$bad"
				sup_start "$BENCH_B" "$name-same-unbound" bound 1 new 1 0 load --bound-percent 0
				sup_fetch "$BENCH_B" "$name-same-unbound"
				p_ok="$(python3 - "$SUP_SELF_DIR" "$SUP_RAW/$name-same-unbound.json" <<'PROBE'
import importlib.util,json,sys
from pathlib import Path
sp=importlib.util.spec_from_file_location('report',Path(sys.argv[1])/'supplemental-report.py');r=importlib.util.module_from_spec(sp);sp.loader.exec_module(r)
print('true' if r.run_status(json.load(open(sys.argv[2])))=='OK' else 'false')
PROBE
)"
				bench_json_set "$SUP_RAW/m7-tier.json" '.same_subject_passthrough_ok=$ok' --argjson ok "$p_ok"
				bench_json_set "$SUP_RAW/m7-spec.json" '.same_subject_passthrough_runs=((.same_subject_passthrough_runs // [])+$r)' --slurpfile r "$SUP_RAW/$name-same-unbound.json"
				reading="$(sup_sample)"
				bench_json_set "$SUP_RAW/m7-tier.json" '.resource_samples+=[$s+{phase:"held",t_s:($t/1000)}]' --argjson s "$reading" --argjson t "$(bench_elapsed_ms "$tier_start")"
				osb_api command run "$BENCH_B" -- touch "$CB_GUEST_DIR/$name-go" >/dev/null
				released_start="$(bench_ns)"; sup_fetch "$BENCH_B" "$name"
				SUP_TOTAL_CONCURRENCY="$burst"; sup_append_run m7 "$SUP_RAW/$name.json" bound "$burst" keep-alive 0 "$rep" 500m
				denials="$(kubectl -n "$RESOURCE_NS" logs "$BENCH_POD" -c egress --since-time="$since" | python3 "$SUP_SELF_DIR/supplemental-tools.py" budget-denials)"
				t0="$(bench_ns)"; cb_until "M7 recovered bound injection" 60 "$BENCH_B" m7-recovered "$SUP_CODE"
				bench_json_set "$SUP_RAW/m7-tier.json" '.recovered=true | .injection_recovery_ms=$t | .server_budget_denials=$n' --argjson t "$(bench_elapsed_ms "$t0")" --argjson n "$denials"
				recovered=false
				while true; do
					reading="$(sup_sample)"
					bench_json_set "$SUP_RAW/m7-tier.json" '.resource_samples+=[$s+{phase:"released",t_s:($t/1000),release_elapsed_s:($r/1000)}]' \
						--argjson s "$reading" --argjson t "$(bench_elapsed_ms "$tier_start")" --argjson r "$(bench_elapsed_ms "$released_start")"
					if sup_m7_resources_ready; then recovered=true; break; fi
					(( $(bench_elapsed_ms "$released_start") < SUP_RESOURCE_RECOVERY_S*1000 )) || break
					sleep "$SUP_RESOURCE_INTERVAL_S"
				done
				bench_json_set "$SUP_RAW/m7-spec.json" '.tiers=((.tiers // [])+$t)' --slurpfile t "$SUP_RAW/m7-tier.json"
				SUP_SEQ=$((SUP_SEQ+1)); sup_report m7
				# Observe the full bounded recovery sequence before replacing a Pool.
				if [[ "$recovered" != true ]]; then sup_pool "$mode" 500m; sup_pair; fi
			done
		done
		sup_report m7; mv "$SUP_DIR/m7.json" "$SUP_DIR/m7-$mode.json"
		cp "$SUP_RAW/m7-spec.json" "$SUP_RAW/m7-$mode-spec.json"
	done
}

sup_forward_ready() {
	grep -q 'Forwarding from 127.0.0.1:' "$SUP_RAW/m9-port-forward.log"
}

sup_scale_is() {
	[[ "$(cat "$1/scale" 2>/dev/null)" == "$2" ]]
}

sup_m9() {
	sup_spec m9
	sup_pool credential-bound 500m; sup_pair
	local control="$SUP_RAW/m9-control" out="$SUP_RAW/m9-driver.json" step pid port reading after nft t0 nft_cpu=0
	mkdir "$control"; : > "$SUP_RAW/m9-resources.jsonl"
	# The runner and port-forward have their own task cgroup, outside egress.
	kubectl -n "$RESOURCE_NS" port-forward --address 127.0.0.1 "$BENCH_POD" 0:18080 > "$SUP_RAW/m9-port-forward.log" 2>&1 & SUP_FORWARD_PID=$!
	bench_wait 30 sup_forward_ready || fail "M9 controlled action channel unavailable"
	port="$(sed -n 's/.*Forwarding from 127.0.0.1:\([0-9]*\) ->.*/\1/p' "$SUP_RAW/m9-port-forward.log" | head -1)"
	# shellcheck disable=SC2086 # validated integer steps
	python3 "$SUP_SELF_DIR/supplemental-subjects.py" --url "http://127.0.0.1:$port/_fastlet/v1/actions" \
		--steps $SUP_SUBJECT_STEPS --out "$out" --control-dir "$control" > "$LOGS_DIR/supplemental-subjects.log" 2>&1 & pid=$!
	SUP_SUBJECT_PID="$pid"
	printf 'driver_pid=%s\n' "$pid" > "$SUP_RAW/m9-cgroup-isolation.txt"
	cat "/proc/$pid/cgroup" >> "$SUP_RAW/m9-cgroup-isolation.txt"
	kubectl -n "$RESOURCE_NS" exec "$BENCH_POD" -c egress -- cat /proc/1/cgroup >> "$SUP_RAW/m9-cgroup-isolation.txt"
	for step in $SUP_SUBJECT_STEPS; do
		bench_wait "$SUP_CLIENT_ATTEMPTS" sup_scale_is "$control" "$step" || fail "M9 scale controller missing"
		reading="$(sup_sample)"
		# Product memory/CPU snapshot precedes nft enumeration. Keep enumeration
		# CPU and wall costs separate so cumulative CPU can be recomputed.
		t0="$(bench_ns)"
		nft="$(kubectl -n "$RESOURCE_NS" exec "$BENCH_POD" -c egress -- nft -j list ruleset | jq '[.nftables[] | select(has("rule"))] | length')"
		after="$(sup_sample)"
		jq -n --argjson target "$step" --argjson s "$reading" --argjson e "$after" --argjson n "$nft" \
			--argjson prior "$nft_cpu" --argjson wall "$(bench_elapsed_ms "$t0")" \
			'{target:$target,resource_sample:$s,memory_current:$s.memory_current,anon:$s.anon,usage_usec:$s.usage_usec,
			usage_excluding_prior_enumeration_usec:($s.usage_usec-$prior),nft_rules:$n,
			nft_enumeration:{wall_ms:$wall,cpu_before_usec:$s.usage_usec,cpu_after_usec:$e.usage_usec,memory_current_before:$s.memory_current,memory_current_after:$e.memory_current,anon_before:$s.anon,anon_after:$e.anon,cpu_delta_usec:($e.usage_usec-$s.usage_usec)}}' >> "$SUP_RAW/m9-resources.jsonl"
		nft_cpu=$((nft_cpu+$(jq -n --argjson a "$reading" --argjson b "$after" '$b.usage_usec-$a.usage_usec')))
		bench_handshakes "$BENCH_U" "m9-u-$step" "$SUP_SCALE_PROBES" "$SUP_RAW/m9-u-$step.json"
		bench_handshakes "$BENCH_B" "m9-b-$step" "$SUP_SCALE_PROBES" "$SUP_RAW/m9-b-$step.json"
		touch "$control/continue-$step"
	done
	wait "$pid" || fail "M9 synthetic driver failed"; SUP_SUBJECT_PID=""
	kill "$SUP_FORWARD_PID"; wait "$SUP_FORWARD_PID" 2>/dev/null || true; SUP_FORWARD_PID=""
	bench_json_set "$SUP_RAW/m9-spec.json" '.points=[$d[0].points[] as $p | $p+($r[] | select(.target==$p.target))] | .cleanup_ok=$d[0].cleanup_ok | .recovery_ok=$d[0].recovery_ok | .resource_scope="egress_only_external_driver"' \
		--slurpfile d "$out" --slurpfile r "$SUP_RAW/m9-resources.jsonl"
	local denials
	denials="$(kubectl -n "$RESOURCE_NS" logs "$BENCH_POD" -c egress --since-time="$SUP_SINCE" | grep -c subject_capacity_exhausted || true)"
	bench_json_set "$SUP_RAW/m9-spec.json" '.points |= map(if .target>4096 then .capacity_rejections=$n else . end)' --argjson n "$denials"
	python3 "$SUP_SELF_DIR/supplemental-tools.py" m9-probes "$SUP_RAW/m9-spec.json" "$SUP_RAW" "$CB_ORIGIN_LEAF" "$SUP_CODE"
	sup_report m9
}

sup_m10() {
	sup_spec m10
	local block mode label t0 switch original_dir="$BENCH_DIR" original_raw="$BENCH_RAW" uid live since
	for block in $(seq 0 $((SUP_BLOCKS-1))); do
		label="${SUP_SEQUENCE:$block:1}"; mode=all; [[ "$label" != B ]] || mode=credential-bound
		t0="$(bench_ns)"; sup_pool "$mode" 500m; switch="$(bench_elapsed_ms "$t0")"
		since="$(date -u +%FT%TZ)"
		BENCH_DIR="$SUP_RAW/m10-block-$block"; BENCH_RAW="$BENCH_DIR/raw"; mkdir -p "$BENCH_RAW"
		bench_m1
		python3 "$SUP_SELF_DIR/supplemental-tools.py" create-inputs "$BENCH_RAW/m1-spec.json" "$BENCH_RAW/create-inputs.json"
		uid="$(kubectl -n "$RESOURCE_NS" get pods -l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" -o jsonpath='{.items[0].metadata.uid}')"
		live="$(kubectl -n "$RESOURCE_NS" get pods -l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" -o json | jq -r '.items[0].spec.containers[] | select(.name=="egress") | .env[] | select(.name=="OPENSANDBOX_EGRESS_FSB_INTERCEPTION_MODE") | .value')"
		kubectl -n "$RESOURCE_NS" logs -l "app=sandbox-fastlet,fast-sandbox.io/pool=$POOL_NAME" -c egress --since-time="$since" --tail=-1 > "$BENCH_RAW/egress.log"
		python3 "$SUP_SELF_DIR/supplemental-tools.py" segments "$BENCH_RAW/egress.log" "$BENCH_RAW/segments.json"
		bench_json_set "$SUP_RAW/m10-spec.json" '.blocks += [{mode:$block_mode,p50_ms:$r.pooled_latency_ms.p50,status:$r.status,switch_ms:$switch,pod_uid:$uid,live_mode:$mode,warm_ready:true,segments:$segments,create_latency_ms_inputs:$inputs[0]}]' \
			--arg block_mode "$label" --argjson r "$(cat "$BENCH_DIR/m1-create.json")" --argjson switch "$switch" --arg uid "$uid" --arg mode "$live" --argjson segments "$(cat "$BENCH_RAW/segments.json")" --slurpfile inputs "$BENCH_RAW/create-inputs.json"
		BENCH_DIR="$original_dir"; BENCH_RAW="$original_raw"
	done
	sup_report m10
}

sup_cleanup() {
	[[ -z "${SUP_FORWARD_PID:-}" ]] || { kill "$SUP_FORWARD_PID" 2>/dev/null || true; wait "$SUP_FORWARD_PID" 2>/dev/null || true; }
	local pid
	for pid in ${SUP_WINDOW_PIDS:-}; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
	unset CB_SANDBOX_TIMEOUT CB_CREATE_READBACK_HOOK
	[[ -z "${SUP_SAMPLER:-}" ]] || { kill "$SUP_SAMPLER" 2>/dev/null || true; wait "$SUP_SAMPLER" 2>/dev/null || true; }
	[[ -z "${SUP_SUBJECT_PID:-}" ]] || { kill "$SUP_SUBJECT_PID" 2>/dev/null || true; wait "$SUP_SUBJECT_PID" 2>/dev/null || true; }
	cb_cleanup
	EGRESS_INTERCEPTION_MODE="$SUP_ORIGINAL_MODE"; WARM_IMAGES="$SUP_ORIGINAL_WARM"
	bench_pool_restore
}

supplemental_bench() {
	SUP_OWNER_PID="$BASHPID"
	[[ "$-" != *x* ]] || fail "supplemental refuses xtrace"
	SUP_SMOKE="${SUP_SMOKE:-false}"
	SUP_MEASUREMENTS="${SUP_MEASUREMENTS:-m10 m3x m5 m6 m7 m9 m8}"
	SUP_CPU_LIMITS="${SUP_CPU_LIMITS:-500m 2}"
	SUP_CONCURRENCIES="${SUP_CONCURRENCIES:-1 16 64 256}"
	SUP_BODY_BYTES="${SUP_BODY_BYTES:-0 65536}"
	SUP_REPEATS="${SUP_REPEATS:-3}"
	SUP_LOAD_S="${SUP_LOAD_S:-60}"; SUP_WARMUP_S="${SUP_WARMUP_S:-10}"; SUP_IDLE_S="${SUP_IDLE_S:-20}"
	SUP_CHURN_S="${SUP_CHURN_S:-1800}"; SUP_SOAK_S="${SUP_SOAK_S:-7200}"; SUP_SOAK_ANALYSIS_S="${SUP_SOAK_ANALYSIS_S:-1800}"
	SUP_SOAK_CONCURRENCY="${SUP_SOAK_CONCURRENCY:-16}"; SUP_SOAK_RATE_ALL="${SUP_SOAK_RATE_ALL:-0}"; SUP_SOAK_RATE_CB="${SUP_SOAK_RATE_CB:-0}"; SUP_RECOVERY_S="${SUP_RECOVERY_S:-30}"
	SUP_BURST_REPEATS="${SUP_BURST_REPEATS:-3}"; SUP_RESOURCE_RECOVERY_S="${SUP_RESOURCE_RECOVERY_S:-240}"; SUP_RESOURCE_INTERVAL_S="${SUP_RESOURCE_INTERVAL_S:-5}"
	SUP_BURSTS="${SUP_BURSTS:-500 1000 2000 2049}"; SUP_SUBJECT_STEPS="${SUP_SUBJECT_STEPS:-256 1024 2048 4096 4097}"
	SUP_SCALE_PROBES="${SUP_SCALE_PROBES:-20}"; SUP_BLOCKS="${SUP_BLOCKS:-8}"; SUP_SEQUENCE=ABBAABBA
	SUP_CLIENT_ATTEMPTS="${SUP_CLIENT_ATTEMPTS:-7200}"
	SUP_LOAD_GUESTS="${SUP_LOAD_GUESTS:-4}"; SUP_LOAD_IDS=()
	SUP_CHURN_EVERY=0; SUP_RATE_U="${SUP_RATE_U:-0}"; SUP_RATE_B="${SUP_RATE_B:-0}"; SUP_SEQ=0
	export SUP_BURST_REPEATS SUP_RESOURCE_RECOVERY_S SUP_RESOURCE_INTERVAL_S
	export SUP_SMOKE SUP_MEASUREMENTS SUP_CPU_LIMITS SUP_CONCURRENCIES SUP_BODY_BYTES SUP_REPEATS SUP_LOAD_S SUP_WARMUP_S SUP_IDLE_S SUP_CHURN_S SUP_SOAK_S SUP_SOAK_ANALYSIS_S SUP_SOAK_CONCURRENCY SUP_RECOVERY_S SUP_BURSTS SUP_SUBJECT_STEPS SUP_SCALE_PROBES SUP_BLOCKS SUP_CLIENT_ATTEMPTS SUP_RATE_B SUP_LOAD_GUESTS SUP_SOAK_RATE_ALL SUP_SOAK_RATE_CB
	python3 "$SUP_SELF_DIR/supplemental-tools.py" validate || die "invalid supplemental parameters"
	bench_validate_knobs
	load_mitm_ca_fingerprint; bench_load_template_id
	CB_NET="$(kind_network)"; [[ -n "$CB_NET" ]] || die "kind network missing"
	SUP_DIR="${SUP_REPORT_DIR:-$WORK/bench/supplemental-$(date -u +%Y%m%dT%H%M%SZ)}"; SUP_RAW="$SUP_DIR/raw"
	[[ ! -e "$SUP_DIR" ]] || die "supplemental output exists; choose a fresh SUP_REPORT_DIR"
	mkdir -p "$SUP_RAW" "$GEN_DIR"
	# shellcheck disable=SC2034 # read by sourced bench helpers
	BENCH_DIR="$SUP_DIR"; BENCH_RAW="$SUP_RAW"; SUP_ORIGINAL_MODE="$EGRESS_INTERCEPTION_MODE"; SUP_ORIGINAL_WARM="$WARM_IMAGES"; WARM_IMAGES=1
	# shellcheck disable=SC2034 # array read by bench_bind
	BENCH_BIND_MS=()
	CB_WORK_DIR="$(mktemp -d "$GEN_DIR/supplemental.XXXXXX")"
	trap 'sup_cleanup' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	SUP_SINCE="$(date -u +%FT%TZ)"; SUP_CRED="$(cb_fake_value supplemental)"; SUP_CODE="$(cb_digest "$SUP_CRED")"
	(umask 077; printf '%s\n' "$SUP_CRED" > "$CB_WORK_DIR/values")
	# shellcheck disable=SC2034 # read by cb_origin_up
	CB_ORIGIN_SRC="$SUP_SELF_DIR/supplemental-origin.py"
	local original_ca="$MITM_CA_DIR"
	python3 "$SUP_SELF_DIR/supplemental-tools.py" certificate "$MITM_CA_DIR" "$CB_WORK_DIR/ca" "$MITM_ECHO_DOMAIN"
	MITM_CA_DIR="$CB_WORK_DIR/ca"; cb_origin_up; MITM_CA_DIR="$original_ca"
	SUP_GATE_URL="http://$CB_ORIGIN_IP:18081"
	# Fixture FD limit: no product limit is changed.
	docker exec "$CB_ORIGIN_CONTAINER" python3 -c 'from pathlib import Path; assert int([x for x in Path("/proc/1/limits").read_text().splitlines() if x.startswith("Max open files")][0].split()[3]) >= 65536' || fail "origin FD limit is below 65536"
	BENCH_POLICY="$CB_WORK_DIR/policy.json"
	jq -n --arg ip "$CB_ORIGIN_IP" --arg domain "$MITM_ECHO_DOMAIN" '{defaultAction:"deny",egress:[{action:"allow",target:$ip},{action:"allow",target:$domain},{action:"allow",target:("unbound."+$domain)}]}' > "$BENCH_POLICY"
	local measurement measurement_start report
	for measurement in $SUP_MEASUREMENTS; do
		SUP_REQUIRED_TTL_S="$(python3 "$SUP_SELF_DIR/supplemental-tools.py" lifetime "$measurement")"
		# shellcheck disable=SC2034 # optional creation controls read by verify/credential-bound.sh
		CB_SANDBOX_TIMEOUT="$((SUP_REQUIRED_TTL_S+600))s"
		# shellcheck disable=SC2034 # called by shared creation helper
		CB_CREATE_READBACK_HOOK=sup_lifetime_readback
		measurement_start="$(bench_ns)"
		case "$measurement" in m3x) sup_m3x;; m5) sup_m5;; m6|m8) sup_time "$measurement";; m7) sup_m7;; m9) sup_m9;; m10) sup_m10;; esac
		for report in "$SUP_DIR/$measurement"*.json; do
			[[ -f "$report" ]] || continue
			bench_json_set "$report" '.execution_wall_ms=$ms | .execution_scope="measurement including all modes and rebuilds"' --argjson ms "$(bench_elapsed_ms "$measurement_start")"
		done
		sup_scan
		# INVALID is a stop gate even when a report was written by a subshell.
		if jq -e 'select(.status=="INVALID")' "$SUP_DIR/"*.json >/dev/null; then fail "INVALID supplemental report"; fi
	done
	sup_cleanup; trap - EXIT INT TERM
}
