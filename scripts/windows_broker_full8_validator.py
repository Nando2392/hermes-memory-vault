"""Pure, closed Schema8/Cadence3 consumer; no lifecycle or execution authority.

Structural controls may be ordinary SQLite/shared-loop reports. Hosted success
additionally requires exact native installed-command and stopped-oracle evidence.
Legacy Schema5 remains a separate workflow function, never a normalization target.
"""

from __future__ import annotations
import json
import hashlib
from typing import Any

REPORT_LIMIT = 16 * 1024 * 1024
IO = "read_operations write_operations other_operations read_bytes write_bytes other_bytes".split()
MEM = "private_bytes working_set_bytes lifetime_peak_private_bytes lifetime_peak_working_set_bytes".split()
STAGES = "Ready Preparation Baseline Release Done End Finalize Append Receipt Retention Ack PostAck Complete".split()
CLASSES = ["Baseline", "Requested", "End"]
ACTIONS = "WorkerWait WorkerRead WorkerObservation SourceBeforeStop StopClient StopBroker WaitBrokerExit CleanExits StoppedSqlite SourceAfterStop Projection Export FinalBrokerObservation DeleteClient".split()
CLEANUP = {"StopClient", "StopBroker", "WaitBrokerExit"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_equal(left: Any, right: Any) -> bool:
    # Python structural equality aliases bool/int/float; preserve JSON representation.
    return left == right and json.dumps(
        left, sort_keys=True, separators=(",", ":")
    ) == json.dumps(right, sort_keys=True, separators=(",", ":"))


def uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 18446744073709551615


def sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def logical_io(value: Any) -> None:
    keys = {
        "read_operations",
        "write_operations",
        "other_operations",
        "read_bytes",
        "write_bytes",
        "other_bytes",
    }
    require(
        isinstance(value, dict)
        and set(value) == keys
        and all(uint(v) for v in value.values()),
        "Logical IO schema",
    )


def process_sample(value: Any) -> None:
    fields = {
        "logical_io",
        "private_bytes",
        "working_set_bytes",
        "lifetime_peak_private_bytes",
        "lifetime_peak_working_set_bytes",
    }
    require(isinstance(value, dict) and set(value) == fields, "Process sample fields")
    logical_io(value["logical_io"])
    for key in (
        "private_bytes",
        "working_set_bytes",
        "lifetime_peak_private_bytes",
        "lifetime_peak_working_set_bytes",
    ):
        require(uint(value[key]), "Process memory schema")


def validate_measurement(
    m: dict[str, Any],
    payload_bytes: int,
    operation_id: int = 0,
    *,
    command_success: bool = True,
) -> None:
    # Mirrors the current Rust schema, including explicitly missing coverage.
    fields = "schema identity operation_id payload_bytes command_success child_exit_us live_attempts live_samples exit_races live_errors first_live_error first_sample_us last_sample_us max_sample_gap_us memory timepoints omitted_timepoints final_lifetime_logical_io final_io_error".split()
    require(isinstance(m, dict) and set(m) == set(fields), "CLI measurement fields")
    require(
        type(m["schema"]) is int
        and m["schema"] == 2
        and type(m["operation_id"]) is int
        and m["operation_id"] == operation_id,
        "CLI schema/operation",
    )
    require(
        exact_equal(m["identity"], {"role": "cli-child", "epoch": 3 + operation_id})
        and type(m["identity"]["epoch"]) is int,
        "CLI retained epoch",
    )
    require(
        uint(m["payload_bytes"])
        and m["payload_bytes"] == payload_bytes
        and type(command_success) is bool
        and m["command_success"] is command_success
        and m["payload_bytes"] <= 2097152,
        "CLI payload/success",
    )
    for key in (
        "child_exit_us",
        "live_attempts",
        "live_samples",
        "exit_races",
        "live_errors",
        "max_sample_gap_us",
        "omitted_timepoints",
    ):
        require(uint(m[key]), "CLI numeric metadata")
    require(
        m["live_attempts"] == m["live_samples"] + m["exit_races"] + m["live_errors"],
        "CLI attempt accounting",
    )
    points = m["timepoints"]
    require(
        isinstance(points, list)
        and len(points) <= 12
        and len(points) + m["omitted_timepoints"] == m["live_samples"],
        "CLI retained point accounting",
    )
    has_samples = m["live_samples"] > 0
    require(has_samples == bool(points), "CLI live samples require retained prefix")
    require(
        (points[0]["since_spawn_start_us"] if points else None) == m["first_sample_us"],
        "CLI first retained timestamp",
    )
    for key in ("memory", "first_sample_us", "last_sample_us"):
        require(
            (m[key] is not None) == has_samples, "CLI missing coverage must remain null"
        )
    require(
        (m["first_live_error"] is not None) == (m["live_errors"] > 0),
        "CLI live error accounting",
    )
    for key in ("first_live_error", "final_io_error"):
        require(
            m[key] is None
            or (isinstance(m[key], str) and len(m[key].encode()) <= 2048),
            "CLI error bound",
        )
    final_io = m["final_lifetime_logical_io"]
    if final_io is not None:
        logical_io(final_io)
        require(m["final_io_error"] is None, "CLI final IO with error")
    if has_samples:
        require(
            uint(m["first_sample_us"])
            and uint(m["last_sample_us"])
            and m["first_sample_us"] <= m["last_sample_us"] <= m["child_exit_us"],
            "CLI sample times",
        )
        memory_keys = (
            "sampled_private_bytes",
            "sampled_working_set_bytes",
            "observed_lifetime_peak_private_bytes",
            "observed_lifetime_peak_working_set_bytes",
        )
        require(
            isinstance(m["memory"], dict)
            and set(m["memory"]) == set(memory_keys)
            and all(uint(v) for v in m["memory"].values()),
            "CLI memory schema",
        )
    previous = None
    retained_gap = 0
    for point in points:
        require(
            isinstance(point, dict)
            and set(point)
            == {
                "since_spawn_start_us",
                "logical_io",
                "private_bytes",
                "working_set_bytes",
                "lifetime_peak_private_bytes",
                "lifetime_peak_working_set_bytes",
            },
            "CLI timepoint fields",
        )
        process_sample({k: v for k, v in point.items() if k != "since_spawn_start_us"})
        t = point["since_spawn_start_us"]
        require(
            uint(t) and m["first_sample_us"] <= t <= m["last_sample_us"],
            "CLI timepoint coverage",
        )
        if previous is not None:
            retained_gap = max(retained_gap, t - previous["since_spawn_start_us"])
            require(
                t >= previous["since_spawn_start_us"]
                and all(
                    point["logical_io"][k] >= previous["logical_io"][k]
                    for k in point["logical_io"]
                ),
                "CLI counter/time regression",
            )
        if final_io is not None:
            require(
                all(final_io[k] >= point["logical_io"][k] for k in final_io),
                "CLI final counter regression",
            )
        for maximum, field in zip(
            memory_keys,
            (
                "private_bytes",
                "working_set_bytes",
                "lifetime_peak_private_bytes",
                "lifetime_peak_working_set_bytes",
            ),
        ):
            require(
                m["memory"][maximum] >= point[field], "CLI sampled maximum regression"
            )
        previous = point
    require(
        m["max_sample_gap_us"] >= retained_gap
        and (m["omitted_timepoints"] != 0 or m["max_sample_gap_us"] == retained_gap),
        "CLI retained cadence mismatch",
    )


def closed(value: Any, fields: str, context: str) -> None:
    require(
        type(value) is dict and set(value) == set(fields.split()),
        context + " closed fields",
    )


def full_descriptor(id: int) -> dict[str, Any]:
    # Mirror the pinned Full20x256V1 producer, including JSON-array stdin vs JSONL.
    source = id - 20 if 42 <= id < 62 else id
    first, count = (
        (source, 1)
        if source < 22
        else (22 + (source - 22) * 256, 256)
        if source < 42
        else (0, 0)
    )
    records = []
    for ordinal in range(first, first + count):
        text = f"ordinary full20x256-v1 mutation {ordinal:06} "
        records.append(
            {
                "id": f"benchmark-full20x256-v1-{ordinal:06}",
                "session_id": "benchmark-client",
                "workspace": "disposable-benchmark",
                "kind": "user",
                "content": (text * (2048 // len(text) + 1))[:2048],
                "timestamp": 1720000000.0 + ordinal,
                "metadata": {"ordinal": ordinal, "workload": "full20x256-v1"},
            }
        )

    def encode(value: Any) -> bytes:
        return json.dumps(value, separators=(",", ":")).encode()

    snapshot = {
        "items": [
            {
                "content": "snapshot benchmark reference",
                "kind": "user",
                "metadata": {"fixture": True},
                "timestamp": 1600000000.0,
            }
        ],
        "session_id": "benchmark-snapshot",
        "workspace": "disposable-benchmark",
    }
    payload = encode(records) if id < 62 else encode(snapshot) if id == 62 else b""
    inserted = count if id < 42 else 0
    return {
        "id": id,
        "cli_epoch": 3 + id,
        "stage": "warmup"
        if id < 2
        else "single"
        if id < 22
        else "batch"
        if id < 42
        else "dedup"
        if id < 62
        else "unchanged-snapshot"
        if id == 62
        else "export",
        "records": count,
        "inserted": inserted,
        "duplicates": count if 42 <= id < 62 else 0,
        "replay_source": id - 20 if 42 <= id < 62 else None,
        "payload_bytes": len(payload),
        "appended_jsonl_bytes": sum(len(encode(r)) + 1 for r in records)
        if inserted
        else 0,
        "sessions": 18 if id == 63 else None,
    }


def full_statistics(values: list[int]) -> dict[str, int] | None:
    values = sorted(values)
    return (
        None
        if not values
        else {
            "count": len(values),
            "p50": values[(len(values) * 50 + 99) // 100 - 1],
            "p95": values[(len(values) * 95 + 99) // 100 - 1],
            "worst": values[-1],
        }
    )


def strict_json(raw: bytes | str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result

    def constant(value: str) -> None:
        raise ValueError("Nonfinite JSON number")

    def finite_float(value: str) -> float:
        import math

        parsed = float(value)
        require(math.isfinite(parsed), "Nonfinite JSON float")
        return parsed

    return json.loads(
        raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float
    )


def encoded(value: Any) -> bytes:
    """Use UTF-8 compact JSON byte budgets, including escaped diagnostics."""
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def number(value: Any, nullable: bool = False) -> None:
    require((nullable and value is None) or uint(value), "Exact unsigned integer")


def boolean(value: Any) -> None:
    require(type(value) is bool, "Exact boolean")


def text(value: Any, limit: int = 2048, nullable: bool = False) -> None:
    require(
        (nullable and value is None)
        or (type(value) is str and 0 < len(value.encode()) <= limit),
        "Bounded text",
    )


def equal(actual: Any, expected: Any, context: str) -> None:
    require(exact_equal(actual, expected), context)


def decode_report(raw: bytes | str) -> dict[str, Any]:
    """Reject duplicate keys, nonfinite numbers and oversized input before parsing."""
    require(type(raw) in (bytes, str), "JSON input type")
    require(
        len(raw if type(raw) is bytes else raw.encode()) <= REPORT_LIMIT,
        "Report byte cap",
    )
    value = strict_json(raw)
    require(type(value) is dict, "Report object")
    return value


def failure(value: Any, role: str | None = None) -> None:
    if value is None:
        return
    closed(value, "role kind os_code text", "Cadence diagnostic")
    require(value["role"] in (None, "SupervisorB", "BrokerC"), "Diagnostic role")
    if role is not None:
        equal(value["role"], role, "Role diagnostic owner")
    require(
        value["kind"] in ("exit", "abort", "invalid-sample", "query", "controller"),
        "Diagnostic kind",
    )
    require(
        value["os_code"] is None
        or (type(value["os_code"]) is int and -(2**31) <= value["os_code"] < 2**31),
        "OS code",
    )
    text(value["text"])


def sample(value: Any) -> None:
    process_sample(value)
    require(
        value["private_bytes"] <= value["lifetime_peak_private_bytes"]
        and value["working_set_bytes"] <= value["lifetime_peak_working_set_bytes"],
        "Impossible lifetime peak",
    )


def delta(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    logical_io(after)
    logical_io(before)
    require(all(after[k] >= before[k] for k in IO), "IO regression")
    return {k: after[k] - before[k] for k in IO}


def point(p: Any, role: str, epoch: int, envelope: int) -> None:
    closed(
        p,
        "ordinal class sample_begin_us sample_end_us requested_slot read",
        "Cadence point",
    )
    for key in ("ordinal", "sample_begin_us", "sample_end_us"):
        number(p[key])
    number(p["requested_slot"], True)
    require(
        p["class"] in CLASSES
        and p["sample_begin_us"] <= p["sample_end_us"] <= envelope,
        "Point class/span",
    )
    closed(p["read"], "role epoch sample", "Retained read")
    equal([p["read"]["role"], p["read"]["epoch"]], [role, epoch], "Read identity")
    sample(p["read"]["sample"])


def role_cadence(r: dict[str, Any], role: str, epoch: int, c: dict[str, Any]) -> None:
    closed(
        r,
        "last_attempt_span max_attempt_span_us error role epoch attempts successful_live_samples exit_observations query_errors counter_regressions not_attempted_due_to_abort forced_baseline_attempts forced_end_attempts baseline end prefix omitted_points first_sample_us last max_consecutive_gap_us observation_max_gap_us operational_max_gap_us max_acquisition_span_us maxima baseline_to_end_io",
        "Role cadence",
    )
    equal([r["role"], r["epoch"]], [role, epoch], "Role identity")
    for key in "attempts successful_live_samples exit_observations query_errors counter_regressions not_attempted_due_to_abort forced_baseline_attempts forced_end_attempts omitted_points".split():
        number(r[key])
    for key in "max_attempt_span_us first_sample_us max_consecutive_gap_us observation_max_gap_us operational_max_gap_us max_acquisition_span_us".split():
        number(r[key], True)
    env, release, done = (
        c["observation_envelope_end_us"],
        c["release_begin_us"],
        c["done_validated_us"],
    )
    require(r["attempts"] <= 30002, "Role attempts cap")
    require(
        (r["last_attempt_span"] is not None)
        == (r["attempts"] > 0)
        == (r["max_attempt_span_us"] is not None),
        "Attempt span presence",
    )
    if r["last_attempt_span"] is not None:
        sp = r["last_attempt_span"]
        closed(sp, "sample_begin_us sample_end_us", "Attempt span")
        number(sp["sample_begin_us"])
        number(sp["sample_end_us"])
        require(
            sp["sample_begin_us"] <= sp["sample_end_us"] <= env
            and sp["sample_end_us"] - sp["sample_begin_us"]
            <= r["max_attempt_span_us"]
            <= env,
            "Attempt span bound",
        )
    errors = r["exit_observations"] + r["query_errors"] + r["counter_regressions"]
    require(
        (r["error"] is not None) == (errors > 0)
        and errors + r["not_attempted_due_to_abort"] <= 1,
        "First role fault",
    )
    failure(r["error"], role)
    if r["error"] is not None:
        require(
            r["error"]["kind"] in ("exit", "query", "invalid-sample"), "Role fault kind"
        )
    n = r["successful_live_samples"]
    require(
        type(r["prefix"]) is list
        and len(r["prefix"]) == min(n, 12)
        and n == len(r["prefix"]) + r["omitted_points"]
        and r["attempts"] == n + errors
        and r["forced_baseline_attempts"] <= 1
        and r["forced_end_attempts"] <= 1,
        "Role prefix/accounting",
    )
    if not n:
        require(
            all(
                r[k] is None
                for k in "first_sample_us last maxima baseline end max_consecutive_gap_us observation_max_gap_us operational_max_gap_us max_acquisition_span_us baseline_to_end_io".split()
            ),
            "Empty role explicit nulls",
        )
        return
    prefix = r["prefix"]
    for p in (
        prefix + [r["last"]] + [p for p in (r["baseline"], r["end"]) if p is not None]
    ):
        point(p, role, epoch, env)
    last = r["last"]
    first = prefix[0]
    equal(r["first_sample_us"], first["sample_end_us"], "First sample")
    gap = span = 0
    maximum = {k: 0 for k in MEM}
    previous = None
    for p in prefix:
        ps = p["read"]["sample"]
        if previous is not None:
            require(
                previous["sample_end_us"] <= p["sample_begin_us"],
                "Acquisition clock regression",
            )
            delta(ps["logical_io"], previous["read"]["sample"]["logical_io"])
            require(
                all(ps[k] >= previous["read"]["sample"][k] for k in MEM[2:]),
                "Lifetime peak regression",
            )
            gap = max(gap, p["sample_end_us"] - previous["sample_end_us"])
        span = max(span, p["sample_end_us"] - p["sample_begin_us"])
        maximum = {k: max(maximum[k], ps[k]) for k in MEM}
        previous = p
    require(prefix[-1]["sample_end_us"] <= last["sample_end_us"], "Last order")
    delta(
        last["read"]["sample"]["logical_io"], prefix[-1]["read"]["sample"]["logical_io"]
    )
    sample(r["maxima"])
    ls = last["read"]["sample"]
    mx = r["maxima"]
    require(
        all(mx[k] >= max(maximum[k], ls[k]) for k in MEM),
        "Maxima below retained evidence",
    )
    equal(
        [mx[k] for k in MEM[2:]],
        [ls[k] for k in MEM[2:]],
        "Lifetime maxima must equal last",
    )
    equal(mx["logical_io"], ls["logical_io"], "Maxima final IO")
    require(
        gap <= r["max_consecutive_gap_us"] <= env
        and max(span, last["sample_end_us"] - last["sample_begin_us"])
        <= r["max_acquisition_span_us"]
        <= env,
        "Online gap/span",
    )
    equal(
        r["observation_max_gap_us"],
        max(
            first["sample_end_us"],
            r["max_consecutive_gap_us"],
            env - last["sample_end_us"],
        ),
        "Observation edges",
    )
    if not r["omitted_points"]:
        equal(last, prefix[-1], "Exact last")
        equal(mx, dict(maximum, logical_io=ls["logical_io"]), "Exact maxima")
        equal(
            [r["max_consecutive_gap_us"], r["max_acquisition_span_us"]],
            [gap, span],
            "Exact aggregates",
        )
    if r["baseline"] is not None:
        equal(r["baseline"], first, "Baseline first")
        require(
            r["forced_baseline_attempts"] == 1
            and first["requested_slot"] is None
            and (release is None or first["sample_end_us"] <= release),
            "Baseline edge",
        )
    if r["end"] is not None:
        equal(r["end"], last, "End last")
        require(
            r["forced_end_attempts"] == 1
            and last["requested_slot"] is None
            and done is not None
            and done <= last["sample_begin_us"],
            "End edge",
        )
    expected_delta = (
        delta(
            r["end"]["read"]["sample"]["logical_io"],
            r["baseline"]["read"]["sample"]["logical_io"],
        )
        if r["baseline"] is not None and r["end"] is not None
        else None
    )
    equal(r["baseline_to_end_io"], expected_delta, "Endpoint delta")
    if release is not None and done is not None:
        known = max(
            max(0, min(first["sample_end_us"], done) - release),
            max(0, done - max(last["sample_end_us"], release)),
        )
        for a, b in zip(prefix, prefix[1:]):
            known = max(
                known,
                max(
                    0, min(b["sample_end_us"], done) - max(a["sample_end_us"], release)
                ),
            )
        require(
            r["operational_max_gap_us"] is not None
            and known <= r["operational_max_gap_us"] <= done - release,
            "Clipped operational gap",
        )
        if not r["omitted_points"]:
            equal(r["operational_max_gap_us"], known, "Exact clipped gap")
    else:
        require(
            r["operational_max_gap_us"] is None or release is not None,
            "Operational gap without release",
        )
    if r["error"] is not None:
        require(
            last["sample_end_us"] <= r["last_attempt_span"]["sample_begin_us"],
            "Success after fault",
        )


def complete(st: dict[str, Any]) -> bool:
    return (
        st["sealed"]
        and st["post_ack_checked"]
        and st["action"] is None
        and st["stage"] == "Complete"
        and st["terminal"] is None
        and st["ack"] == st["release"] == "Confirmed"
        and st["done_observed"]
        and st["append_verified"]
        and st["receipt_validated"]
        and st["command_retained"]
        and st["pending_slot"] is None
    )


def operation_action(value: Any, stage: str) -> str:
    require(
        type(value) is dict
        and len(value) == 1
        and next(iter(value)) in ("Phase", "Gate"),
        "Entered operation action",
    )
    kind = next(iter(value))
    equal(value[kind], stage, "Action stage owner")
    return kind


def new_phase_state() -> dict[str, Any]:
    """Constant-size effect projection; acquisition frontiers replay separately."""
    return dict(
        stage="Ready",
        sealed=False,
        post_ack_checked=False,
        append_verified=False,
        receipt_validated=False,
        command_retained=False,
        ack="NotStarted",
        release="NotStarted",
        done_observed=False,
    )


def phase_transition(state: dict[str, Any], event: str, value: Any) -> None:
    """Atomic phase/effect reducer. Complete is derived exclusively by seal."""
    require(not state["sealed"], "Absorbing operation seal")
    next_state = dict(state)
    stage = state["stage"]
    if event == "stage":
        require(
            value in STAGES and STAGES.index(value) == STAGES.index(stage) + 1,
            "Sequential phase admission",
        )
        prerequisites = {
            "Done": state["release"] == "Confirmed",
            "End": state["done_observed"],
            "Retention": state["receipt_validated"],
            "Ack": state["command_retained"],
            "PostAck": state["ack"] == "Confirmed",
            "Complete": state["post_ack_checked"]
            and state["ack"] == state["release"] == "Confirmed"
            and state["done_observed"]
            and state["append_verified"]
            and state["receipt_validated"]
            and state["command_retained"],
        }
        require(prerequisites.get(value, True), "Phase prerequisite")
        next_state["stage"] = value
        if value == "Complete":
            next_state["sealed"] = True
    elif event in ("release", "ack"):
        require(
            stage == ("Release" if event == "release" else "Ack")
            and state[event] == "NotStarted"
            and value in ("Attempted", "Confirmed", "Unknown"),
            "Publication admission/outcome",
        )
        if event == "ack":
            require(state["command_retained"], "ACK after retention")
        next_state[event] = value
    else:
        fields = {
            "done": ("Done", "done_observed"),
            "append": ("Append", "append_verified"),
            "receipt": ("Receipt", "receipt_validated"),
            "retain": ("Retention", "command_retained"),
            "post_ack": ("PostAck", "post_ack_checked"),
        }
        require(event in fields, "Closed reducer event")
        expected, field = fields[event]
        require(
            stage == expected and not state[field] and value is True,
            "Effect phase entry",
        )
        require(event != "receipt" or state["append_verified"], "Receipt after append")
        require(
            event != "retain" or state["receipt_validated"], "Retention after receipt"
        )
        next_state[field] = True
    state.clear()
    state.update(next_state)


def replay_phases(st: dict[str, Any]) -> None:
    """Replay exactly the entered sequential producer stages and completed facts."""
    projected = new_phase_state()
    events = {
        "Release": ("release", "release"),
        "Done": ("done", "done_observed"),
        "Append": ("append", "append_verified"),
        "Receipt": ("receipt", "receipt_validated"),
        "Retention": ("retain", "command_retained"),
        "Ack": ("ack", "ack"),
        "PostAck": ("post_ack", "post_ack_checked"),
    }
    for stage in STAGES[1 : STAGES.index(st["stage"]) + 1]:
        phase_transition(projected, "stage", stage)
        if stage in events:
            event, field = events[stage]
            value = st[field]
            if value is True or event in ("release", "ack") and value != "NotStarted":
                phase_transition(projected, event, value)
    equal(projected, {k: st[k] for k in projected}, "Reducer effect projection")


def state_cadence(c: dict[str, Any]) -> None:
    st = c["state"]
    closed(
        st,
        "sealed primary_finalized post_ack_checked action stage pairs classes last_pair clock_fault last_live last_attempt last_slot pending_slot append_verified receipt_validated command_retained ack release done_observed peer_consumption terminal",
        "Operation state",
    )
    for key in "sealed primary_finalized post_ack_checked append_verified receipt_validated command_retained done_observed".split():
        boolean(st[key])
    for key in ("pairs", "last_slot"):
        number(st[key])
    number(st["pending_slot"], True)
    require(
        st["stage"] in STAGES
        and st["ack"] in ("NotStarted", "Attempted", "Confirmed", "Unknown")
        and st["release"] in ("NotStarted", "Attempted", "Confirmed", "Unknown")
        and st["peer_consumption"] in ("NotObserved", "NextReadyObserved"),
        "State enums",
    )
    for key, length in (("classes", 3), ("last_live", 2), ("last_attempt", 2)):
        require(
            type(st[key]) is list and len(st[key]) == length, "State frontier width"
        )
        for n in st[key]:
            number(n)
    equal(st["pairs"], c["pair_attempts"], "State pairs")
    equal(
        st["classes"],
        [
            c[k]["pairs"]
            for k in ("baseline_coverage", "requested_coverage", "end_coverage")
        ],
        "State classes",
    )
    require(
        (st["terminal"] is not None) == (c["failure"] is not None)
        and (not st["primary_finalized"] or st["terminal"] is not None),
        "Terminal/diagnostic conservation",
    )
    require(
        st["sealed"] == (st["stage"] == "Complete")
        and (not st["sealed"] or complete(st)),
        "Seal authority",
    )
    index = STAGES.index(st["stage"])
    pairs = st["pairs"]
    classes = st["classes"]
    require(
        pairs <= 30002
        and (not pairs or index >= 2)
        and (not classes[1] or index >= 4)
        and (not classes[2] or index >= 5),
        "Phase acquisition frontier",
    )
    equal(st["done_observed"], c["done_validated_us"] is not None, "DONE conservation")
    equal(
        st["release"] == "Confirmed",
        c["release_end_us"] is not None,
        "Release conservation",
    )
    cut = st["last_pair"]
    require((cut is not None) == (pairs > 0), "Last pair presence")
    if cut is not None:
        closed(cut, "ordinal class slot spans outcomes abort_check_span", "Pair cut")
        number(cut["ordinal"])
        number(cut["slot"], True)
        equal(cut["ordinal"], pairs, "Pair ordinal")
        expected_class = (
            "Baseline"
            if pairs == 1
            else "Requested"
            if pairs <= 1 + classes[1]
            else "End"
        )
        equal(cut["class"], expected_class, "Pair class frontier")
        require(
            type(cut["spans"]) is list
            and len(cut["spans"]) == 2
            and all(type(p) is list and len(p) == 2 for p in cut["spans"]),
            "Pair spans",
        )
        for sp in cut["spans"]:
            for n in sp:
                number(n)
        bb, be, cb, ce = cut["spans"][0] + cut["spans"][1]
        require(bb <= be <= cb <= ce, "Sequential pair clock")
        equal(ce, c["last_pair_end_us"], "Pair envelope frontier")
        require(
            type(cut["outcomes"]) is list
            and len(cut["outcomes"]) == 2
            and all(
                o
                in ("Live", "Exit", "QueryError", "InvalidSample", "NotAttemptedAbort")
                for o in cut["outcomes"]
            )
            and cut["outcomes"][0] != "NotAttemptedAbort",
            "Ordered role outcomes",
        )
        equal(
            cut["abort_check_span"],
            cut["spans"][1] if cut["outcomes"][1] == "NotAttemptedAbort" else None,
            "Abort is not OS acquisition",
        )
        equal(
            c["partial_pairs"],
            int(cut["outcomes"] != ["Live", "Live"]),
            "Terminal partial pair",
        )
        require(
            not c["partial_pairs"] or st["terminal"] is not None, "Partial terminal"
        )
        require((cut["slot"] is None) == (cut["class"] != "Requested"), "Class slot")
        equal(
            st["last_slot"],
            cut["slot"]
            if cut["slot"] is not None
            else (0 if not classes[1] else st["last_slot"]),
            "Last slot",
        )
        if (
            cut["class"] == "Requested"
            and not c["unacquired_requests"]
            and c["done_validated_us"] is None
        ):
            equal(cut["slot"], c["accounted_slots"], "Terminal reservation")
        equal(
            st["last_live"],
            [pairs if o == "Live" else pairs - 1 for o in cut["outcomes"]],
            "Last success frontier",
        )
        equal(
            st["last_attempt"],
            [pairs if o != "NotAttemptedAbort" else pairs - 1 for o in cut["outcomes"]],
            "Last attempt frontier",
        )
        for i, role in enumerate((c["supervisor"], c["broker"])):
            outcome = cut["outcomes"][i]
            equal(
                role["last"]["ordinal"] if role["last"] is not None else 0,
                st["last_live"][i],
                "No success after terminal ordinal",
            )
            equal(
                role["successful_live_samples"],
                pairs - int(outcome != "Live"),
                "Closed live prefix",
            )
            for pos, p in enumerate(role["prefix"], 1):
                equal(p["ordinal"], pos, "Ordinal retained prefix")
            for p in role["prefix"] + [
                p
                for p in (role["last"], role["baseline"], role["end"])
                if p is not None
            ]:
                require(0 < p["ordinal"] <= st["last_live"][i], "Point frontier")
                require(
                    (
                        p["class"] == "Baseline"
                        and p["ordinal"] == 1
                        and p["requested_slot"] is None
                    )
                    or (
                        p["class"] == "Requested"
                        and 1 < p["ordinal"] <= 1 + classes[1]
                        and p["requested_slot"] is not None
                    )
                    or (
                        p["class"] == "End"
                        and p["ordinal"] == pairs
                        and classes[2] == 1
                        and p["requested_slot"] is None
                    ),
                    "Point class frontier",
                )
            if outcome == "Live":
                p = role["last"]
                equal(
                    [
                        p["ordinal"],
                        p["class"],
                        p["requested_slot"],
                        [p["sample_begin_us"], p["sample_end_us"]],
                    ],
                    [cut["ordinal"], cut["class"], cut["slot"], cut["spans"][i]],
                    "Last live pair binding",
                )
            elif outcome != "NotAttemptedAbort":
                sp = role["last_attempt_span"]
                equal(
                    [sp["sample_begin_us"], sp["sample_end_us"]],
                    cut["spans"][i],
                    "Failed attempt span",
                )
            err = role["error"]
            require(
                (
                    outcome in ("Live", "NotAttemptedAbort")
                    and err is None
                    and role["query_errors"] == role["counter_regressions"] == 0
                )
                or (
                    outcome == "Exit"
                    and err is not None
                    and err["kind"] == "exit"
                    and role["query_errors"] == role["counter_regressions"] == 0
                )
                or (
                    outcome == "QueryError"
                    and err is not None
                    and role["query_errors"] == 1
                    and role["counter_regressions"] == 0
                )
                or (
                    outcome == "InvalidSample"
                    and err is not None
                    and err["kind"] == "invalid-sample"
                    and role["query_errors"] + role["counter_regressions"] == 1
                ),
                "Outcome diagnostic binding",
            )
            equal(
                [role["not_attempted_due_to_abort"], role["exit_observations"]],
                [int(outcome == "NotAttemptedAbort"), int(outcome == "Exit")],
                "Outcome counters",
            )
    else:
        equal(
            [st["last_live"], st["last_attempt"], st["last_slot"]],
            [[0, 0], [0, 0], 0],
            "Empty frontiers",
        )
    require(
        (st["pending_slot"] is not None) == (c["unacquired_requests"] == 1),
        "Pending request",
    )
    if st["pending_slot"] is not None:
        require(
            st["pending_slot"] == c["accounted_slots"]
            and st["pending_slot"] > st["last_slot"],
            "Pending slot frontier",
        )
    fault = st["clock_fault"]
    if fault is not None:
        closed(fault, "ordinal class slot spans", "Clock fault")
        number(fault["ordinal"])
        number(fault["slot"], True)
        equal(fault["ordinal"], pairs + 1, "Clock fault ordinal")
        require(
            fault["class"] in CLASSES
            and type(fault["spans"]) is list
            and len(fault["spans"]) == 2
            and all(type(p) is list and len(p) == 2 for p in fault["spans"]),
            "Clock fault shape",
        )
        for sp in fault["spans"]:
            for n in sp:
                number(n)
        bb, be, cb, ce = fault["spans"][0] + fault["spans"][1]
        require(
            not (bb <= be <= cb <= ce and (cut is None or cut["spans"][1][1] <= bb)),
            "Actual invalid clock endpoints required",
        )
        require(
            st["terminal"] is not None
            and st["terminal"]["cause"] in ("InvalidClock", "AdmissionStopped"),
            "Clock primary binding",
        )
        equal(fault["slot"], st["pending_slot"], "Clock pending slot")
    replay_phases(st)
    # Bind replay admission to actual acquisition/end observations.
    if index >= 3:
        require(
            c["baseline_coverage"]["both_live"] == 1
            and (st["release"] == "NotStarted" or c["release_begin_us"] is not None),
            "Release prerequisite",
        )
    if index >= 4:
        require(st["release"] == "Confirmed", "DONE after release")
    if index >= 5:
        require(st["done_observed"], "End after DONE")
    if index >= 6:
        require(c["end_coverage"]["both_live"] == 1, "Finalize endpoint")
    require(not st["append_verified"] or index >= 7, "Append phase")
    require(
        not st["receipt_validated"] or (index >= 8 and st["append_verified"]),
        "Receipt phase",
    )
    require(
        not st["command_retained"] or (index >= 9 and st["receipt_validated"]),
        "Retention phase",
    )
    if index >= 9:
        require(st["receipt_validated"], "Retention prerequisite")
    if index >= 10:
        require(st["command_retained"], "ACK prerequisite")
    if index >= 11:
        require(st["ack"] == "Confirmed", "PostACK prerequisite")
    require(
        (st["release"] == "NotStarted" or index >= 3)
        and (st["ack"] == "NotStarted" or index >= 10),
        "Publication phase",
    )
    require(not st["post_ack_checked"] or index >= 11, "PostACK entered gate")
    require(
        st["peer_consumption"] == "NotObserved" or complete(st),
        "Next READY is observation after seal",
    )
    stop = st["terminal"]
    if stop is not None:
        closed(
            stop, "action cause stage pair_count pending_slot primary", "Terminal cut"
        )
        text(stop["primary"])
        equal(
            [stop["stage"], stop["pair_count"], stop["pending_slot"], stop["action"]],
            [st["stage"], pairs, st["pending_slot"], st["action"]],
            "Terminal owner/frontier",
        )
        kind = operation_action(stop["action"], st["stage"])
        require(
            not st["sealed"]
            and not (st["stage"] == "Ack" and st["ack"] == "Confirmed"),
            "Confirmed ACK cannot own returned failure",
        )
        unknown = (st["stage"] == "Release" and st["release"] == "Unknown") or (
            st["stage"] == "Ack" and st["ack"] == "Unknown"
        )
        require(
            unknown == (st["release"] == "Unknown" or st["ack"] == "Unknown"),
            "Unknown publication owner",
        )
        cause = (
            "PublicationUnknown"
            if unknown
            else "AdmissionStopped"
            if kind == "Gate"
            else "InvalidClock"
            if fault is not None
            else "AcquisitionFault"
            if cut is not None and cut["outcomes"] != ["Live", "Live"]
            else "ControllerFailure"
        )
        require(not unknown or kind == "Phase", "Admission after unknown publication")
        require(st["stage"] != "PostAck" or kind == "Gate", "PostACK failure owns gate")
        equal(stop["cause"], cause, "Producer-derived stop cause")
    else:
        require(
            st["release"] != "Unknown" and st["ack"] != "Unknown",
            "Unknown requires terminal",
        )
    equal(
        st["action"],
        None
        if st["sealed"]
        else stop["action"]
        if stop is not None
        else {"Phase": st["stage"]},
        "Entered action frontier",
    )


def cadence(c: dict[str, Any], epoch: str, op: int) -> None:
    closed(
        c,
        "state schema case_epoch operation_id cli_epoch origin_us nominal_period_us release_begin_us release_end_us done_validated_us observation_envelope_end_us accounted_slots requested_samples missed_slots pair_attempts baseline_coverage requested_coverage end_coverage unacquired_requests both_live_pairs partial_pairs max_pair_span_us last_pair_end_us supervisor broker evidence_complete cadence_target_met failure",
        "Cadence3",
    )
    equal(
        [
            c["schema"],
            c["case_epoch"],
            c["operation_id"],
            c["cli_epoch"],
            c["origin_us"],
            c["nominal_period_us"],
        ],
        [3, epoch, op, op + 3, 0, 2000],
        "Cadence correlation",
    )
    for k in "accounted_slots requested_samples missed_slots pair_attempts unacquired_requests both_live_pairs partial_pairs last_pair_end_us".split():
        number(c[k])
    for k in "release_begin_us release_end_us done_validated_us observation_envelope_end_us max_pair_span_us".split():
        number(c[k], True)
    boolean(c["evidence_complete"])
    boolean(c["cadence_target_met"])
    failure(c["failure"])
    env, release, rend, done = (
        c[k]
        for k in (
            "observation_envelope_end_us",
            "release_begin_us",
            "release_end_us",
            "done_validated_us",
        )
    )
    require(env is not None and c["last_pair_end_us"] <= env, "Observation envelope")
    if rend is not None:
        require(release is not None and release <= rend <= env, "Release span")
    if done is not None:
        require(rend is not None and rend <= done <= env, "DONE span")
    require(
        c["pair_attempts"] <= 30002
        and c["pair_attempts"] == c["both_live_pairs"] + c["partial_pairs"]
        and c["partial_pairs"] <= 1,
        "Pair conservation",
    )
    if release is not None:
        require(
            release <= env and c["accounted_slots"] <= (env - release) // 2000,
            "Slot envelope",
        )
    if release is not None and done is not None:
        equal(c["accounted_slots"], (done - release) // 2000, "Final slots")
    equal(
        c["requested_samples"] + c["missed_slots"], c["accounted_slots"], "Missed slots"
    )
    classes = [
        c[k] for k in ("baseline_coverage", "requested_coverage", "end_coverage")
    ]
    for coverage in classes:
        closed(
            coverage,
            "pairs supervisor_live broker_live both_live supervisor_aborted broker_aborted",
            "Pair coverage",
        )
        for n in coverage.values():
            number(n)
        require(
            coverage["both_live"]
            <= min(coverage["supervisor_live"], coverage["broker_live"])
            and coverage["supervisor_live"] + coverage["supervisor_aborted"]
            <= coverage["pairs"]
            and coverage["broker_live"] + coverage["broker_aborted"]
            <= coverage["pairs"]
            and coverage["supervisor_live"] + coverage["broker_live"]
            <= coverage["pairs"] + coverage["both_live"],
            "Coverage conservation",
        )
    equal(classes[0]["pairs"], int(c["pair_attempts"] > 0), "Baseline class")
    require(
        classes[2]["pairs"] <= 1
        and sum(x["pairs"] for x in classes) == c["pair_attempts"]
        and sum(x["both_live"] for x in classes) == c["both_live_pairs"],
        "Class pair totals",
    )
    equal(
        c["requested_samples"],
        classes[1]["pairs"] + c["unacquired_requests"],
        "Requested count",
    )
    require(
        c["unacquired_requests"] <= 1
        and (not c["unacquired_requests"] or c["failure"] is not None and done is None)
        and (not classes[2]["pairs"] or done is not None)
        and (release is None or classes[0]["both_live"] == 1)
        and (not c["requested_samples"] or rend is not None),
        "Acquisition phase",
    )
    for r, role, epoch_id, label in (
        (c["supervisor"], "SupervisorB", 2, "supervisor"),
        (c["broker"], "BrokerC", 1, "broker"),
    ):
        role_cadence(r, role, epoch_id, c)
        equal(
            r["successful_live_samples"],
            sum(x[label + "_live"] for x in classes),
            "Class live totals",
        )
        equal(
            r["not_attempted_due_to_abort"],
            sum(x[label + "_aborted"] for x in classes),
            "Class aborted totals",
        )
        equal(
            [r["forced_baseline_attempts"], r["forced_end_attempts"]],
            [classes[j]["pairs"] - classes[j][label + "_aborted"] for j in (0, 2)],
            "Forced attempt totals",
        )
        equal(
            [int(r["baseline"] is not None), int(r["end"] is not None)],
            [classes[j][label + "_live"] for j in (0, 2)],
            "Endpoint presence",
        )
        pts = r["prefix"] + (
            [r["last"]]
            if r["last"] is not None
            and (not r["prefix"] or not exact_equal(r["last"], r["prefix"][-1]))
            else []
        )
        previous_slot = retained_requested = 0
        for p in pts:
            slot = p["requested_slot"]
            if slot is not None:
                require(
                    slot > previous_slot
                    and release is not None
                    and p["sample_begin_us"] >= release
                    and slot
                    <= min(
                        c["accounted_slots"], (p["sample_begin_us"] - release) // 2000
                    ),
                    "Requested slot timing/order",
                )
                retained_requested += 1
                previous_slot = slot
            else:
                require(
                    exact_equal(p, r["baseline"]) or exact_equal(p, r["end"]),
                    "Unclassified point",
                )
        require(
            retained_requested <= classes[1][label + "_live"]
            and (
                r["omitted_points"] > 0
                or retained_requested == classes[1][label + "_live"]
            ),
            "Retained requested coverage",
        )
        require(
            r["attempts"] + r["not_attempted_due_to_abort"] == c["pair_attempts"]
            and (
                (r["error"] is None and not r["not_attempted_due_to_abort"])
                or c["failure"] is not None
                and c["partial_pairs"] > 0
            ),
            "Role pair/fault conservation",
        )
    require(
        (c["max_pair_span_us"] is not None) == (c["pair_attempts"] > 0),
        "Pair span presence",
    )
    if c["max_pair_span_us"] is not None:
        require(
            max(
                c["supervisor"]["max_attempt_span_us"] or 0,
                c["broker"]["max_attempt_span_us"] or 0,
            )
            <= c["max_pair_span_us"]
            <= env,
            "Pair span",
        )
        for b, cr in list(zip(c["supervisor"]["prefix"], c["broker"]["prefix"])) + (
            [(c["supervisor"]["end"], c["broker"]["end"])]
            if c["supervisor"]["end"] is not None and c["broker"]["end"] is not None
            else []
        ):
            require(
                b["sample_end_us"] <= cr["sample_begin_us"]
                and cr["sample_end_us"] - b["sample_begin_us"] <= c["max_pair_span_us"],
                "Pair skew",
            )
            equal(b["requested_slot"], cr["requested_slot"], "Pair slot binding")
    if c["partial_pairs"]:
        failed = next(i for i, x in enumerate(classes) if x["both_live"] != x["pairs"])
        require(
            all(
                x["both_live"] == x["pairs"]
                if i < failed
                else x["pairs"] == x["both_live"] + 1
                if i == failed
                else x["pairs"] == 0
                for i, x in enumerate(classes)
            ),
            "No postfault acquisition class",
        )
        require(
            (
                failed != 0
                or release is None
                and not c["requested_samples"]
                and done is None
            )
            and (failed != 1 or done is None)
            and (failed != 2 or done is not None),
            "Postfault phase",
        )
        first = next(
            r
            for r in (c["supervisor"], c["broker"])
            if r["error"] is not None or r["not_attempted_due_to_abort"]
        )
        equal(c["failure"]["role"], first["role"], "First failed role")
        if first["error"] is not None:
            equal(c["failure"], first["error"], "First acquisition diagnostic retained")
        else:
            equal(c["failure"]["kind"], "abort", "Abort diagnostic")
    state_cadence(c)
    is_complete = (
        c["failure"] is None
        and rend is not None
        and done is not None
        and all(
            c[r][p] is not None
            for r in ("supervisor", "broker")
            for p in ("baseline", "end")
        )
        and not c["partial_pairs"]
    )
    equal(c["evidence_complete"], is_complete, "Evidence completeness")
    target = (
        is_complete
        and not c["missed_slots"]
        and all(
            c[r]["operational_max_gap_us"] is not None
            and c[r]["operational_max_gap_us"] <= 2000
            for r in ("supervisor", "broker")
        )
    )
    equal(c["cadence_target_met"], target, "Diagnostic target not performance approval")
    require(len(encoded(c)) <= 32768, "Cadence interval byte cap")


def case_outcome(report: dict[str, Any], operations: list[dict[str, Any]]) -> None:
    actions = report["case_actions"]
    action_failure = None
    op_failure = None
    if actions is not None:
        closed(actions, "operation_failure records entered", "Case actions")
        require(
            actions["entered"] is None
            and type(actions["records"]) is list
            and len(actions["records"]) <= 14,
            "Finished bounded actions",
        )
        text(actions["operation_failure"], nullable=True)
        op_failure = actions["operation_failure"]
        previous = None
        failed = op_failure is not None
        for record in actions["records"]:
            closed(record, "action error", "Case action record")
            action = record["action"]
            text(record["error"], nullable=True)
            require(
                action in ACTIONS and (not failed or action in CLEANUP),
                "Postfailure cleanup only",
            )
            idx = ACTIONS.index(action)
            require(
                (previous is None or idx > previous)
                if action in CLEANUP
                else idx == (0 if previous is None else previous + 1),
                "Entered action order",
            )
            previous = idx
            if record["error"] is not None:
                failed = True
                if action_failure is None:
                    action_failure = record
        if report["pass"] or report["correctness_complete"]:
            require(
                op_failure is None and len(actions["records"]) == 14 and not failed,
                "All14 actual observed actions required",
            )
    elif report["pass"] or report["correctness_complete"]:
        require(False, "Successful controller requires action capsule")
    acknowledged = 0
    for op in operations:
        if op["cadence"]["state"]["ack"] != "Confirmed":
            break
        acknowledged += 1
    terminal = operations[-1]["cadence"]["state"]["terminal"] if operations else None
    error = report["error"]
    text(error, nullable=True)
    expected = None
    if terminal is not None:
        require(
            operations[-1]["cadence"]["state"]["primary_finalized"],
            "Finalized operation primary",
        )
        if actions is not None:
            equal(op_failure, terminal["primary"], "Common operation/case owner")
        expected = (
            operations[-1]["operation_id"],
            {"Operation": terminal["stage"]},
            terminal["primary"],
        )
    elif op_failure is not None:
        require(
            len(operations) < 64 and error == op_failure,
            "External setup operation owner",
        )
        expected = (len(operations), "ExternalObservation", op_failure)
    elif action_failure is not None:
        require(
            len(operations) == 64
            and all(complete(o["cadence"]["state"]) for o in operations),
            "Action failure after sealed workload",
        )
        expected = (64, {"Action": action_failure["action"]}, action_failure["error"])
    elif error is not None:
        require(len(operations) < 64, "External error cannot own sealed full case")
        expected = (len(operations), "ExternalObservation", error)
    if expected is None:
        equal(report["case_stop"], None, "No unowned case stop")
        equal(error, None, "No unowned error")
    else:
        position, cause, primary = expected
        closed(
            report["case_stop"],
            "position acknowledged_prefix cause primary",
            "Case stop",
        )
        equal(
            report["case_stop"],
            {
                "position": position,
                "acknowledged_prefix": acknowledged,
                "cause": cause,
                "primary": primary,
            },
            "Derived case outcome",
        )
        equal(error, primary, "Case primary must survive cleanup")
        require(report["pass"] is False, "Terminal cannot pass")


def command_semantics(command: dict[str, Any], op: int, retained: bool) -> None:
    closed(
        command,
        "exe args exit_code success child_exited capture_complete spawn_error capture_error kill_error wait_error stdout_overflow stderr_overflow timed_out stop_requested elapsed_us stdout stderr stdout_file stderr_file measurement",
        "Measured command",
    )
    require(len(encoded(command)) <= 131072, "Command byte cap")
    for key in "success child_exited capture_complete stdout_overflow stderr_overflow timed_out stop_requested".split():
        boolean(command[key])
    for key in "spawn_error capture_error kill_error wait_error".split():
        text(command[key], nullable=True)
    require(
        command["exit_code"] is None
        or type(command["exit_code"]) is int
        and -(2**31) <= command["exit_code"] < 2**31,
        "Command exit",
    )
    number(command["elapsed_us"])
    text(command["exe"], 32768)
    require(
        type(command["args"]) is list
        and len(command["args"]) <= 128
        and all(
            type(arg) is str and len(arg.encode()) <= 65536 for arg in command["args"]
        ),
        "Argument bounds",
    )
    for key in ("stdout", "stderr"):
        require(
            type(command[key]) is str and len(command[key].encode()) <= 1048576,
            "Pipe text cap",
        )
        text(command[key + "_file"], 32768)
    m = command["measurement"]
    # Unretained attempts can be unsuccessful. Validate their closed measurement
    # with its actual boolean, never turn them into successful retained receipts.
    closed(
        m,
        "schema identity operation_id payload_bytes command_success child_exit_us live_attempts live_samples exit_races live_errors first_live_error first_sample_us last_sample_us max_sample_gap_us memory timepoints omitted_timepoints final_lifetime_logical_io final_io_error",
        "Measurement",
    )
    boolean(m["command_success"])
    equal(m["identity"], {"role": "cli-child", "epoch": op + 3}, "CLI identity")
    equal([m["schema"], m["operation_id"]], [2, op], "CLI schema/ordinal")
    for key in "payload_bytes child_exit_us live_attempts live_samples exit_races live_errors max_sample_gap_us omitted_timepoints".split():
        number(m[key])
    for key in ("first_sample_us", "last_sample_us"):
        number(m[key], True)
    if retained:
        require(
            command["exit_code"] == 0
            and all(
                command[k] is True
                for k in ("success", "child_exited", "capture_complete")
            )
            and all(
                command[k] is False
                for k in (
                    "stdout_overflow",
                    "stderr_overflow",
                    "timed_out",
                    "stop_requested",
                )
            )
            and all(
                command[k] is None
                for k in ("spawn_error", "capture_error", "kill_error", "wait_error")
            ),
            "Retained intrinsic command success",
        )
        descriptor = full_descriptor(op)
        validate_measurement(m, descriptor["payload_bytes"], op)
        expected = (
            {"sessions": 18}
            if op == 63
            else {
                "inserted": descriptor["inserted"],
                "duplicates": descriptor["duplicates"],
            }
        )
        equal(strict_json(command["stdout"]), expected, "Retained stage output")
    else:
        validate_measurement(
            m, m["payload_bytes"], op, command_success=m["command_success"]
        )


def boundary(c: dict[str, Any], end: bool) -> dict[str, Any] | None:
    b, cr = [c[r]["end" if end else "baseline"] for r in ("supervisor", "broker")]
    if b is None or cr is None:
        return None
    return {
        "broker_epoch": 1,
        "supervisor_epoch": 2,
        "cli_epoch": c["cli_epoch"],
        "broker": cr["read"]["sample"],
        "supervisor": b["read"]["sample"],
        "broker_logical_io_delta": c["broker"]["baseline_to_end_io"] if end else None,
        "supervisor_logical_io_delta": c["supervisor"]["baseline_to_end_io"]
        if end
        else None,
        "handshake_span_us": c["observation_envelope_end_us"] if end else None,
    }


def validate_structure(report: dict[str, Any]) -> dict[str, Any]:
    """Validate current controller reports, including genuine negative prefixes.

    This is structural ordinary evidence, not native custody or performance proof.
    """
    closed(
        report,
        "case_actions case_stop schema role case case_epoch workload_spec seed_records additions final_records sessions commands controller_retained_commands operations source_oracle import_oracle projection_oracle export_oracle correctness_complete workload_complete measurement_complete sampling_complete native_handle_verified performance_policy_status performance_complete release_ready pass error diagnostics",
        "Schema8 report",
    )
    require(len(encoded(report)) <= REPORT_LIMIT, "Report byte cap")
    equal(
        [
            report["schema"],
            report["role"],
            report["case"],
            report["workload_spec"],
            report["additions"],
            report["sessions"],
        ],
        [
            8,
            "Controller",
            "representative-6MiB-full20x256-v1",
            {"schema": 1, "kind": "Full20x256V1"},
            5142,
            18,
        ],
        "Closed current namespace",
    )
    for key in "correctness_complete workload_complete measurement_complete sampling_complete native_handle_verified performance_complete release_ready pass".split():
        boolean(report[key])
    require(
        not any(
            report[k]
            for k in (
                "measurement_complete",
                "sampling_complete",
                "performance_complete",
                "release_ready",
            )
        )
        and report["performance_policy_status"] == "unapproved",
        "Unapproved incomplete policy",
    )
    seeds = report["seed_records"]
    number(seeds, True)
    number(report["final_records"], True)
    require(seeds is None or 16 <= seeds <= 400000, "Seed bound")
    equal(
        report["final_records"],
        None if seeds is None else seeds + 5143,
        "Final records",
    )
    # Structural epochs are correlation values, not native admission tokens.
    # encoded(report) above also rejects non-UTF-8 Unicode scalar strings.
    require(
        report["case_epoch"] is None or type(report["case_epoch"]) is str,
        "Nullable case epoch string",
    )
    require(type(report["diagnostics"]) is dict, "Diagnostics object")
    commands = report["commands"]
    retained = report["controller_retained_commands"]
    operations = report["operations"]
    operations_present = operations is not None
    require(type(commands) is list and len(commands) <= 64, "Commands bound")
    require(
        retained is None or type(retained) is list and len(retained) <= 64,
        "Retention bound",
    )
    require(
        operations is None or type(operations) is list and len(operations) <= 64,
        "Operations bound",
    )
    # Rust requires a manifest for nonempty retained receipts and for every
    # present operation array, including []. Preserve nullable pre-setup reports.
    require(not retained or seeds is not None, "Retained receipt manifest missing")
    require(
        operations is None or report["case_epoch"] is not None,
        "Cadence case epoch missing",
    )
    require(
        operations is None or seeds is not None, "Full operation manifest seed missing"
    )
    retained = [] if retained is None else retained
    operations = [] if operations is None else operations
    for op, command in enumerate(commands):
        command_semantics(command, op, op < len(retained))
    for op, command in enumerate(retained):
        command_semantics(command, op, True)
    for worker, owned in zip(commands, retained):
        equal(worker, owned, "Exact worker/controller overlap")
    cadence_bytes = pair_count = retained_prefix = 0
    for op, evidence in enumerate(operations):
        closed(
            evidence,
            "operation_id cli_epoch descriptor before_release after_done receipt_validated exact_append_verified cadence",
            "Operation boundary",
        )
        equal(
            [evidence["operation_id"], evidence["cli_epoch"], evidence["descriptor"]],
            [op, op + 3, full_descriptor(op)],
            "Operation descriptor",
        )
        boolean(evidence["receipt_validated"])
        boolean(evidence["exact_append_verified"])
        c = evidence["cadence"]
        cadence(c, report["case_epoch"], op)
        st = c["state"]
        cadence_bytes += len(encoded(c))
        pair_count += c["pair_attempts"]
        require(
            cadence_bytes <= 2097152 and pair_count <= 150128,
            "Case cadence byte/pair caps",
        )
        if op:
            prev = operations[op - 1]["cadence"]["state"]
            require(
                complete(prev)
                and (
                    st["stage"] == "Ready"
                    or prev["peer_consumption"] == "NextReadyObserved"
                ),
                "Next operation after sealed ACK",
            )
        if st["command_retained"]:
            require(retained_prefix == op, "Retained effect prefix")
            retained_prefix += 1
        equal(
            [evidence["receipt_validated"], evidence["exact_append_verified"]],
            [st["receipt_validated"], st["append_verified"]],
            "Completed receipt/append effects",
        )
        for end, key in ((False, "before_release"), (True, "after_done")):
            obs = evidence[key]
            if obs is not None:
                equal(obs, boundary(c, end), "Actual boundary/cadence binding")
            else:
                require(not c["evidence_complete"], "Complete boundary required")
        if c["failure"] is not None:
            require(
                op == len(operations) - 1
                and all(
                    report[k] is False
                    for k in (
                        "pass",
                        "workload_complete",
                        "correctness_complete",
                        "native_handle_verified",
                    )
                )
                and report["error"] is not None,
                "Terminal report closure",
            )
            acquisition_terminal = (
                c["partial_pairs"] > 0 or c["unacquired_requests"] > 0
            )
            require(
                op <= len(retained) <= op + 1
                and len(commands) <= op + int(c["release_end_us"] is not None)
                and (
                    len(retained) == op
                    or not acquisition_terminal
                    and evidence["after_done"] is not None
                ),
                "Terminal retained prefix",
            )
            require(
                not acquisition_terminal
                or not evidence["receipt_validated"]
                and not evidence["exact_append_verified"]
                and evidence["after_done"] is None,
                "No postacquisition receipt",
            )
        if report["correctness_complete"]:
            require(
                evidence["receipt_validated"] and evidence["exact_append_verified"],
                "Correctness receipt",
            )
        if report["native_handle_verified"]:
            require(c["evidence_complete"], "Native evidence complete")
    # None carries no cadence-prefix owner; Some([]) carries an empty owner.
    if operations_present:
        equal(len(retained), retained_prefix, "Exact retained effect count")
    if report["workload_complete"]:
        require(
            report["case_epoch"] is not None and report["case_epoch"] != "",
            "Complete workload case epoch missing",
        )
    if report["workload_complete"] or report["correctness_complete"]:
        require(
            len(operations) == len(commands) == len(retained) == 64
            and seeds is not None
            and report["case_epoch"] is not None
            and all(
                complete(e["cadence"]["state"]) and e["cadence"]["evidence_complete"]
                for e in operations
            ),
            "All64 sealed coverage",
        )
    require(
        not report["native_handle_verified"] or len(operations) == 64, "Native coverage"
    )
    require(
        not report["pass"]
        or report["workload_complete"]
        and report["correctness_complete"]
        and report["error"] is None,
        "Pass closure",
    )
    require(
        not report["correctness_complete"] or report["workload_complete"],
        "Correctness closure",
    )
    case_outcome(report, operations)
    validate_oracles(report)
    return {
        "correctness_pass": report["pass"],
        "workload_complete": report["workload_complete"],
        "measurement_complete": False,
        "sampling_complete": False,
        "performance_complete": False,
        "release_ready": False,
        "performance_policy_status": "unapproved",
        "evidence_scope": "structural-only",
    }


def validate_oracles(report: dict[str, Any]) -> None:
    """Validate closed nullable stopped-oracle grammar even on failed reports."""
    fields = {
        "source_oracle": "source_unchanged archive_sha256 logical_sha256 records source_inventory",
        "import_oracle": "persisted_startup_receipt final_read_only_export expected_final_logical_sha256",
        "projection_oracle": "records bytes exact_records_including_metadata_verified",
        "export_oracle": "records sessions files exact_payloads_verified snapshot_payload_verified index_sha256",
    }
    for key, keys in fields.items():
        value = report[key]
        require(
            value is not None or not report["correctness_complete"],
            "Required correctness oracle",
        )
        if value is None:
            continue
        closed(value, keys, key)
    source, imp, projection, export = (report[k] for k in fields)
    if source is not None:
        boolean(source["source_unchanged"])
        number(source["records"])
        require(
            sha(source["archive_sha256"])
            and sha(source["logical_sha256"])
            and type(source["source_inventory"]) is dict
            and 1 <= len(source["source_inventory"]) <= 16,
            "Source oracle",
        )
        for name, file in source["source_inventory"].items():
            text(name, 32768)
            closed(file, "bytes sha256", "Source digest")
            number(file["bytes"])
            require(sha(file["sha256"]), "Source SHA")
    if imp is not None:
        require(sha(imp["expected_final_logical_sha256"]), "Final logical SHA")
        for key in ("persisted_startup_receipt", "final_read_only_export"):
            receipt = imp[key]
            closed(
                receipt,
                "records snapshot_states snapshot_counters logical_sha256",
                "Logical receipt",
            )
            for k in ("records", "snapshot_states", "snapshot_counters"):
                number(receipt[k])
            require(sha(receipt["logical_sha256"]), "Receipt SHA")
    if projection is not None:
        number(projection["records"])
        number(projection["bytes"])
        boolean(projection["exact_records_including_metadata_verified"])
    if export is not None:
        number(export["records"])
        number(export["sessions"])
        boolean(export["exact_payloads_verified"])
        boolean(export["snapshot_payload_verified"])
        require(
            sha(export["index_sha256"])
            and type(export["files"]) is list
            and len(export["files"]) <= 18,
            "Export digest/membership",
        )
        for file in export["files"]:
            closed(file, "path bytes sha256", "Export file")
            text(file["path"], 32768)
            number(file["bytes"])
            require(
                file["bytes"] <= 20971520 and sha(file["sha256"]), "Export file bounds"
            )
    if report["correctness_complete"]:
        seeds = report["seed_records"]
        final = seeds + 5143
        require(
            source["source_unchanged"] and source["records"] == seeds + 1,
            "Source records",
        )
        for key, count, digest in (
            ("persisted_startup_receipt", seeds + 1, source["logical_sha256"]),
            ("final_read_only_export", final, imp["expected_final_logical_sha256"]),
        ):
            equal(
                imp[key],
                {
                    "records": count,
                    "snapshot_states": 1,
                    "snapshot_counters": 1,
                    "logical_sha256": digest,
                },
                "Stopped SQLite exact oracle",
            )
        total = source["source_inventory"]["events.jsonl"]["bytes"] + sum(
            full_descriptor(op)["appended_jsonl_bytes"] for op in range(64)
        )
        equal(
            projection,
            {
                "records": final,
                "bytes": total,
                "exact_records_including_metadata_verified": True,
            },
            "Exact JSONL oracle",
        )
        require(
            export["records"] == final
            and export["sessions"] == len(export["files"]) == 18
            and export["exact_payloads_verified"]
            and export["snapshot_payload_verified"],
            "Stopped export oracle",
        )


def validate_full8_report(
    report: dict[str, Any], pins: dict[str, str]
) -> dict[str, Any]:
    """Hosted acceptance is success-only and requires independent native evidence."""
    validate_structure(report)
    result = validate_native_success(report, pins)
    cadences = [evidence["cadence"] for evidence in report["operations"]]
    result["measurement_status"] = "incomplete-full64-cadence3"
    result["cadence_summary"] = {
        "schema": 3,
        "operations": len(cadences),
        "all64_sealed": all(complete(c["state"]) for c in cadences),
        "evidence_complete": all(c["evidence_complete"] for c in cadences),
        "cadence_target_met": all(c["cadence_target_met"] for c in cadences),
        "pair_attempts": sum(c["pair_attempts"] for c in cadences),
        "requested_samples": sum(c["requested_samples"] for c in cadences),
        "missed_slots": sum(c["missed_slots"] for c in cadences),
        "retained_point_limit_per_role": 12,
        "roles": {
            role: {
                "successful_live_samples": sum(
                    c[role]["successful_live_samples"] for c in cadences
                ),
                "omitted_points": sum(c[role]["omitted_points"] for c in cadences),
                "worst_operational_gap_us": max(
                    c[role]["operational_max_gap_us"] for c in cadences
                ),
                "worst_observation_gap_us": max(
                    c[role]["observation_max_gap_us"] for c in cadences
                ),
                "maxima": {
                    field: max(c[role]["maxima"][field] for c in cadences)
                    for field in MEM
                },
            }
            for role in ("supervisor", "broker")
        },
    }
    return result


def validate_native_success(
    report: dict[str, Any], pins: dict[str, str]
) -> dict[str, Any]:
    closed(
        report,
        "case_actions case_stop schema role case case_epoch workload_spec seed_records additions final_records sessions commands controller_retained_commands operations source_oracle import_oracle projection_oracle export_oracle correctness_complete workload_complete measurement_complete sampling_complete native_handle_verified performance_policy_status performance_complete release_ready pass error diagnostics",
        "Full report",
    )
    require(
        exact_equal(report["schema"], 8)
        and report["role"] == "Controller"
        and report["case"] == "representative-6MiB-full20x256-v1",
        "Full schema/role/case",
    )
    require(
        exact_equal(report["workload_spec"], {"schema": 1, "kind": "Full20x256V1"}),
        "Full manifest namespace",
    )
    for key in (
        "correctness_complete",
        "workload_complete",
        "native_handle_verified",
        "pass",
    ):
        require(report[key] is True, "Full required success evidence")
    for key in (
        "measurement_complete",
        "sampling_complete",
        "performance_complete",
        "release_ready",
    ):
        require(report[key] is False, "Full boundary-only measurement is incomplete")
    require(
        report["performance_policy_status"] == "unapproved" and report["error"] is None,
        "Full error/policy",
    )
    seeds = report["seed_records"]
    require(
        uint(seeds)
        and 16 <= seeds <= 400000
        and exact_equal(report["additions"], 5142)
        and exact_equal(report["sessions"], 18)
        and uint(report["final_records"])
        and report["final_records"] == seeds + 5143,
        "Full record totals",
    )
    diag = report["diagnostics"]
    require(
        type(diag) is dict
        and diag.get("source_unchanged") is True
        and diag.get("client_registration_deleted") is True
        and "error" not in diag,
        "Full source/cleanup diagnostics",
    )
    require(
        exact_equal(
            diag["executable_sha256"],
            {role: pins[role] for role in ("admin", "broker", "client")},
        ),
        "Full executable pins",
    )
    root = diag["fixture"]["root"]
    epoch = report["case_epoch"]
    require(
        isinstance(root, str)
        and 1 <= len(root.encode()) <= 32768
        and isinstance(epoch, str)
        and 1 <= len(epoch.encode()) <= 256
        and all(c.isascii() and (c.isalnum() or c == "-") for c in epoch)
        and epoch == diag["fixture"]["client_service"],
        "Full root/case epoch",
    )
    enroll = diag["plan"]["enrollment"]
    require(
        isinstance(enroll, str) and 1 <= len(enroll.encode()) <= 32768,
        "Full enrollment path",
    )
    generation = diag["generation"]
    require(
        exact_equal(
            generation["fixture_spec"],
            {"shape": "representative-v2", "target_jsonl_bytes": 6291456},
        )
        and exact_equal(generation["seed_records"], seeds)
        and exact_equal(generation["records"], seeds + 1),
        "Full6 fixture only",
    )
    for value in (
        diag["client_stop"]["process"]["exit_code"],
        diag["client_stop"]["scm_exit_code"],
        diag["broker_exit"]["exit_code"],
        diag["broker_after"]["pinned_process"]["exit_code"],
    ):
        require(exact_equal(value, 0), "Full clean exit")
    require(
        diag["client_stop"]["process"]["exited"] is True
        and diag["broker_exit"]["exited"] is True
        and diag["broker_before"]["pinned_process"]["exited"] is False
        and diag["broker_after"]["pinned_process"]["exited"] is True,
        "Full retained lifecycle",
    )
    require(
        bool(diag["broker_before"]["initial_identity"])
        and exact_equal(
            diag["broker_before"]["initial_identity"],
            diag["broker_after"]["initial_identity"],
        )
        and exact_equal(diag["broker_before"]["name"], diag["broker_after"]["name"]),
        "Full same retained broker",
    )
    commands, retained, operations = (
        report["commands"],
        report["controller_retained_commands"],
        report["operations"],
    )
    require(
        type(commands) is list
        and type(retained) is list
        and type(operations) is list
        and len(commands) == len(retained) == len(operations) == 64
        and exact_equal(commands, retained),
        "Full exact ordered64 preACK retention",
    )
    previous = None
    appended = 0
    for id, (command, evidence) in enumerate(zip(commands, operations)):
        descriptor = full_descriptor(id)
        closed(
            evidence,
            "operation_id cli_epoch descriptor before_release after_done receipt_validated exact_append_verified cadence",
            "Full boundary",
        )
        require(
            exact_equal(evidence["operation_id"], id)
            and exact_equal(evidence["cli_epoch"], 3 + id)
            and exact_equal(evidence["descriptor"], descriptor)
            and evidence["receipt_validated"] is True
            and evidence["exact_append_verified"] is True,
            "Full descriptor/receipt correlation",
        )
        closed(
            command,
            "exe args exit_code success child_exited capture_complete spawn_error capture_error kill_error wait_error stdout_overflow stderr_overflow timed_out stop_requested elapsed_us stdout stderr stdout_file stderr_file measurement",
            "Full measured command",
        )
        require(
            len(json.dumps(command, separators=(",", ":")).encode()) <= 131072,
            "Full command byte cap",
        )
        require(
            exact_equal(command["exit_code"], 0)
            and uint(command["elapsed_us"])
            and command["elapsed_us"] <= 60000000,
            "Full command exit/time",
        )
        for key in ("success", "child_exited", "capture_complete"):
            require(command[key] is True, "Full command completeness")
        for key in (
            "stdout_overflow",
            "stderr_overflow",
            "timed_out",
            "stop_requested",
        ):
            require(command[key] is False, "Full command timeout/capture")
        for key in ("spawn_error", "capture_error", "kill_error", "wait_error"):
            require(command[key] is None, "Full command infrastructure error")
        expected_args = [
            "--enrollment",
            enroll,
            "snapshot" if id == 62 else "export" if id == 63 else "ingest",
            "--root",
            root + "\\small/source",
        ]
        if id == 63:
            expected_args += [
                "--workspace",
                "disposable-benchmark",
                "--vault",
                root + "\\scratch\\export",
            ]
        require(
            command["exe"] == root + "\\install-small\\bin/hermes-memory-client.exe"
            and exact_equal(command["args"], expected_args),
            "Full exact installed executable/argv; no normalization",
        )
        for stream in ("stdout", "stderr"):
            require(
                isinstance(command[stream], str)
                and len(command[stream].encode()) <= 1048576
                and command[stream + "_file"]
                == root + f"\\scratch\\full20x256-v1-op-{id}.{stream}",
                "Full exact capture path/text",
            )
        expected = (
            {"sessions": 18}
            if id == 63
            else {
                "inserted": descriptor["inserted"],
                "duplicates": descriptor["duplicates"],
            }
        )
        require(
            exact_equal(strict_json(command["stdout"]), expected),
            "Full stage acknowledgement",
        )
        m = command["measurement"]
        validate_measurement(m, descriptor["payload_bytes"], id)
        require(
            m["live_samples"] > 0
            and m["live_errors"] == 0
            and m["memory"] is not None
            and m["final_lifetime_logical_io"] is not None
            and m["final_io_error"] is None
            and m["child_exit_us"] <= min(command["elapsed_us"], 45000000),
            "Full required complete CLI evidence",
        )
        before, after = evidence["before_release"], evidence["after_done"]
        for observation, is_after in ((before, False), (after, True)):
            closed(
                observation,
                "broker_epoch supervisor_epoch cli_epoch broker supervisor broker_logical_io_delta supervisor_logical_io_delta handshake_span_us",
                "Full observation",
            )
            require(
                exact_equal(observation["broker_epoch"], 1)
                and exact_equal(observation["supervisor_epoch"], 2)
                and exact_equal(observation["cli_epoch"], 3 + id),
                "Full retained epochs",
            )
            for role in ("broker", "supervisor"):
                process_sample(observation[role])
                delta = observation[role + "_logical_io_delta"]
                if is_after:
                    logical_io(delta)
                    require(
                        all(
                            after[role]["logical_io"][key]
                            >= before[role]["logical_io"][key]
                            and delta[key]
                            == after[role]["logical_io"][key]
                            - before[role]["logical_io"][key]
                            for key in delta
                        ),
                        "Full checked retained IO delta",
                    )
                    if previous is not None:
                        require(
                            all(
                                before[role]["logical_io"][key]
                                >= previous[role]["logical_io"][key]
                                for key in delta
                            ),
                            "Full cross-operation retained counters",
                        )
                else:
                    require(delta is None, "Full baseline explicit null delta")
            require(
                uint(observation["handshake_span_us"])
                if is_after
                else observation["handshake_span_us"] is None,
                "Full observation phase duration",
            )
        previous = after
        appended += descriptor["appended_jsonl_bytes"]
    source, imported, projection, exported = (
        report[key]
        for key in (
            "source_oracle",
            "import_oracle",
            "projection_oracle",
            "export_oracle",
        )
    )
    closed(
        source,
        "source_unchanged archive_sha256 logical_sha256 records source_inventory",
        "Full source oracle",
    )
    require(
        source["source_unchanged"] is True
        and exact_equal(source["records"], seeds + 1)
        and sha(source["archive_sha256"])
        and sha(source["logical_sha256"]),
        "Full source identity",
    )
    inventory = source["source_inventory"]
    require(
        type(inventory) is dict
        and 1 <= len(inventory) <= 16
        and all(isinstance(k, str) for k in inventory),
        "Full source inventory",
    )
    for file in inventory.values():
        closed(file, "bytes sha256", "Full source file")
        require(uint(file["bytes"]) and sha(file["sha256"]), "Full source file digest")
    require(
        exact_equal(inventory, generation["source_before"])
        and exact_equal(inventory, generation["source_after"])
        and source["logical_sha256"] == generation["logical_sha256"]
        and source["archive_sha256"] == generation["archive_sha256"],
        "Full source oracle/generation correlation",
    )
    initial = inventory["events.jsonl"]["bytes"]
    require(6291456 <= initial <= 7340032, "Full6 source projection bound")
    closed(
        imported,
        "persisted_startup_receipt final_read_only_export expected_final_logical_sha256",
        "Full import oracle",
    )
    for name, count, digest in (
        ("persisted_startup_receipt", seeds + 1, source["logical_sha256"]),
        (
            "final_read_only_export",
            seeds + 5143,
            imported["expected_final_logical_sha256"],
        ),
    ):
        receipt = imported[name]
        closed(
            receipt,
            "records snapshot_states snapshot_counters logical_sha256",
            "Full logical receipt",
        )
        require(
            exact_equal(receipt["records"], count)
            and exact_equal(receipt["snapshot_states"], 1)
            and exact_equal(receipt["snapshot_counters"], 1)
            and sha(digest)
            and receipt["logical_sha256"] == digest,
            "Full streaming SQLite logical oracle",
        )
    closed(
        projection,
        "records bytes exact_records_including_metadata_verified",
        "Full projection oracle",
    )
    require(
        exact_equal(projection["records"], seeds + 5143)
        and uint(projection["bytes"])
        and projection["bytes"] == initial + appended
        and projection["exact_records_including_metadata_verified"] is True,
        "Full streaming JSONL bytes/records oracle",
    )
    closed(
        exported,
        "records sessions files exact_payloads_verified snapshot_payload_verified index_sha256",
        "Full export oracle",
    )
    require(
        exact_equal(exported["records"], seeds + 5143)
        and exact_equal(exported["sessions"], 18)
        and exported["exact_payloads_verified"] is True
        and exported["snapshot_payload_verified"] is True
        and sha(exported["index_sha256"]),
        "Full stopped export oracle",
    )
    files = exported["files"]
    require(type(files) is list and len(files) == 18, "Full export membership count")

    def segment(value: str) -> str:
        return value + "-" + hashlib.sha256(value.encode()).hexdigest()[:16]

    sessions = (
        ["benchmark-client"]
        + [f"benchmark-seed-{n:02}" for n in range(16)]
        + ["benchmark-snapshot"]
    )
    expected_paths = {
        root
        + "\\scratch/export\\Sessions\\"
        + segment("disposable-benchmark")
        + "\\"
        + segment(session)
        + ".md"
        for session in sessions
    }
    actual_paths = []
    for file in files:
        closed(file, "path bytes sha256", "Full export file")
        require(
            isinstance(file["path"], str)
            and uint(file["bytes"])
            and 0 < file["bytes"] <= 20971520
            and sha(file["sha256"]),
            "Full export file digest",
        )
        actual_paths.append(file["path"])
    require(
        len(set(actual_paths)) == 18 and set(actual_paths) == expected_paths,
        "Full exact canonical session path set",
    )
    stages = {}
    for stage, ids in (
        ("warmup", range(2)),
        ("single", range(2, 22)),
        ("batch", range(22, 42)),
        ("dedup", range(42, 62)),
        ("unchanged-snapshot", range(62, 63)),
        ("export", range(63, 64)),
    ):
        samples = [commands[id]["measurement"] for id in ids]
        stages[stage] = {
            "count": len(samples),
            "child_exit_us": full_statistics([m["child_exit_us"] for m in samples]),
            "logical_io": {
                key: full_statistics(
                    [m["final_lifetime_logical_io"][key] for m in samples]
                )
                for key in samples[0]["final_lifetime_logical_io"]
            },
        }
    return {
        "correctness_pass": True,
        "measurement_status": "incomplete-full64-boundary-only",
        "workload_complete": True,
        "measurement_complete": False,
        "sampling_complete": False,
        "performance_policy_status": "unapproved",
        "performance_complete": False,
        "release_ready": False,
        "stage_summaries": stages,
        "streaming_oracles": {
            "source_records": source["records"],
            "final_records": projection["records"],
            "projection_bytes": projection["bytes"],
            "final_logical_sha256": imported["expected_final_logical_sha256"],
            "sessions": exported["sessions"],
            "index_sha256": exported["index_sha256"],
        },
    }
