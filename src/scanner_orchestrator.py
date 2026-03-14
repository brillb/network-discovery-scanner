# Copyright 2026 Benjamin Brillat
#
# Author: Benjamin Brillat
# GitHub: https://github.com/brillb
# License: Apache License 2.0
# SPDX-License-Identifier: Apache-2.0
#
# This file is part of the brillb/network-discovery-scanner project.
#
# Co-authored using AI coding assist modules in the IDE, including
# GPT, Copilot, Gemini, and similar tools.
#
# See the LICENSE file at the repository root for full license terms.

"""
Component: Orchestrator (`scanner_orchestrator.py`)
Primary entry point. Reads targets, resolves precedence, runs subnet sweeps,
and executes single-IP discovery through bounded worker and writer threads.
"""
import argparse
import csv
import ipaddress
import os
import sys
import threading
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from queue import Queue

import module_portscan

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db_loader import describe_database, load_database, load_db_config
from module_orchestrator_cli_ui import OrchestratorCliUI, build_default_logfile_path
from module_db_writer import ScanResultWriter
from process_single_ip import SingleIPPipeline, SingleIPScanRequest, SingleIPScanResult, load_yaml_file


COLOR_RESET = "\033[0m"
COLOR_DISPATCH = "\033[32m"
COLOR_COMPLETED = "\033[95m"
SENTINEL = object()


@dataclass(frozen=True)
class TargetSpec:
    """
    One normalized targeting rule loaded from a single CSV row.

    "Spec" here means specification: a row-level rule that says
    "scan this IP/subnet using these keytags if this rule wins precedence."

    Examples:
    - a single IP row becomes a /32 or /128 TargetSpec
    - a subnet row stays a subnet TargetSpec
    """
    row_index: int
    raw_target: str
    network: object
    keytags: tuple[str, ...]

    @property
    def is_single_ip(self):
        return self.network.prefixlen == self.network.max_prefixlen

    @property
    def ip_version(self):
        return self.network.version

    @property
    def precedence_key(self):
        return (self.network.prefixlen, self.row_index)


class TargetPlanner:
    def __init__(self, specs):
        """
        Build lookup structures for all target rules from the CSV.

        `specs` is the list of TargetSpec objects. Each TargetSpec represents
        one CSV row after validation/normalization.

        We keep:
        - `specs_by_version`: IPv4 and IPv6 rules separated so membership checks
          do not mix address families
        - `latest_identical_row`: when the exact same network appears multiple
          times, the later row wins
        """
        self.specs = specs
        self.specs_by_version = {4: [], 6: []}
        self.latest_identical_row = {}

        for spec in specs:
            self.specs_by_version[spec.ip_version].append(spec)
            self.latest_identical_row[(spec.ip_version, spec.network.with_prefixlen)] = spec.row_index

    def owning_spec_for_ip(self, ip_obj):
        """
        Return the TargetSpec that "owns" this IP for the current run.

        "Owner" means the single winning CSV rule that should control scanning
        for this IP after precedence is resolved.

        Ownership rules:
        - the rule must contain the IP
        - the most specific rule wins
        - if specificity ties, the later CSV row wins

        Example:
        - `192.168.1.0/24` matches `192.168.1.7`
        - `192.168.1.7/32` also matches `192.168.1.7`
        - the /32 is more specific, so it is the owner
        """
        winner = None
        for spec in self.specs_by_version.get(ip_obj.version, []):
            if ip_obj not in spec.network:
                continue
            if winner is None or spec.precedence_key > winner.precedence_key:
                winner = spec
        return winner

    def should_process_spec_ip(self, spec, ip_obj):
        """
        Check whether a specific TargetSpec is allowed to schedule this IP.

        We compute the owning rule for the IP, then allow scheduling only if
        the current `spec` is that winning rule.

        This is what prevents:
        - duplicate IP scans
        - broader subnets from re-scanning an IP already claimed by a more
          specific IP or subnet rule
        """
        owner = self.owning_spec_for_ip(ip_obj)
        return owner is not None and owner.row_index == spec.row_index

    def is_shadowed_identical_network(self, spec):
        """
        Return True if the exact same network appears later in the CSV.

        Example:
        - row 10: `192.168.1.0/24`
        - row 20: `192.168.1.0/24`

        In that case row 10 is shadowed and row 20 is the only rule that should
        survive, because equal-prefix ties are resolved by later row order.
        """
        latest_row = self.latest_identical_row.get((spec.ip_version, spec.network.with_prefixlen))
        return latest_row is not None and latest_row != spec.row_index


class RunState:
    def __init__(self):
        # Shared counters/state updated from multiple threads. Keep every
        # mutation under one lock so progress reporting stays internally
        # consistent.
        self.lock = threading.Lock()
        self.queued_scans = 0
        self.running_scans = 0
        self.awaiting_persist = 0
        self.submitted = 0
        self.completed = 0
        self.scheduled_ip_ids = set()
        self.runtime_failures = []

    def mark_enqueued(self, ip_text, max_parallel):
        with self.lock:
            self.queued_scans += 1
            self.submitted += 1
            queued = self.queued_scans
            running = self.running_scans
            awaiting_persist = self.awaiting_persist
            submitted = self.submitted
        print(
            f"\n{COLOR_DISPATCH}---> Queued IP Pipeline: {ip_text} "
            f"(running={running}/{max_parallel}, queued={queued}, awaiting_db={awaiting_persist}, submitted={submitted})"
            f"{COLOR_RESET}",
            flush=True,
        )

    def mark_started(self, ip_text, max_parallel):
        with self.lock:
            if self.queued_scans > 0:
                self.queued_scans -= 1
            self.running_scans += 1
            queued = self.queued_scans
            running = self.running_scans
            awaiting_persist = self.awaiting_persist
        print(
            f"{COLOR_DISPATCH}===> Starting IP Pipeline: {ip_text} "
            f"(running={running}/{max_parallel}, queued={queued}, awaiting_db={awaiting_persist})"
            f"{COLOR_RESET}",
            flush=True,
        )

    def mark_scan_finished(self, ip_text):
        with self.lock:
            if self.running_scans > 0:
                self.running_scans -= 1
            self.awaiting_persist += 1
            queued = self.queued_scans
            running = self.running_scans
            awaiting_persist = self.awaiting_persist
        print(
            f"{COLOR_COMPLETED}<=== Scan Finished, Awaiting DB Write: {ip_text} "
            f"(running={running}, queued={queued}, awaiting_db={awaiting_persist})"
            f"{COLOR_RESET}",
            flush=True,
        )

    def mark_completed(self, ip_text):
        with self.lock:
            if self.awaiting_persist > 0:
                self.awaiting_persist -= 1
            self.completed += 1
            queued = self.queued_scans
            running = self.running_scans
            awaiting_persist = self.awaiting_persist
            completed = self.completed
        print(
            f"{COLOR_COMPLETED}<--- Completed IP Pipeline: {ip_text} "
            f"(running={running}, queued={queued}, awaiting_db={awaiting_persist}, completed={completed})"
            f"{COLOR_RESET}",
            flush=True,
        )

    def mark_failed_completion(self, ip_text, message):
        with self.lock:
            if self.awaiting_persist > 0:
                self.awaiting_persist -= 1
            self.completed += 1
            queued = self.queued_scans
            running = self.running_scans
            awaiting_persist = self.awaiting_persist
            completed = self.completed
        print(
            f"<--- IP Pipeline FAILED: {ip_text} "
            f"(error={message}, running={running}, queued={queued}, awaiting_db={awaiting_persist}, completed={completed})",
            flush=True,
        )

    def mark_runtime_failure(self, ip_text, message):
        with self.lock:
            self.runtime_failures.append({"ip_address": ip_text, "message": message})

    def snapshot(self):
        with self.lock:
            return {
                "queued": self.queued_scans,
                "running": self.running_scans,
                "awaiting_db": self.awaiting_persist,
                "submitted": self.submitted,
                "completed": self.completed,
                "runtime_failures": len(self.runtime_failures),
            }

    def try_schedule_ip(self, ip_obj):
        ip_id = int(ip_obj)
        with self.lock:
            if ip_id in self.scheduled_ip_ids:
                return False
            self.scheduled_ip_ids.add(ip_id)
            return True

    def raise_for_failures(self):
        if not self.runtime_failures:
            return

        failed_targets = ", ".join(
            f"{item['ip_address']} ({item['message']})" for item in self.runtime_failures
        )
        raise SystemExit(f"{len(self.runtime_failures)} pipeline(s) failed: {failed_targets}")


def create_evidence_folder(base_path):
    # Each orchestrator run gets its own timestamped evidence folder so SSH
    # output from different runs never collides.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"discovered_device_evidence_{timestamp}"
    folder_path = os.path.abspath(os.path.join(base_path, folder_name))
    os.makedirs(folder_path, exist_ok=True)
    return folder_path


def require_existing_file(parser, path_value, argument_name):
    if not os.path.isfile(path_value):
        parser.error(f"{argument_name} does not exist or is not a file: {path_value}")


def load_target_specs(csv_path):
    """
    Read the CSV into TargetSpec objects.

    We intentionally load rules, not a pre-expanded IP list.
    That keeps memory usage reasonable even when the CSV contains large ranges
    such as `/16` networks.
    """
    specs = []

    with open(csv_path, "r", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        next(reader, None)

        for row_index, row in enumerate(reader, start=1):
            if not row:
                continue

            target_text = row[0].strip()
            if not target_text:
                continue

            keytags = tuple(tag.strip() for tag in row[1:] if tag.strip())
            try:
                if "/" in target_text:
                    network = ipaddress.ip_network(target_text, strict=False)
                else:
                    ip_obj = ipaddress.ip_address(target_text)
                    network = ipaddress.ip_network(f"{ip_obj}/{ip_obj.max_prefixlen}", strict=False)
            except ValueError:
                print(f"Invalid target in CSV row {row_index}: {target_text}")
                continue

            specs.append(
                TargetSpec(
                    row_index=row_index,
                    raw_target=target_text,
                    network=network,
                    keytags=keytags,
                )
            )

    return specs


def build_pipeline_exception_result(request, exc):
    # Convert an unexpected worker exception into a normal scan result shape so
    # the failure can still move through the writer/status pipeline cleanly.
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detail = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    return SingleIPScanResult(
        ip=request.ip,
        keytags=tuple(request.keytags),
        started_at=now,
        finished_at=now,
        errors=[f"pipeline_exception:{detail}"],
    )


def choose_writer_index(ip_text, writer_count):
    # Shard by IP so repeated writes for the same device stay on the same writer
    # thread/connection during a run.
    return int(ipaddress.ip_address(ip_text)) % writer_count


def update_ui_runtime(ui, run_state, task_queue, writer_queues):
    if not ui:
        return

    snapshot = run_state.snapshot()
    ui.update_runtime(
        running=snapshot["running"],
        queued=snapshot["queued"],
        awaiting_db=snapshot["awaiting_db"],
        submitted=snapshot["submitted"],
        completed=snapshot["completed"],
        runtime_failures=snapshot["runtime_failures"],
        task_queue_depth=task_queue.qsize(),
        writer_queue_depths=tuple(queue.qsize() for queue in writer_queues),
    )


def scan_worker(
    worker_id,
    task_queue,
    writer_queues,
    stop_event,
    keys_data,
    ssh_commands_data,
    evidence_dir,
    run_state,
    max_parallel,
    ui,
):
    # Each scan worker owns its own pipeline instance and performs only network
    # discovery. It does not write directly to the database.
    pipeline = SingleIPPipeline(
        keys_data=keys_data,
        ssh_commands_data=ssh_commands_data,
        evidence_dir=evidence_dir,
    )

    while True:
        request = task_queue.get()
        if request is SENTINEL:
            task_queue.task_done()
            break

        if stop_event.is_set():
            task_queue.task_done()
            continue

        try:
            run_state.mark_started(request.ip, max_parallel)
            update_ui_runtime(ui, run_state, task_queue, writer_queues)
            result = pipeline.run(request)
        except Exception as exc:
            # Unexpected scan-side exceptions are reported as synthetic failed
            # results so the orchestrator can finish the run deterministically.
            result = build_pipeline_exception_result(request, exc)
            run_state.mark_runtime_failure(request.ip, "scan_exception")
            update_ui_runtime(ui, run_state, task_queue, writer_queues)

        run_state.mark_scan_finished(result.ip)
        update_ui_runtime(ui, run_state, task_queue, writer_queues)
        writer_index = choose_writer_index(result.ip, len(writer_queues))
        # Hand off the completed result to the DB writer shard that owns this IP.
        writer_queues[writer_index].put(result)
        update_ui_runtime(ui, run_state, task_queue, writer_queues)
        task_queue.task_done()


def writer_worker(writer_index, result_queue, stop_event, db_handle, run_state, ui, task_queue, writer_queues):
    # Each writer thread owns one live DB connection for the duration of the run.
    # This is what lets SQLite stay at one writer while scan workers still fan out.
    db_conn = db_handle.engine.connect()
    result_writer = ScanResultWriter(db_conn)

    try:
        while True:
            result = result_queue.get()
            if result is SENTINEL:
                result_queue.task_done()
                break

            if stop_event.is_set() and result is None:
                result_queue.task_done()
                continue

            try:
                result_writer.persist_scan_result(result)
                if ui:
                    ui.note_db_write(result.ip, writer_index)
                run_state.mark_completed(result.ip)
                update_ui_runtime(ui, run_state, task_queue, writer_queues)
            except Exception as exc:
                # Persistence failures are tracked separately from scan failures
                # so the orchestrator can exit non-zero with a summary.
                run_state.mark_runtime_failure(result.ip, f"db_exception:{exc}")
                run_state.mark_failed_completion(result.ip, exc)
                update_ui_runtime(ui, run_state, task_queue, writer_queues)
                print(
                    f"[writer-{writer_index}] Failed to persist {result.ip}: {exc}",
                    flush=True,
                )
            finally:
                result_queue.task_done()
    finally:
        db_conn.close()


def enqueue_request(request, task_queue, run_state, max_parallel, ui, writer_queues):
    # Queue insertion is bounded; if workers are saturated this blocks and
    # applies backpressure instead of letting memory usage grow without limit.
    task_queue.put(request)
    run_state.mark_enqueued(request.ip, max_parallel)
    update_ui_runtime(ui, run_state, task_queue, writer_queues)


def maybe_schedule_ip(ip_text, source_spec, planner, task_queue, run_state, max_parallel, ui, writer_queues):
    """
    Attempt to schedule one concrete IP for scanning.

    `source_spec` is the TargetSpec currently producing this IP:
    - for a direct IP row, that row itself
    - for a subnet row, the subnet rule currently being swept

    The IP is only enqueued if:
    1. `source_spec` is the owning rule for that IP
    2. the IP has not already been scheduled during this run
    """
    ip_obj = ipaddress.ip_address(ip_text)
    if not planner.should_process_spec_ip(source_spec, ip_obj):
        return False

    if not run_state.try_schedule_ip(ip_obj):
        return False

    request = SingleIPScanRequest(ip=str(ip_obj), keytags=source_spec.keytags)
    enqueue_request(request, task_queue, run_state, max_parallel, ui, writer_queues)
    return True


def process_target_specs(specs, planner, task_queue, run_state, max_parallel, stop_event, ui, writer_queues):
    """
    Walk the TargetSpec rules in CSV order and turn them into scan requests.

    Important distinction:
    - `specs` are row-level targeting rules
    - scan requests are concrete single-IP jobs

    For direct IP rules, we try to schedule exactly one IP.
    For subnet rules, we sweep for active hosts and then test each discovered IP
    against the planner to see whether this subnet is actually the owning rule.
    """
    for spec_index, spec in enumerate(specs, start=1):
        if stop_event.is_set():
            break

        if ui:
            ui.update_target_progress(processed=spec_index, current_target=spec.raw_target)

        if spec.is_single_ip:
            if planner.is_shadowed_identical_network(spec):
                # The exact same IP/network appears later in the CSV, so this
                # earlier rule is ignored.
                continue
            maybe_schedule_ip(
                str(spec.network.network_address),
                spec,
                planner,
                task_queue,
                run_state,
                max_parallel,
                ui,
                writer_queues,
            )
            continue

        if planner.is_shadowed_identical_network(spec):
            # Same-network duplicate subnet rule; later row wins.
            continue

        cidr = spec.network.with_prefixlen
        print(f"Sweeping Subnet: {cidr}")
        result = module_portscan.sweep_subnet(cidr)
        if "error" in result:
            print(f"Subnet error: {result['error']}")
            continue

        for active_ip in result.get("up_hosts", []):
            if stop_event.is_set():
                break
            # Even though this IP came from the current subnet sweep, a more
            # specific rule may own it. The planner enforces that here.
            maybe_schedule_ip(
                active_ip,
                spec,
                planner,
                task_queue,
                run_state,
                max_parallel,
                ui,
                writer_queues,
            )

    if ui:
        ui.update_target_progress(processed=len(specs), done=True)


def build_argument_parser():
    parser = argparse.ArgumentParser(description="Network Scanner Entry Point")
    parser.add_argument("--targets", required=True)
    parser.add_argument("--keys", required=True)
    parser.add_argument("--ssh-commands", required=True)
    parser.add_argument("--evidence-dir", default=os.getcwd())
    parser.add_argument("--dbconfig", required=True)
    parser.add_argument(
        "--max-workers-per-db-connection",
        type=int,
        default=10,
        help="Maximum number of active scan workers per DB writer connection.",
    )
    parser.add_argument(
        "--max-db-connections",
        type=int,
        default=1,
        help="Maximum number of DB writer connections. SQLite requires exactly 1.",
    )
    return parser


def run_orchestrator(args, ui, evidence_dir):
    dbconfig_path = os.path.abspath(args.dbconfig)

    if args.max_workers_per_db_connection < 1:
        raise SystemExit("--max-workers-per-db-connection must be a positive integer.")
    if args.max_db_connections < 1:
        raise SystemExit("--max-db-connections must be a positive integer.")

    args.targets = os.path.abspath(args.targets)
    args.keys = os.path.abspath(args.keys)
    args.ssh_commands = os.path.abspath(args.ssh_commands)
    args.evidence_dir = os.path.abspath(args.evidence_dir)

    if not os.path.isfile(args.targets):
        raise SystemExit(f"--targets does not exist or is not a file: {args.targets}")
    if not os.path.isfile(args.keys):
        raise SystemExit(f"--keys does not exist or is not a file: {args.keys}")
    if not os.path.isfile(args.ssh_commands):
        raise SystemExit(f"--ssh-commands does not exist or is not a file: {args.ssh_commands}")
    if not os.path.isfile(dbconfig_path):
        raise SystemExit(f"--dbconfig does not exist or is not a file: {dbconfig_path}")

    db_config = load_db_config(dbconfig_path)
    if db_config["type"] == "sqlite" and args.max_db_connections != 1:
        raise SystemExit("--max-db-connections must be 1 for SQLite.")

    total_workers = args.max_workers_per_db_connection * args.max_db_connections
    os.makedirs(args.evidence_dir, exist_ok=True)

    # Initialize the schema up front before any worker threads start. For
    # external backends, pool size is capped to the advertised writer budget.
    db_handle = load_database(
        dbconfig_path,
        initialize=True,
        pool_size=args.max_db_connections if db_config["type"] != "sqlite" else None,
        max_overflow=0 if db_config["type"] != "sqlite" else None,
    )
    db_description = describe_database(db_handle.config)
    print(f"Database initialized: {db_description}")
    print(f"Evidence Directory Created: {evidence_dir}")
    print(f"Logfile Created: {ui.logfile_path}")

    keys_data = load_yaml_file(args.keys, "Keys")
    ssh_commands_data = load_yaml_file(args.ssh_commands, "SSH commands")
    specs = load_target_specs(args.targets)
    planner = TargetPlanner(specs)

    task_queue_capacity = max(total_workers * 2, total_workers)
    writer_queue_capacity = max(args.max_workers_per_db_connection * 2, 10)
    if ui:
        ui.configure(
            db_description=db_description,
            evidence_dir=evidence_dir,
            logfile_path=ui.logfile_path,
            target_rules_total=len(specs),
            max_parallel=total_workers,
            max_db_connections=args.max_db_connections,
            workers_per_db_connection=args.max_workers_per_db_connection,
            task_queue_capacity=task_queue_capacity,
            writer_queue_capacity=writer_queue_capacity,
        )

    print(f"Configured DB writer connections: {args.max_db_connections}", flush=True)
    print(f"Configured scan workers per DB connection: {args.max_workers_per_db_connection}", flush=True)
    print(f"Configured total active scan workers: {total_workers}", flush=True)
    print(f"Loaded target rules: {len(specs)}", flush=True)

    run_state = RunState()
    stop_event = threading.Event()
    # The scan queue holds concrete single-IP jobs. Size is intentionally
    # bounded so large subnets cannot dump an unbounded backlog into memory.
    task_queue = Queue(maxsize=task_queue_capacity)
    # Each writer shard gets its own result queue. These are also bounded so DB
    # backpressure can propagate back to the scan workers.
    writer_queues = [
        Queue(maxsize=writer_queue_capacity)
        for _ in range(args.max_db_connections)
    ]
    update_ui_runtime(ui, run_state, task_queue, writer_queues)

    scan_threads = []
    for worker_id in range(total_workers):
        # Scan workers perform the Ping/SNMP/SSH pipeline and hand off finished
        # results to the DB writer shard that owns the IP.
        thread = threading.Thread(
            target=scan_worker,
            args=(
                worker_id,
                task_queue,
                writer_queues,
                stop_event,
                keys_data,
                ssh_commands_data,
                evidence_dir,
                run_state,
                total_workers,
                ui,
            ),
            daemon=True,
        )
        thread.start()
        scan_threads.append(thread)

    writer_threads = []
    for writer_index, writer_queue in enumerate(writer_queues):
        # Writer threads are the only place that touch live DB connections during
        # orchestration, which keeps the DB concurrency model explicit.
        thread = threading.Thread(
            target=writer_worker,
            args=(writer_index, writer_queue, stop_event, db_handle, run_state, ui, task_queue, writer_queues),
            daemon=True,
        )
        thread.start()
        writer_threads.append(thread)

    try:
        process_target_specs(specs, planner, task_queue, run_state, total_workers, stop_event, ui, writer_queues)
        # First wait for all scan jobs to finish, then wait for all queued DB
        # writes to drain.
        task_queue.join()
        for writer_queue in writer_queues:
            writer_queue.join()
    except KeyboardInterrupt:
        print("\nInterrupt received; stopping new submissions and draining queued work...", flush=True)
        stop_event.set()
        while not task_queue.empty():
            time.sleep(0.1)
        task_queue.join()
        for writer_queue in writer_queues:
            writer_queue.join()
        raise
    finally:
        stop_event.set()
        # Send one sentinel per thread so each worker can exit its blocking
        # queue.get() cleanly.
        for _ in scan_threads:
            task_queue.put(SENTINEL)
        for thread in scan_threads:
            thread.join()

        for writer_queue in writer_queues:
            writer_queue.put(SENTINEL)
        for thread in writer_threads:
            thread.join()

        db_handle.engine.dispose()

    print(f"All pipelines completed: {run_state.completed}", flush=True)
    run_state.raise_for_failures()


def main():
    parser = build_argument_parser()
    args = parser.parse_args()
    args.evidence_dir = os.path.abspath(args.evidence_dir)
    os.makedirs(args.evidence_dir, exist_ok=True)
    evidence_dir = create_evidence_folder(args.evidence_dir)
    logfile_path = build_default_logfile_path(evidence_dir)

    with OrchestratorCliUI(logfile_path=logfile_path) as ui:
        if ui.fallback_reason:
            print(f"CLI UI fallback: {ui.fallback_reason}", flush=True)
        run_orchestrator(args, ui, evidence_dir)


if __name__ == "__main__":
    main()
