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
Component: Orchestrator CLI UI
Captures console output, optionally renders a Blessed-based dashboard, and
mirrors messages to a logfile.
"""
from __future__ import annotations

import os
import ipaddress
import re
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import TextIO


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE_RE.sub("", text)


def build_default_logfile_path(evidence_dir: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(os.path.abspath(evidence_dir), f"logfile-{timestamp}.txt")


@dataclass
class UIStatus:
    started_at: float = field(default_factory=time.time)
    db_description: str = ""
    evidence_dir: str = ""
    logfile_path: str = ""
    target_rules_total: int = 0
    target_rules_processed: int = 0
    current_target: str = ""
    scheduling_done: bool = False
    max_parallel: int = 0
    max_db_connections: int = 0
    workers_per_db_connection: int = 0
    running: int = 0
    queued: int = 0
    awaiting_db: int = 0
    submitted: int = 0
    completed: int = 0
    runtime_failures: int = 0
    task_queue_depth: int = 0
    task_queue_capacity: int = 0
    writer_queue_depths: tuple[int, ...] = ()
    writer_queue_capacity: int = 0
    last_db_write_ip: str = ""
    last_db_writer: str = ""
    ui_mode: str = "plain"


class _CapturedStream:
    def __init__(self, ui, original_stream: TextIO):
        self.ui = ui
        self.original_stream = original_stream
        self.encoding = getattr(original_stream, "encoding", "utf-8")

    def write(self, text):
        if not text:
            return 0

        self.ui.handle_stream_text(text)
        if self.ui.should_mirror_to_console():
            self.original_stream.write(text)
        return len(text)

    def flush(self):
        self.ui.flush_stream_buffers()
        if self.ui.should_mirror_to_console():
            self.original_stream.flush()

    def isatty(self):
        return self.original_stream.isatty()


class OrchestratorCliUI:
    def __init__(self, *, logfile_path: str | None = None, enable_tui: bool = True):
        self.logfile_path = os.path.abspath(logfile_path) if logfile_path else ""
        self.enable_tui = enable_tui
        self.status = UIStatus(logfile_path=self.logfile_path)
        self._lock = threading.Lock()
        self._log_lines = deque(maxlen=2000)
        self._partial_line = ""
        self._log_handle: TextIO | None = None
        self._stdout_original = sys.stdout
        self._stderr_original = sys.stderr
        self._stop_event = threading.Event()
        self._refresh_thread: threading.Thread | None = None
        self._fallback_reason = ""
        self._force_console_mirror = False
        self._tui_active = False
        self._term = None
        self._blessed = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False

    @property
    def fallback_reason(self):
        return self._fallback_reason

    def should_mirror_to_console(self):
        return self._force_console_mirror or not self._tui_active

    def start(self):
        self._open_logfile()
        self._try_start_tui()
        sys.stdout = _CapturedStream(self, self._stdout_original)
        sys.stderr = _CapturedStream(self, self._stderr_original)

    def stop(self):
        try:
            self.flush_stream_buffers()
        finally:
            sys.stdout = self._stdout_original
            sys.stderr = self._stderr_original
            self._stop_refresh_loop()
            self._close_tui()
            self._close_logfile()

    def configure(
        self,
        *,
        db_description: str = "",
        evidence_dir: str = "",
        logfile_path: str = "",
        target_rules_total: int | None = None,
        max_parallel: int | None = None,
        max_db_connections: int | None = None,
        workers_per_db_connection: int | None = None,
        task_queue_capacity: int | None = None,
        writer_queue_capacity: int | None = None,
    ):
        with self._lock:
            if db_description:
                self.status.db_description = db_description
            if evidence_dir:
                self.status.evidence_dir = evidence_dir
            if logfile_path:
                self.status.logfile_path = logfile_path
            if target_rules_total is not None:
                self.status.target_rules_total = target_rules_total
            if max_parallel is not None:
                self.status.max_parallel = max_parallel
            if max_db_connections is not None:
                self.status.max_db_connections = max_db_connections
            if workers_per_db_connection is not None:
                self.status.workers_per_db_connection = workers_per_db_connection
            if task_queue_capacity is not None:
                self.status.task_queue_capacity = task_queue_capacity
            if writer_queue_capacity is not None:
                self.status.writer_queue_capacity = writer_queue_capacity

    def update_target_progress(self, *, processed: int | None = None, current_target: str = "", done: bool | None = None):
        with self._lock:
            if processed is not None:
                self.status.target_rules_processed = processed
            if current_target:
                self.status.current_target = current_target
            if done is not None:
                self.status.scheduling_done = done

    def update_runtime(
        self,
        *,
        running: int,
        queued: int,
        awaiting_db: int,
        submitted: int,
        completed: int,
        runtime_failures: int,
        task_queue_depth: int,
        writer_queue_depths: tuple[int, ...],
    ):
        with self._lock:
            self.status.running = running
            self.status.queued = queued
            self.status.awaiting_db = awaiting_db
            self.status.submitted = submitted
            self.status.completed = completed
            self.status.runtime_failures = runtime_failures
            self.status.task_queue_depth = task_queue_depth
            self.status.writer_queue_depths = writer_queue_depths

    def note_db_write(self, ip_text: str, writer_index: int):
        with self._lock:
            self.status.last_db_write_ip = ip_text
            self.status.last_db_writer = f"writer-{writer_index}"

    def handle_stream_text(self, text: str):
        clean_text = strip_ansi(text).replace("\r\n", "\n").replace("\r", "\n")
        if self._log_handle:
            self._log_handle.write(clean_text)
            self._log_handle.flush()

        with self._lock:
            self._partial_line += clean_text
            while "\n" in self._partial_line:
                line, remainder = self._partial_line.split("\n", 1)
                self._log_lines.append(line)
                self._partial_line = remainder

    def flush_stream_buffers(self):
        with self._lock:
            if self._partial_line:
                self._log_lines.append(self._partial_line)
                self._partial_line = ""

    def _open_logfile(self):
        if not self.logfile_path:
            return

        parent_dir = os.path.dirname(self.logfile_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
        self._log_handle = open(self.logfile_path, "a", encoding="utf-8")

    def _close_logfile(self):
        if self._log_handle:
            self._log_handle.close()
            self._log_handle = None

    def _try_start_tui(self):
        if not self.enable_tui:
            self._disable_tui("Blessed TUI disabled")
            return
        if not self._stdout_original.isatty():
            self._disable_tui("stdout is not a TTY")
            return

        try:
            import blessed
        except ImportError:
            self._disable_tui("blessed module unavailable; install blessed")
            return

        try:
            term = blessed.Terminal(stream=self._stdout_original)
            if not getattr(term, "is_a_tty", False):
                self._disable_tui("stdout is not a Blessed TTY")
                return
        except Exception as exc:
            self._disable_tui(f"blessed initialization failed: {exc}")
            return

        self._blessed = blessed
        self._term = term
        self._tui_active = True
        self._force_console_mirror = False
        self.status.ui_mode = "blessed"
        self._refresh_thread = threading.Thread(target=self._refresh_loop, name="orchestrator-ui", daemon=True)
        self._refresh_thread.start()

    def _stop_refresh_loop(self):
        self._stop_event.set()
        if self._refresh_thread:
            self._refresh_thread.join(timeout=2)
            self._refresh_thread = None

    def _close_tui(self):
        if not self._tui_active or self._term is None:
            return

        try:
            self._draw(final=True)
        except Exception:
            pass

        try:
            self._stdout_original.write(self._term.normal)
            self._stdout_original.flush()
        except Exception:
            pass

        self._tui_active = False
        self.status.ui_mode = "plain"
        self._term = None
        self._blessed = None

    def _refresh_loop(self):
        assert self._term is not None
        term = self._term
        try:
            with term.fullscreen(), term.hidden_cursor():
                while not self._stop_event.is_set():
                    try:
                        self._draw()
                    except Exception as exc:
                        self._disable_tui(f"Blessed refresh failed: {exc}")
                        break
                    time.sleep(0.1)
        except Exception as exc:
            self._disable_tui(f"Blessed fullscreen failed: {exc}")

    def _disable_tui(self, reason: str):
        self._fallback_reason = reason
        self._force_console_mirror = True
        self.status.ui_mode = "plain"
        if self._tui_active:
            self._tui_active = False
            try:
                if self._term is not None:
                    self._stdout_original.write(self._term.normal)
                    self._stdout_original.flush()
            except Exception:
                pass

    def _draw(self, final: bool = False):
        if not self._tui_active or self._term is None:
            return

        term = self._term
        width = max(int(getattr(term, "width", 0) or 0), 40)
        height = max(int(getattr(term, "height", 0) or 0), 6)

        with self._lock:
            status = UIStatus(**self.status.__dict__)
            log_lines = list(self._log_lines)
            partial_line = self._partial_line

        top_lines = self._build_top_lines(status, width)
        bottom_lines = self._build_bottom_lines(status, width, final=final)
        reserved_lines = len(top_lines) + len(bottom_lines)
        middle_height = max(height - reserved_lines, 1)

        visible_log_lines = log_lines[-middle_height:]
        if partial_line and len(visible_log_lines) < middle_height:
            visible_log_lines.append(partial_line)
        visible_log_lines = visible_log_lines[-middle_height:]

        output_parts = [term.home, term.clear]
        header_primary = self._style("black_on_bright_cyan") + self._style("bold")
        header_secondary = self._style("white_on_blue") + self._style("bold")
        footer_divider = self._style("bright_blue")
        footer_primary = self._style("black_on_yellow") + self._style("bold")
        footer_secondary = self._style("black_on_green")

        for row_index, line in enumerate(top_lines):
            style = header_primary if row_index == 0 else header_secondary
            output_parts.append(term.move_xy(0, row_index) + self._paint_line(line, width, style))

        middle_start = len(top_lines)
        for offset, line in enumerate(visible_log_lines):
            output_parts.append(term.move_xy(0, middle_start + offset) + self._format_log_line(line, width))

        bottom_start = height - len(bottom_lines)
        for offset, line in enumerate(bottom_lines):
            if offset == 0:
                painted = self._paint_line(line, width, footer_divider)
            elif offset == 1:
                painted = self._paint_line(line, width, footer_primary)
            else:
                painted = self._paint_line(line, width, footer_secondary)
            output_parts.append(term.move_xy(0, bottom_start + offset) + painted)

        output_parts.append(term.normal)
        self._stdout_original.write("".join(output_parts))
        self._stdout_original.flush()

    def _build_top_lines(self, status: UIStatus, width: int):
        elapsed = int(time.time() - status.started_at)
        header_left = (
            f"Scanner UI [{status.ui_mode}]  elapsed={elapsed}s  db={status.db_description or 'pending'}"
        )
        header_right = (
            f"workers={status.running}/{status.max_parallel}  writers={status.max_db_connections}"
        )
        progress_line = (
            f"rules={status.target_rules_processed}/{status.target_rules_total} "
            f"submitted={status.submitted} completed={status.completed} "
            f"queued={status.queued} awaiting_db={status.awaiting_db} failures={status.runtime_failures}"
        )
        return [
            self._compose_status_line(header_left, header_right, width),
            progress_line,
        ]

    def _build_bottom_lines(self, status: UIStatus, width: int, *, final: bool):
        writer_depths = ",".join(str(item) for item in status.writer_queue_depths) or "-"
        footer_left = (
            f"task_q={status.task_queue_depth}/{status.task_queue_capacity} "
            f"writer_q={writer_depths}/{status.writer_queue_capacity} "
            f"last_db={status.last_db_writer}:{status.last_db_write_ip or '-'}"
        )
        current_target = status.current_target or ("scheduling complete" if status.scheduling_done else "-")
        footer_right = f"target={current_target}"
        path_line = f"logfile={status.logfile_path or '-'}  evidence={status.evidence_dir or '-'}"
        if final:
            path_line = f"final status  {path_line}"
        return [
            self._divider(width, label=" status "),
            self._compose_status_line(footer_left, footer_right, width),
            path_line,
        ]

    @staticmethod
    def _fit_line(text: str, width: int):
        if width <= 1:
            return ""
        if len(text) <= width - 1:
            return text
        if width <= 4:
            return text[: width - 1]
        return text[: width - 4] + "..."

    def _compose_status_line(self, left: str, right: str, width: int):
        max_chars = max(width - 1, 1)
        if len(left) + len(right) + 1 <= max_chars:
            gap = max_chars - len(left) - len(right)
            return f"{left}{' ' * gap}{right}"
        return self._fit_line(f"{left} | {right}", width)

    def _format_log_line(self, text: str, width: int):
        raw = self._fit_line(text, width)
        if self._term is None:
            return raw

        styled = raw

        token_styles = [
            ("--->", self._style("green") + self._style("bold")),
            ("===>", self._style("green") + self._style("bold")),
            ("<===", self._style("magenta") + self._style("bold")),
            ("<---", self._style("magenta") + self._style("bold")),
            ("FAILED", self._style("red") + self._style("bold")),
            ("failed", self._style("red") + self._style("bold")),
            ("successful", self._style("green") + self._style("bold")),
            ("Skipping SSH", self._style("yellow") + self._style("bold")),
            ("Attempting SSH", self._style("cyan") + self._style("bold")),
            ("Attempting SNMP", self._style("cyan") + self._style("bold")),
            ("Verifying reachability", self._style("cyan")),
            ("Sweeping Subnet:", self._style("blue") + self._style("bold")),
            ("Database initialized:", self._style("yellow") + self._style("bold")),
            ("Evidence Directory Created:", self._style("yellow") + self._style("bold")),
            ("Logfile Created:", self._style("yellow") + self._style("bold")),
        ]

        for token, style in token_styles:
            styled = styled.replace(token, f"{style}{token}{self._term.normal}")

        ip_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

        def replace_ip(match):
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return candidate
            return f"{self._style('bright_white')}{self._style('bold')}{candidate}{self._term.normal}"

        styled = ip_pattern.sub(replace_ip, styled)
        return styled

    def _paint_line(self, text: str, width: int, style: str):
        if self._term is None:
            return self._fit_line(text, width)
        visible_width = max(width - 1, 1)
        fitted = self._fit_line(text, width)
        padded = fitted.ljust(visible_width)
        return f"{style}{padded}{self._term.normal}"

    def _divider(self, width: int, label: str = ""):
        visible_width = max(width - 1, 1)
        if not label:
            return "-" * visible_width

        label_text = f"[{label.strip()}]"
        if len(label_text) >= visible_width:
            return self._fit_line(label_text, width)

        remaining = visible_width - len(label_text)
        left = remaining // 2
        right = remaining - left
        return f"{'=' * left}{label_text}{'=' * right}"

    def _style(self, name: str):
        if self._term is None:
            return ""
        return getattr(self._term, name, "")
