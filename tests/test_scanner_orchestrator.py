import os
import shutil
import sys
import unittest
import uuid
from argparse import Namespace
from unittest.mock import patch


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_ROOT = os.path.join(PROJECT_ROOT, "src")

if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

import scanner_orchestrator


class ScannerOrchestratorNmapGuardTests(unittest.TestCase):
    def test_require_nmap_skips_single_ip_cidr_notation(self):
        specs = [
            scanner_orchestrator.TargetSpec(
                row_index=1,
                raw_target="192.0.2.10/32",
                network=scanner_orchestrator.ipaddress.ip_network("192.0.2.10/32"),
                keytags=(),
            )
        ]

        with patch(
            "scanner_orchestrator.module_portscan.ensure_nmap_available",
            side_effect=AssertionError("nmap check should not run for single IP targets"),
        ):
            scanner_orchestrator.require_nmap_for_subnet_sweeps(specs)

    def test_run_orchestrator_exits_before_db_init_when_subnet_needs_nmap(self):
        temp_dir = os.path.join(PROJECT_ROOT, "tests", f"tmp_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=False)

        try:
            targets_path = os.path.join(temp_dir, "targets.csv")
            keys_path = os.path.join(temp_dir, "keys.yaml")
            ssh_commands_path = os.path.join(temp_dir, "ssh_commands.yaml")
            dbconfig_path = os.path.join(temp_dir, "db.yaml")

            with open(targets_path, "w", encoding="utf-8") as handle:
                handle.write("ip_or_subnet,keytag1\n192.0.2.0/24,site_a\n")
            with open(keys_path, "w", encoding="utf-8") as handle:
                handle.write("site_a: {}\n")
            with open(ssh_commands_path, "w", encoding="utf-8") as handle:
                handle.write("cisco_ios: {}\n")
            with open(dbconfig_path, "w", encoding="utf-8") as handle:
                handle.write("db: {}\n")

            args = Namespace(
                targets=targets_path,
                keys=keys_path,
                ssh_commands=ssh_commands_path,
                evidence_dir=os.path.join(temp_dir, "scan_results"),
                dbconfig=dbconfig_path,
                max_workers_per_db_connection=1,
                max_db_connections=1,
            )

            with patch(
                "scanner_orchestrator.module_portscan.ensure_nmap_available",
                side_effect=RuntimeError("nmap missing"),
            ), patch(
                "scanner_orchestrator.load_db_config",
                side_effect=AssertionError("DB config should not load before nmap validation"),
            ):
                with self.assertRaises(SystemExit) as ctx:
                    scanner_orchestrator.run_orchestrator(
                        args,
                        ui=None,
                        evidence_dir=os.path.join(temp_dir, "evidence_run"),
                    )

            message = str(ctx.exception)
            self.assertIn("subnet sweep target", message)
            self.assertIn("nmap", message)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
