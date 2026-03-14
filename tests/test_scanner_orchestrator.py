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

import module_ssh
import process_single_ip
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


class ProcessSingleIpSshPortTests(unittest.TestCase):
    def test_build_ssh_credentials_includes_default_and_custom_ports(self):
        request = process_single_ip.SingleIPScanRequest(ip="192.0.2.10", keytags=("site_a",))
        keys_data = {
            "site_a": {
                "ssh_password": [
                    {"username": "admin", "password": "pw"},
                    {"username": "alt", "password": "pw2", "port": 2222},
                ],
                "ssh_key": [
                    {"username": "automation", "key_file": "id_rsa"},
                ],
            }
        }

        credentials = process_single_ip.build_ssh_credentials(request, keys_data)

        self.assertEqual(credentials[0]["credential_ref"], "site_a:p0")
        self.assertEqual(credentials[0]["params"]["port"], 22)
        self.assertEqual(credentials[1]["credential_ref"], "site_a:p1")
        self.assertEqual(credentials[1]["params"]["port"], 2222)
        self.assertEqual(credentials[2]["credential_ref"], "site_a:k0")
        self.assertEqual(credentials[2]["params"]["port"], 22)

    def test_verify_reachability_checks_candidate_ssh_ports(self):
        request = process_single_ip.SingleIPScanRequest(ip="192.0.2.20", keytags=("site_a",))
        pipeline = process_single_ip.SingleIPPipeline(
            keys_data={
                "site_a": {
                    "ssh_password": [
                        {"username": "admin", "password": "pw"},
                        {"username": "jump", "password": "pw2", "port": 2222},
                    ]
                }
            },
            ssh_commands_data={},
            evidence_dir=".",
        )

        with patch("process_single_ip.module_ping.ping_host", return_value={"is_alive": False}), patch(
            "process_single_ip.module_portscan.check_tcp_port",
            side_effect=lambda ip, port: {"ip_address": ip, "port": port, "is_open": port == 2222},
        ) as check_tcp_port:
            result = pipeline._verify_reachability(request)

        self.assertFalse(result.ping_responded)
        self.assertTrue(result.ssh_port_open)
        self.assertTrue(result.is_alive)
        self.assertEqual(
            [call.kwargs["port"] for call in check_tcp_port.call_args_list],
            [22, 2222],
        )


class ModuleSshPortTests(unittest.TestCase):
    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def settimeout(self, timeout):
            self.timeout = timeout

        def recv(self, size):
            if hasattr(self, "_sent"):
                return b""
            self._sent = True
            return b"SSH-2.0-test\r\n"

    class _FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def enable(self):
            return None

        def send_command(self, command):
            return f"output for {command}"

    def test_probe_ssh_banner_uses_supplied_port(self):
        with patch("module_ssh.socket.create_connection", return_value=self._FakeSocket()) as create_connection:
            banner_ok, banner_detail = module_ssh._probe_ssh_banner("192.0.2.30", 2222, 5)

        self.assertTrue(banner_ok)
        self.assertIsNone(banner_detail)
        create_connection.assert_called_once_with(("192.0.2.30", 2222), timeout=5)

    def test_gather_configs_passes_custom_port_to_netmiko(self):
        temp_dir = os.path.join(PROJECT_ROOT, "tests", f"tmp_{uuid.uuid4().hex}")
        os.makedirs(temp_dir, exist_ok=False)

        try:
            with patch(
                "module_ssh._probe_ssh_banner",
                return_value=(True, None),
            ), patch(
                "module_ssh.ConnectHandler",
                return_value=self._FakeConnection(),
            ) as connect_handler:
                result = module_ssh.gather_configs(
                    "192.0.2.40",
                    {"username": "admin", "password": "pw", "port": 2222},
                    temp_dir,
                    device_type="cisco_ios",
                    commands_to_run=["show version"],
                )

            self.assertEqual(result["status"], "success")
            self.assertTrue(os.path.exists(result["evidence_file_path"]))
            self.assertEqual(connect_handler.call_args.kwargs["port"], 2222)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
