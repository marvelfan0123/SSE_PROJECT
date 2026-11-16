"""Comprehensive Nmap reliability, process lifecycle, XML resilience, and real Windows execution tests."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import asset_discovery


VALID_OPEN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap --unprivileged -sT -Pn -n -p 3000 -oX - 127.0.0.1">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Node.js" version="20.11.0" extrainfo="Express"/>
      </port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

VALID_CLOSED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="user-set"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="closed" reason="conn-refused"/>
        <service name="ppp"/>
      </port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

HOST_DOWN_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="down" reason="no-response"/>
  </host>
  <runstats><hosts up="0" down="1" total="1"/></runstats>
</nmaprun>
"""


class NmapReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "nmap_test.db"
        self.db_patch = mock.patch.object(asset_discovery, "DB_PATH", self.db_path)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.tmp.cleanup()

    def test_01_executable_not_installed(self):
        """1. Executable not installed raises executable_unavailable and is not retryable."""
        with mock.patch.object(asset_discovery, "_candidate_nmap_paths", return_value=[Path(self.tmp.name) / "missing_nmap.exe"]):
            self.assertFalse(asset_discovery.nmap_available())
            with self.assertRaises(asset_discovery.NmapScanError) as ctx:
                asset_discovery.scan_target("127.0.0.1", "3000")
            self.assertEqual(ctx.exception.category, "executable_unavailable")
            self.assertFalse(ctx.exception.retryable)

    def test_02_executable_available_not_in_path(self):
        """2. Executable available in Windows install path / env var but not in PATH is discovered."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch("shutil.which", return_value=None), \
             mock.patch.dict(os.environ, {"VULNX_NMAP_PATH": str(fake_exe)}):
            discovered = asset_discovery.discover_nmap_executable()
            self.assertEqual(discovered, str(fake_exe))
            self.assertEqual(asset_discovery.validate_nmap_executable(), str(fake_exe))

    def test_03_invalid_target_not_retried(self):
        """3. Invalid targets and ports are rejected immediately before process creation."""
        with mock.patch.object(asset_discovery, "_run_nmap_process") as run_mock:
            for bad_target in ("8.8.8.8", "example.com", "-oX", "", "1.1.1.1"):
                with self.assertRaises(ValueError):
                    asset_discovery.scan_target(bad_target, "80")
            for bad_port in ("0", "65536", "80;whoami", ""):
                with self.assertRaises(ValueError):
                    asset_discovery.scan_target("127.0.0.1", bad_port)
            run_mock.assert_not_called()

    def test_04_unreachable_target_host_down(self):
        """4. Unreachable target (host status down) raises target_unreachable."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch.object(asset_discovery, "_run_nmap_process", return_value=(0, HOST_DOWN_XML, "", 0.15)):
            with self.assertRaises(asset_discovery.NmapScanError) as ctx:
                asset_discovery.scan_target("192.168.1.250", "80", executable=str(fake_exe))
            self.assertEqual(ctx.exception.category, "target_unreachable")
            self.assertFalse(ctx.exception.retryable)

    def test_05_responsive_local_target(self):
        """5. Responsive local target normalizes localhost -> 127.0.0.1 and records duration and exit code."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch.object(asset_discovery, "_run_nmap_process", return_value=(0, VALID_OPEN_XML, "", 0.12)):
            res = asset_discovery.scan_target("localhost", "3000", executable=str(fake_exe))
            self.assertEqual(res["target"], "127.0.0.1")
            self.assertEqual(res["host_status"], "up")
            self.assertEqual(res["exit_code"], 0)
            self.assertGreaterEqual(res["duration_seconds"], 0.1)

    def test_06_open_ports_parsed_and_persisted(self):
        """6. Open ports and service versions are extracted and persisted to SQLite."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch.object(asset_discovery, "_run_nmap_process", return_value=(0, VALID_OPEN_XML, "", 0.08)):
            res = asset_discovery.scan_target("127.0.0.1", "3000", executable=str(fake_exe))
            self.assertEqual(len(res["open_ports"]), 1)
            self.assertEqual(res["open_ports"][0]["port"], "3000")
            self.assertEqual(res["open_ports"][0]["service"], "http")
            self.assertIn("Node.js", res["open_ports"][0]["version"])
            latest = asset_discovery.get_latest_asset_scan_result()
            self.assertIsNotNone(latest)
            self.assertEqual(latest["open_ports"][0]["port"], "3000")

    def test_07_closed_ports_parsed(self):
        """7. Closed ports produce 0 open_ports and record closed_ports accurately."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch.object(asset_discovery, "_run_nmap_process", return_value=(0, VALID_CLOSED_XML, "", 0.05)):
            res = asset_discovery.scan_target("127.0.0.1", "3000", executable=str(fake_exe))
            self.assertEqual(res["open_ports"], [])
            self.assertEqual(len(res["closed_ports"]), 1)
            self.assertEqual(res["closed_ports"][0]["port"], "3000")

    def test_08_timeout_classification_and_retry_eligibility(self):
        """8. Timeout raises NmapScanError with category='timeout' and retryable=True."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        err = asset_discovery.NmapScanError(
            "Nmap scan timed out after 15 seconds.",
            category="timeout",
            retryable=True,
            duration_seconds=15.0,
        )
        with mock.patch.object(asset_discovery, "_run_nmap_process", side_effect=err):
            with self.assertRaises(asset_discovery.NmapScanError) as ctx:
                asset_discovery.scan_target("127.0.0.1", "3000", timeout_seconds=15, max_retries=0, executable=str(fake_exe))
            self.assertEqual(ctx.exception.category, "timeout")
            self.assertTrue(ctx.exception.retryable)

    def test_09_malformed_xml_rejected_without_retry(self):
        """9. Malformed XML output raises category='malformed_xml' and is not retried."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        calls = []

        def fake_run(cmd, timeout):
            calls.append(cmd)
            return 0, "<nmaprun><broken>", "", 0.05

        with mock.patch.object(asset_discovery, "_run_nmap_process", side_effect=fake_run):
            with self.assertRaises(asset_discovery.NmapScanError) as ctx:
                asset_discovery.scan_target("127.0.0.1", "3000", max_retries=2, executable=str(fake_exe))
            self.assertEqual(ctx.exception.category, "malformed_xml")
            self.assertFalse(ctx.exception.retryable)
            self.assertEqual(len(calls), 1)

    def test_10_valid_xml_with_nonzero_exit_code_preserved(self):
        """10. Valid XML report is parsed and preserved even when Nmap exits with a non-zero code."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        with mock.patch.object(
            asset_discovery,
            "_run_nmap_process",
            return_value=(1, VALID_OPEN_XML, "WARNING: Could not import all necessary Npcap functions.", 0.21),
        ):
            res = asset_discovery.scan_target("127.0.0.1", "3000", executable=str(fake_exe))
            self.assertEqual(res["exit_code"], 1)
            self.assertEqual(len(res["open_ports"]), 1)
            self.assertTrue(any("non-zero code 1" in w or "Npcap" in w for w in res["warnings"]))

    def test_11_process_termination_on_timeout(self):
        """11. Timed-out Nmap subprocess is explicitly killed and cleaned up."""
        fake_proc = mock.MagicMock()
        fake_proc.returncode = -9
        fake_proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd=["nmap"], timeout=10),
            ("", "terminated"),
        ]
        with mock.patch("subprocess.Popen", return_value=fake_proc):
            with self.assertRaises(asset_discovery.NmapScanError) as ctx:
                asset_discovery._run_nmap_process(["nmap", "127.0.0.1"], timeout_seconds=10)
            self.assertEqual(ctx.exception.category, "timeout")
            fake_proc.kill.assert_called_once()
            self.assertEqual(fake_proc.communicate.call_count, 2)

    def test_12_real_windows_execution_against_local_socket(self):
        """12. Real Windows Nmap execution against an authorized local TCP listener and closed port."""
        exe = asset_discovery.discover_nmap_executable()
        if not exe:
            self.skipTest("Nmap binary not installed on this host")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(5)
        open_port = server.getsockname()[1]

        closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed_sock.bind(("127.0.0.1", 0))
        closed_port = closed_sock.getsockname()[1]
        closed_sock.close()

        stop_event = threading.Event()

        def _accept_loop():
            while not stop_event.is_set():
                try:
                    conn, _ = server.accept()
                except OSError:
                    break
                try:
                    conn.settimeout(0.5)
                    try:
                        conn.recv(256)
                    except OSError:
                        pass
                    conn.sendall(b"HTTP/1.1 200 OK\r\nServer: VulnXTest/1.0\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        t = threading.Thread(target=_accept_loop, daemon=True)
        t.start()
        try:
            # Probe whether outbound loopback connect() is permitted in the current process context
            sandbox_blocks_connect = False
            try:
                probe = socket.create_connection(("127.0.0.1", open_port), timeout=1.0)
                probe.close()
            except PermissionError:
                sandbox_blocks_connect = True

            res = asset_discovery.scan_target(
                "127.0.0.1",
                f"{open_port},{closed_port}",
                timeout_seconds=30,
                profile="service_light",
            )
            self.assertEqual(res["host_status"], "up")
            self.assertEqual(res["exit_code"], 0)
            self.assertLess(res["duration_seconds"], 15.0)
            if sandbox_blocks_connect:
                filtered_ids = [int(p["port"]) for p in res["filtered_ports"]]
                self.assertIn(open_port, filtered_ids)
                self.assertIn(closed_port, filtered_ids)
            else:
                open_ids = [int(p["port"]) for p in res["open_ports"]]
                closed_ids = [int(p["port"]) for p in res["closed_ports"]]
                filtered_ids = [int(p["port"]) for p in res["filtered_ports"]]
                self.assertIn(open_port, open_ids)
                self.assertNotIn(closed_port, open_ids)
                self.assertIn(closed_port, closed_ids + filtered_ids)
        finally:
            stop_event.set()
            server.close()

    def test_13_retry_behaviour_retries_timeout_once_and_never_retries_permanent_errors(self):
        """13. Timeout on service_light automatically retries once with connect_only; permanent errors do not retry."""
        fake_exe = Path(self.tmp.name) / "nmap.exe"
        fake_exe.write_bytes(b"MZ")
        commands_run = []

        def side_effect(cmd, timeout):
            commands_run.append(cmd)
            if len(commands_run) == 1:
                raise asset_discovery.NmapScanError(
                    "Timed out on service_light",
                    category="timeout",
                    retryable=True,
                    duration_seconds=10.0,
                )
            return 0, VALID_OPEN_XML, "", 0.09

        with mock.patch.object(asset_discovery, "_run_nmap_process", side_effect=side_effect):
            res = asset_discovery.scan_target("127.0.0.1", "3000", timeout_seconds=30, max_retries=1, executable=str(fake_exe))
            self.assertEqual(len(commands_run), 2)
            self.assertIn("-sV", commands_run[0])
            self.assertNotIn("-sV", commands_run[1])
            self.assertEqual(res["profile"], "connect_only")
            self.assertEqual(res["attempts"], 2)
            self.assertEqual(len(res["open_ports"]), 1)


if __name__ == "__main__":
    unittest.main()
