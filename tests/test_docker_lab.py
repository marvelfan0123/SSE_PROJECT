import json
import unittest
from unittest.mock import patch

import docker_lab


class DockerLabTests(unittest.TestCase):
    def test_parse_container_lines_ignores_invalid_lines(self):
        output = '\n'.join([
            json.dumps({"ID": "abc", "Names": "juice-shop", "Image": "bkimminich/juice-shop", "Status": "Up 2 hours", "Ports": "127.0.0.1:3000->3000/tcp", "State": "running"}),
            "not-json",
            "",
        ])
        containers = docker_lab._parse_container_lines(output)
        self.assertEqual(len(containers), 1)
        self.assertEqual(containers[0]["name"], "juice-shop")
        self.assertEqual(containers[0]["state"], "running")

    def test_parse_container_lines_handles_none_output(self):
        self.assertEqual(docker_lab._parse_container_lines(None), [])

    def test_list_containers_decodes_output_with_replacement_errors(self):
        fake = type("Completed", (), {"returncode": 0, "stdout": '{"Names":"juice-shop","State":"running"}\n', "stderr": ""})()
        with patch.object(docker_lab, "docker_available", return_value=True), patch.object(docker_lab.subprocess, "run", return_value=fake) as run:
            result = docker_lab.list_containers()
        self.assertEqual(result[0]["name"], "juice-shop")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")

    def test_list_containers_uses_fixed_command_without_shell(self):
        fake = type("Completed", (), {"returncode": 0, "stdout": '{"Names":"dvwa","State":"running"}\n', "stderr": ""})()
        with patch.object(docker_lab, "docker_available", return_value=True), patch.object(docker_lab.subprocess, "run", return_value=fake) as run:
            result = docker_lab.list_containers()
        self.assertEqual(result[0]["name"], "dvwa")
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        self.assertEqual(run.call_args.args[0][:3], ["docker", "ps", "-a"])

    def test_http_probe_rejects_unconfigured_url(self):
        with self.assertRaises(ValueError):
            docker_lab.check_local_http("http://example.com/")

    def test_get_lab_status_summarizes_expected_services(self):
        containers = [
            {"id": "1", "name": "juice-shop", "image": "bkimminich/juice-shop", "status": "Up", "ports": "3000", "state": "running"}
        ]
        with patch.object(docker_lab, "list_containers", return_value=containers), patch.object(
            docker_lab, "check_local_http", side_effect=[
                {"url": "http://127.0.0.1:3000/", "reachable": True, "status_code": 200, "detail": "HTTP response received"},
                {"url": "http://127.0.0.1:8081/", "reachable": False, "status_code": None, "detail": "refused"},
            ]
        ):
            result = docker_lab.get_lab_status()
        self.assertEqual(result["container_count"], 1)
        self.assertEqual(result["running_count"], 1)
        self.assertTrue(result["services"][0]["http_reachable"])
        self.assertFalse(result["services"][1]["http_reachable"])


if __name__ == "__main__":
    unittest.main()
