
import unittest
from unittest.mock import patch

import troubleshoot


class TestWebsiteTroubleshooter(unittest.TestCase):

    def test_finding_structure(self):
        result = troubleshoot.finding(
            "DNS", "PASS", ["127.0.0.1"]
        )

        self.assertEqual(result["check"], "DNS")
        self.assertEqual(result["status"], "PASS")
        self.assertIn("evidence", result)

    def test_invalid_scheme_rejected(self):
        with self.assertRaises(ValueError):
            troubleshoot.diagnose("ftp://example.com")

    def test_missing_hostname_rejected(self):
        with self.assertRaises(ValueError):
            troubleshoot.diagnose("https://")

    @patch("troubleshoot.shutil.disk_usage")
    def test_disk_warning_threshold(self, mock_disk):
        # Simulate a filesystem that is 90% full.
        mock_disk.return_value = type(
            "Usage", (),
            {"total": 1000, "used": 900, "free": 100}
        )()

        result = troubleshoot.check_disk()

        self.assertEqual(result["status"], "WARNING")
        self.assertEqual(
            result["evidence"]["used_percent"], 90.0
        )

    @patch("troubleshoot.socket.getaddrinfo")
    def test_dns_failure(self, mock_dns):
        import socket
        mock_dns.side_effect = socket.gaierror("DNS lookup failed")

        result = troubleshoot.check_dns("invalid.example")

        self.assertEqual(result["status"], "FAIL")

    @patch("troubleshoot.urllib.request.urlopen")
    def test_http_200(self, mock_urlopen):
        response = mock_urlopen.return_value.__enter__.return_value
        response.status = 200
        response.geturl.return_value = "https://example.com"

        result = troubleshoot.check_http("https://example.com")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["evidence"]["status_code"], 200)


if __name__ == "__main__":
    unittest.main()
