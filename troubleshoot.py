#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from collections import deque

ERROR_WORDS = (
    "error",
    "failed",
    "failure",
    "critical",
    "timed out",
    "timeout",
    "connection refused",
    "upstream",
    "no space left",
    "permission denied",
    "out of memory",
)

WEB_SERVICES = ("apache2", "nginx")
LOG_FILES = (
    "/var/log/apache2/error.log",
    "/var/log/nginx/error.log",
)


def finding(name, status, evidence, next_step=None):
    return {
        "check": name,
        "status": status,
        "evidence": evidence,
        "next_step": next_step,
    }


def check_cpu_load():
    try:
        load = os.getloadavg()
        cpu_count = os.cpu_count() or 1

        return finding(
            "CPU load",
            "INFO",
            {
                "load_1m": round(load[0], 2),
                "load_5m": round(load[1], 2),
                "load_15m": round(load[2], 2),
                "logical_cpu_count": cpu_count,
                "one_minute_load_per_cpu": round(
                    load[0] / cpu_count, 2
                ),
            },
            "Inspect top/ps and CPU pressure if load is high."
            if load[0] > cpu_count else None,
        )
    except (OSError, AttributeError) as exc:
        return finding("CPU load", "INFO", str(exc))


def check_listening_ports():
    code, output = run_command(
        ["ss", "-ltn"], timeout=8
    )

    if code != 0:
        return finding(
            "Listening TCP ports", "INFO", output,
            "Check whether the ss command is available."
        )

    # Include listening ports, not full process details.
    listeners = [
        line.strip()
        for line in output.splitlines()[1:]
        if line.strip()
    ]

    return finding(
        "Listening TCP ports",
        "INFO",
        listeners,
        "Confirm expected web and application ports are listening."
    )

def check_dns(host):
    try:
        addresses = sorted({
            item[4][0]
            for item in socket.getaddrinfo(host, None)
        })
        return finding("DNS", "PASS", addresses)
    except socket.gaierror as exc:
        return finding(
            "DNS", "FAIL", str(exc),
            "Check domain spelling, DNS records and resolver."
        )


def check_http(url, timeout=10):
    start = time.monotonic()

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "WebsiteTroubleshooter/1.0"},
            method="GET",
        )

        # Default urllib redirect handling remains enabled.
        # TLS certificate verification remains enabled.
        with urllib.request.urlopen(
            request, timeout=timeout
        ) as response:
            status = response.status
            final_url = response.geturl()

        elapsed = round(time.monotonic() - start, 3)
        result_status = "PASS" if status < 400 else "WARNING"

        return finding(
            "HTTP",
            result_status,
            {
                "status_code": status,
                "final_url": final_url,
                "elapsed_seconds": elapsed,
            },
            None if status < 400 else
            "Inspect the response, redirects and application logs."
        )

    except urllib.error.HTTPError as exc:
        return finding(
            "HTTP", "WARNING",
            {
                "status_code": exc.code,
                "reason": str(exc.reason),
                "elapsed_seconds": round(
                    time.monotonic() - start, 3
                ),
            },
            "Investigate the HTTP status and relevant server logs."
        )

    except Exception as exc:
        return finding(
            "HTTP", "FAIL",
            {
                "error_type": type(exc).__name__,
                "message": str(exc),
                "elapsed_seconds": round(
                    time.monotonic() - start, 3
                ),
            },
            "Check DNS, network connectivity, TLS and timeout."
        )


def check_tls(host, port=443, timeout=5):
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, port), timeout=timeout
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=host
            ) as tls_socket:
                cert = tls_socket.getpeercert()

        expiry_text = cert.get("notAfter")
        if not expiry_text:
            return finding(
                "TLS", "WARNING",
                "Certificate expiry information unavailable."
            )

        expiry = dt.datetime.strptime(
            expiry_text, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=dt.timezone.utc)

        now = dt.datetime.now(dt.timezone.utc)
        days_left = (expiry - now).days

        status = "PASS" if days_left > 14 else "WARNING"

        return finding(
            "TLS", status,
            {
                "hostname": host,
                "expires_utc": expiry.isoformat(),
                "days_until_expiry": days_left,
            },
            "Verify certificate renewal and hostname configuration."
            if status == "WARNING" else None,
        )

    except Exception as exc:
        return finding(
            "TLS", "FAIL",
            {
                "error_type": type(exc).__name__,
                "message": str(exc),
            },
            "Check certificate validity, hostname, port and connectivity."
        )


def read_memory():
    info = {}

    try:
        with open("/proc/meminfo", encoding="utf-8") as file:
            for line in file:
                key, value = line.split(":", 1)
                info[key] = int(value.strip().split()[0]) * 1024

        total = info["MemTotal"]
        available = info.get("MemAvailable", info.get("MemFree", 0))
        used_percent = round((total - available) / total * 100, 1)

        return finding(
            "Memory", "WARNING" if used_percent >= 90 else "PASS",
            {
                "total_mb": round(total / (1024 ** 2), 1),
                "available_mb": round(available / (1024 ** 2), 1),
                "estimated_used_percent": used_percent,
            },
            "Inspect memory pressure and processes."
            if used_percent >= 90 else None,
        )
    except (OSError, ValueError, KeyError) as exc:
        return finding("Memory", "WARNING", str(exc))


def check_disk():
    usage = shutil.disk_usage("/")
    used_percent = round(usage.used / usage.total * 100, 1)

    status = "WARNING" if used_percent >= 85 else "PASS"

    result = finding(
        "Root filesystem",
        status,
        {
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "used_gb": round(usage.used / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "used_percent": used_percent,
        },
        "Identify large files and check safe cleanup options."
        if status == "WARNING" else None,
    )

    # Check inode usage on Linux when available.
    try:
        stat = os.statvfs("/")
        total_inodes = stat.f_files
        free_inodes = stat.f_ffree

        if total_inodes:
            inode_percent = round(
                (total_inodes - free_inodes) / total_inodes * 100, 1
            )
            result["evidence"]["inode_used_percent"] = inode_percent

            if inode_percent >= 90:
                result["status"] = "WARNING"
                result["next_step"] = (
                    "Inspect inode usage; do not delete files blindly."
                )
    except OSError:
        pass

    return result


def run_command(args, timeout=8):
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def check_service(service):
    code, output = run_command(
        ["systemctl", "is-active", service]
    )

    if code == 0 and output == "active":
        return finding("Service: " + service, "PASS", output)

    if output in ("inactive", "failed", "activating", "deactivating"):
        return finding(
            "Service: " + service, "WARNING", output,
            "Confirm whether this service should be running for this host."
        )

    return finding(
        "Service: " + service, "INFO", output or "No status returned",
        "Verify service name and systemd availability."
    )


def check_recent_logs():
    results = []

    # Read a bounded number of recent lines only.
    for log_path in LOG_FILES:
        path = Path(log_path)

        if not path.is_file():
            continue

        try:
            with path.open(
                "r", encoding="utf-8", errors="replace"
            ) as file:
                lines = file.readlines()[-100:]

            matches = [
                line.strip()[:300]
                for line in lines
                if any(word in line.lower() for word in ERROR_WORDS)
            ]

            results.append({
                "file": str(path),
                "lines_scanned": len(lines),
                "matching_line_count": len(matches),
                # Samples may contain sensitive information.
                "samples": matches[-5:],
            })

        except OSError as exc:
            results.append({
                "file": str(path),
                "error": str(exc),
            })

    if not results:
        return finding(
            "Web server logs", "INFO",
            "No standard Apache/Nginx error log was readable or found.",
            "Check the domain's configured vhost and log paths."
        )

    has_matches = any(
        item.get("matching_line_count", 0) > 0
        for item in results
    )

    return finding(
        "Web server logs",
        "WARNING" if has_matches else "INFO",
        results,
        "Correlate log timestamps with the reported incident."
        if has_matches else "Check application and systemd logs if needed."
    )


def diagnose(url):
    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "Provide a valid HTTP/HTTPS URL without embedded credentials."
        )

    host = parsed.hostname

    report = {
        "generated_at_utc": dt.datetime.now(
            dt.timezone.utc
        ).isoformat(),
        "target_url": url,
        "local_host": socket.gethostname(),
        "scope_warning": (
            "Local server checks describe this machine only. "
            "They do not prove it hosts the target website."
        ),
        "checks": [],
    }

    report["checks"].append(check_dns(host))
    report["checks"].append(check_http(url))

    if parsed.scheme == "https":
        port = parsed.port or 443
        report["checks"].append(check_tls(host, port))

    report["checks"].append(check_disk())
    report["checks"].append(read_memory())
    report["checks"].append(check_cpu_load())
    report["checks"].append(check_listening_ports())

    for service in WEB_SERVICES:
        report["checks"].append(check_service(service))

    report["checks"].append(check_recent_logs())

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Read-only website and Linux diagnostics."
    )
    parser.add_argument("url", help="Full HTTP/HTTPS website URL")
    parser.add_argument(
        "--output",
        default="reports",
        help="Report directory (default: reports)",
    )
    args = parser.parse_args()

    try:
        report = diagnose(args.url)
    except ValueError as exc:
        parser.error(str(exc))

    checks = report["checks"]

    critical_checks = {"DNS", "HTTP"}
    if any(
        check["check"] in critical_checks
        and check["status"] == "FAIL"
        for check in checks
    ):
        overall_status = "CRITICAL"
    elif any(
        check["status"] in {"WARNING", "FAIL"}
        for check in checks
    ):
        overall_status = "WARNING"
    else:
        overall_status = "HEALTHY"

    report["overall_status"] = overall_status

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = output_dir / f"incident-{stamp}.json"

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    try:
        report_path.chmod(0o600)
    except OSError:
        pass

    print(f"\nWebsite Troubleshooter: {args.url}")
    print(f"Overall Status: {report['overall_status']}")
    print("-" * 60)

    for check in report["checks"]:
        print(f"[{check['status']:<7}] {check['check']}")
        print(f"          {json.dumps(check['evidence'])}")
        if check.get("next_step"):
            print(f"          Next: {check['next_step']}")

    print("-" * 60)
    print(f"Report saved locally: {report_path}")
    print("Review sensitive report contents before sharing.")


if __name__ == "__main__":
    main()