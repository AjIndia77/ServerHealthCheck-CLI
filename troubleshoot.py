#!/usr/bin/env python3
import re
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

DB_CPU_THRESHOLD = 50.0  # % of one core

DB_PROCESS_MAP = {
    "mysqld": "MySQL/MariaDB",
    "mariadbd": "MySQL/MariaDB",
    "postgres": "PostgreSQL",
    "mongod": "MongoDB",
    "redis-server": "Redis",
}

DB_SERVICE_MAP = {
    "MySQL/MariaDB": ("mysql", "mariadb", "mysqld"),
    "PostgreSQL": ("postgresql",),
    "MongoDB": ("mongod",),
    "Redis": ("redis-server", "redis"),
}

DB_PORTS = {
    "MySQL/MariaDB": 3306,
    "PostgreSQL": 5432,
    "MongoDB": 27017,
    "Redis": 6379,
}


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
            "Memory", "WARNING" if used_percent >= 85 else "PASS",
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


def check_apache_workers():
    """Read-only Apache process and worker-capacity check."""
    code, output = run_command(
        ["ps", "-eo", "pid=,ppid=,comm=,args="]
    )

    if code != 0:
        return finding(
            "Apache workers", "INFO", output,
            "Check whether ps is available."
        )

    processes = []
    for line in output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue

        pid, ppid, comm = parts[:3]
        args = parts[3] if len(parts) > 3 else ""

        if comm in ("apache2", "httpd"):
            processes.append({
                "pid": int(pid),
                "ppid": int(ppid),
                "args": args,
            })

    if not processes:
        return finding(
            "Apache workers", "INFO",
            {"process_count": 0},
            "Apache processes were not detected on this machine."
        )

    pids = {proc["pid"] for proc in processes}
    masters = [
        proc for proc in processes if proc["ppid"] not in pids
    ]
    worker_count = len(processes) - len(masters)

    # Read common Apache MPM configuration locations.
    config_paths = [
        Path("/etc/apache2"),
        Path("/etc/httpd"),
    ]
    max_workers_values = []

    for base in config_paths:
        if not base.is_dir():
            continue

        try:
            for path in base.rglob("*.conf"):
                try:
                    # Skip unusually large config files.
                    if path.stat().st_size > 1_000_000:
                        continue
                    content = path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue

                for match in re.finditer(
                    r"(?im)^\s*MaxRequestWorkers\s+(\d+)\b",
                    content,
                ):
                    max_workers_values.append({
                        "file": str(path),
                        "value": int(match.group(1)),
                    })
        except OSError:
            pass

    evidence = {
        "process_count": len(processes),
        "detected_master_count": len(masters),
        "estimated_worker_process_count": worker_count,
        "configured_max_request_workers": max_workers_values,
        "note": (
            "Process count is a snapshot, not a count of busy requests. "
            "Included configuration values may not all be active."
        ),
    }

    status = "PASS"
    next_step = None

    # Warn only when one detected configured limit is reached.
    if any(
        worker_count >= item["value"]
        for item in max_workers_values
        if item["value"] > 0
    ):
        status = "WARNING"
        next_step = (
            "Verify the active Apache MPM configuration and inspect "
            "server-status or Apache logs for worker saturation."
        )

    return finding(
        "Apache workers", status, evidence, next_step
    )


def check_php_fpm_workers():
    """Read-only PHP-FPM process and configured capacity check."""
    code, output = run_command(
        ["ps", "-eo", "pid=,ppid=,comm=,args="]
    )

    if code != 0:
        return finding(
            "PHP-FPM workers", "INFO", output,
            "Check whether ps is available."
        )

    processes = []
    for line in output.splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) < 3:
            continue

        pid, ppid, comm = parts[:3]
        args = parts[3] if len(parts) > 3 else ""

        if "php-fpm" in comm.lower() or "php-fpm:" in args.lower():
            processes.append({
                "pid": int(pid),
                "ppid": int(ppid),
                "comm": comm,
                "args": args,
            })

    worker_processes = [
        proc for proc in processes
        if "pool " in proc["args"].lower()
    ]

    # Read common PHP-FPM pool configuration files.
    config_values = []
    for base in (Path("/etc/php"), Path("/etc/php-fpm.d")):
        if not base.is_dir():
            continue

        try:
            for path in base.rglob("*.conf"):
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                    content = path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue

                pool = "unknown"
                section = re.search(
                    r"(?m)^\s*\[([^\]]+)\]\s*$", content
                )
                if section:
                    pool = section.group(1).strip()

                max_children = re.search(
                    r"(?m)^\s*pm\.max_children\s*=\s*(\d+)\s*$",
                    content,
                )
                if max_children:
                    config_values.append({
                        "file": str(path),
                        "pool": pool,
                        "pm.max_children": int(max_children.group(1)),
                    })
        except OSError:
            pass

    if not processes and not config_values:
        return finding(
            "PHP-FPM workers", "INFO",
            {
                "process_count": 0,
                "configured_pools_found": 0,
            },
            "PHP-FPM was not detected. The server may use mod_php "
            "or may not run PHP-FPM locally."
        )

    evidence = {
        "php_fpm_process_count": len(processes),
        "detected_pool_worker_count": len(worker_processes),
        "configured_pool_limits": config_values,
        "busy_idle_counts": (
            "Not available from process listing alone; use a "
            "properly secured PHP-FPM status interface."
        ),
    }

    status = "PASS"
    next_step = None

    # Only compare when there is exactly one configured pool limit;
    # multi-pool process counts cannot be safely compared as a group.
    if len(config_values) == 1:
        limit = config_values[0]["pm.max_children"]
        if limit > 0 and len(worker_processes) >= limit:
            status = "WARNING"
            next_step = (
                "Check PHP-FPM pool status and logs to confirm whether "
                "the pool has reached pm.max_children."
            )

    return finding(
        "PHP-FPM workers", status, evidence, next_step
    )

def read_cpu_ticks(pid):
    """Return utime+stime ticks for a PID from /proc, or None."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as file:
            data = file.read()
        # comm can contain spaces, so split after the last ')'.
        fields = data.rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])
    except (OSError, IndexError, ValueError):
        return None


def detect_databases(sample_seconds=1.0):
    """Detect running DB engines and measure their live CPU usage."""
    code, output = run_command(["ps", "-eo", "pid=,comm="])
    if code != 0:
        return None, output

    engines = {}
    for line in output.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid, comm = int(parts[0]), parts[1].strip()
        engine = DB_PROCESS_MAP.get(comm)
        if engine:
            engines.setdefault(engine, []).append(pid)

    # Two samples of CPU ticks = current CPU usage, not lifetime average.
    before = {
        pid: read_cpu_ticks(pid)
        for pids in engines.values() for pid in pids
    }
    start = time.monotonic()
    time.sleep(sample_seconds)
    elapsed = time.monotonic() - start
    clk = os.sysconf("SC_CLK_TCK")

    result = {}
    for engine, pids in engines.items():
        total = 0.0
        for pid in pids:
            a, b = before.get(pid), read_cpu_ticks(pid)
            if a is not None and b is not None:
                total += (b - a) / clk / elapsed * 100
        result[engine] = {
            "pids": pids,
            "cpu_percent": round(total, 1),
        }
    return result, None


def check_database_status(databases, error=None):
    if databases is None:
        return finding(
            "Database detection", "INFO", error,
            "Check whether ps is available."
        )

    if not databases:
        return finding(
            "Database detection", "INFO",
            "No MySQL/MariaDB, PostgreSQL, MongoDB or Redis "
            "process found on this machine.",
            "Database may be remote (RDS, another server) or "
            "use a different engine."
        )

    details = []
    status = "PASS"
    next_step = None

    for engine, info in databases.items():
        # 1) systemd view
        service_state = "unknown"
        for name in DB_SERVICE_MAP[engine]:
            code, out = run_command(["systemctl", "is-active", name])
            if out in ("active", "inactive", "failed",
                       "activating", "deactivating"):
                service_state = f"{name}: {out}"
                if out == "active":
                    break

        # 2) Port view
        port = DB_PORTS[engine]
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=2
            ):
                port_open = True
        except OSError:
            port_open = False

        # 3) Engine-level ping (works only if auth allows it)
        ping = "not tested"
        if engine == "MySQL/MariaDB" and shutil.which("mysqladmin"):
            code, out = run_command(
                ["mysqladmin", "--connect-timeout=3", "ping"]
            )
            ping = out[:200]
        elif engine == "PostgreSQL" and shutil.which("pg_isready"):
            code, out = run_command(["pg_isready", "-t", "3"])
            ping = out[:200]

        if not port_open or "active" not in service_state.split(": ")[-1:]:
            if not port_open:
                status = "WARNING"
                next_step = (
                    "Process exists but port is not accepting "
                    "connections; check DB logs and systemctl status."
                )

        details.append({
            "engine": engine,
            "process_count": len(info["pids"]),
            "service": service_state,
            f"port_{port}_open": port_open,
            "ping": ping,
            "cpu_percent_now": info["cpu_percent"],
        })

    return finding("Database status", status, details, next_step)


def check_database_cpu(databases):
    if not databases:
        return finding("Database CPU", "INFO", "No database detected.")

    cpus = {e: i["cpu_percent"] for e, i in databases.items()}
    busy = [e for e, c in cpus.items() if c >= DB_CPU_THRESHOLD]

    return finding(
        "Database CPU",
        "WARNING" if busy else "PASS",
        {"cpu_percent_per_engine": cpus,
         "threshold_percent": DB_CPU_THRESHOLD,
         "note": "100% = one full CPU core."},
        "Check the running queries below." if busy else None,
    )


def check_database_queries(databases):
    """Show running queries only when a DB is using high CPU.
    Read-only SELECT/SHOW queries. Uses existing auth config
    (~/.my.cnf, PG* env vars, or local socket); no passwords here."""
    findings = []

    for engine, info in (databases or {}).items():
        if info["cpu_percent"] < DB_CPU_THRESHOLD:
            continue

        if engine == "MySQL/MariaDB" and shutil.which("mysql"):
            sql = (
                "SELECT id, user, db, time, state, LEFT(info, 200) "
                "FROM information_schema.processlist "
                "WHERE command <> 'Sleep' AND id <> CONNECTION_ID() "
                "ORDER BY time DESC LIMIT 5"
            )
            code, out = run_command(
                ["mysql", "--connect-timeout=3", "--batch", "-e", sql],
                timeout=10,
            )
            fix = ("Create a read-only monitoring user and put it in "
                   "~/.my.cnf (chmod 600).")

        elif engine == "PostgreSQL" and shutil.which("psql"):
            sql = (
                "SELECT pid, usename, datname, "
                "now() - query_start AS running_for, state, "
                "left(query, 200) AS query "
                "FROM pg_stat_activity "
                "WHERE state = 'active' AND pid <> pg_backend_pid() "
                "ORDER BY query_start LIMIT 5"
            )
            code, out = run_command(
                ["psql", "-X", "-A", "-c", sql], timeout=10
            )
            fix = ("Set PGUSER/PGHOST/PGDATABASE (and ~/.pgpass) for a "
                   "read-only monitoring role.")
        else:
            findings.append(finding(
                f"Top queries: {engine}", "INFO",
                "Query inspection is not supported for this engine "
                "or the client tool is missing.",
            ))
            continue

        if code != 0:
            findings.append(finding(
                f"Top queries: {engine}", "INFO", out[:300], fix
            ))
        else:
            findings.append(finding(
                f"Top queries: {engine}", "WARNING",
                {"longest_running_active_queries":
                    out.splitlines()[:7]},
                "Review the longest query with EXPLAIN; check "
                "missing indexes. Queries may contain sensitive "
                "data; review before sharing.",
            ))

    return findings

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

    report["checks"].append(check_apache_workers())
    report["checks"].append(check_php_fpm_workers())
    databases, db_error = detect_databases()
    report["checks"].append(check_database_status(databases, db_error))
    report["checks"].append(check_database_cpu(databases))
    report["checks"].extend(check_database_queries(databases))
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