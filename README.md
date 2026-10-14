# ServerHealthCheck-CLI

A lightweight Python-based CLI tool to troubleshoot website connectivity and inspect basic Linux server health. It helps identify common issues through automated checks and generates timestamped JSON incident reports.

## Features

- **DNS Resolution:** Checks whether the target hostname resolves successfully.
- **HTTP/HTTPS Check:** Tests website reachability, HTTP status code, response time, and redirects.
- **TLS Certificate Check:** Checks certificate validity and warns when expiry is approaching.
- **Disk Usage:** Reports root filesystem capacity, used space, available space, and inode usage.
- **Memory Usage:** Reports total and available memory with estimated usage percentage.
- **CPU Load:** Displays 1-minute, 5-minute, and 15-minute load averages.
- **Listening TCP Ports:** Lists listening TCP ports to help investigate service availability.
- **Service Status:** Checks the status of Apache and Nginx using systemd.
- **Web Server Logs:** Inspects available standard Apache/Nginx error logs for common error patterns.
- **Overall Health Status:** Classifies the result as `HEALTHY`, `WARNING`, or `CRITICAL`.
- **JSON Reports:** Saves timestamped reports for incident investigation and record keeping.

## Requirements

- Linux environment
- Python 3
- Standard Python libraries
- `systemctl` and `ss` utilities for applicable system checks
- Network connectivity to the target website

No third-party Python packages are required by the current implementation.

## Installation

Clone the repository:

```bash
git clone https://github.com/AjIndia77/ServerHealthCheck-CLI.git
cd ServerHealthCheck-CLI
```

Replace `https://github.com/AjIndia77/ServerHealthCheck-CLI.git` with your repository's clone URL.

## Usage

Run the tool against a website:

```bash
python3 troubleshoot.py https://example.com
```

Specify a custom report directory:

```bash
python3 troubleshoot.py https://example.com --output incident-reports
```

The tool prints the diagnostic results in the terminal and saves a timestamped JSON report in the selected output directory.

Example report filename:

```text
reports/incident-YYYYMMDD-HHMMSS.json
```

## Example Output

```text
Website Troubleshooter: https://example.com
Overall Status: HEALTHY
------------------------------------------------------------
[PASS   ] DNS
[PASS   ] HTTP
[PASS   ] TLS
[PASS   ] Root filesystem
[PASS   ] Memory
[INFO   ] CPU load
[INFO   ] Listening TCP ports
[INFO   ] Web server logs
------------------------------------------------------------
Report saved locally: reports/incident-YYYYMMDD-HHMMSS.json
```

*Example output is illustrative. Actual results depend on the target website and the machine running the tool.*

## Overall Status

| Status | Meaning |
|---|---|
| `HEALTHY` | No checks returned a warning or failure. |
| `WARNING` | At least one check returned a warning or failure, without a critical DNS/HTTP failure. |
| `CRITICAL` | DNS or HTTP returned a failure. |

## Run Tests

Run the automated unit tests:

```bash
python3 -m unittest discover -s tests -v
```

## Important Notes

- Website connectivity checks target the supplied URL.
- Disk, memory, CPU, port, service, and log checks describe the machine on which the tool runs.
- Local server checks do not prove that the target website is hosted on that machine.
- An HTTP success response does not guarantee that every application feature or API is working.
- The tool performs diagnostic checks; it does not automatically restart services, modify server configuration, or renew certificates.
- Review JSON reports before sharing them because they may contain infrastructure details or log excerpts.

## Project Structure

```text
ServerHealthCheck-CLI/
├── troubleshoot.py
├── tests/
│   └── test_troubleshooter.py
├── reports/
├── .gitignore
└── README.md
```

Generated reports and Python cache files are excluded from Git using `.gitignore`.

## Future Improvements

- Support checking multiple website URLs in a single run.
- Add configurable warning thresholds.
- Improve incident summaries and error categorization.
- Add optional email or messaging notifications.
- Expand application-specific and API health checks.

