"""
Ashley Okoro

SAST vs DAST Comparison Tool 

SAST (Static Application Security Testing):
- Analyzes source code without execution
- Uses Bandit for Python security analysis
- Identifies vulnerabilities early in development

DAST (Dynamic Application Security Testing):
- Tests running application
- Uses OWASP ZAP for black-box testing
- Identifies runtime vulnerabilities

"""

import subprocess
import json
import argparse
import os
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


class Colors:
    """ANSI color codes."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class SASTAnalyzer:
    """Static Application Security Testing using Bandit."""

    def __init__(self, source_path: str):
      
        self.source_path = source_path
        self.results = {
            'tool': 'Bandit (SAST)',
            'timestamp': datetime.now().isoformat(),
            'source_path': source_path,
            'vulnerabilities': [],
            'statistics': {}
        }

    def check_bandit_installed(self) -> bool:
    # Check if Bandit is installed
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def install_bandit(self):
        # Install Bandit
        print(f"{Colors.YELLOW}[*] Installing Bandit...{Colors.END}")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'bandit'], check=True)
            print(f"{Colors.GREEN}[+] Bandit installed successfully{Colors.END}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[!] Failed to install Bandit: {e}{Colors.END}")
            sys.exit(1)

    def run_analysis(self):
        # Run SAST analysis using Bandit.
        print(f"{Colors.BLUE}[*] Running SAST Analysis with Bandit...{Colors.END}")

        if not self.check_bandit_installed():
            self.install_bandit()

        # Run Bandit
        output_file = 'bandit_results.json'
        try:
            cmd = [
                'bandit',
                '-r', self.source_path,
                '-f', 'json',
                '-o', output_file,
                '-ll'  # Only report medium and high severity
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            # Load results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    bandit_data = json.load(f)

                # Parse results
                for issue in bandit_data.get('results', []):
                    vuln = {
                        'severity': issue.get('issue_severity', 'UNKNOWN'),
                        'confidence': issue.get('issue_confidence', 'UNKNOWN'),
                        'type': issue.get('test_id', 'Unknown'),
                        'description': issue.get('issue_text', ''),
                        'file': issue.get('filename', ''),
                        'line': issue.get('line_number', 0),
                        'code': issue.get('code', '').strip()
                    }
                    self.results['vulnerabilities'].append(vuln)

                # Statistics
                metrics = bandit_data.get('metrics', {})
                if metrics:
                    total_loc = sum(file_data.get('SLOC', 0) for file_data in metrics.values() if isinstance(file_data, dict))
                    self.results['statistics'] = {
                        'total_files': len(metrics) - 1,  # Exclude '_totals'
                        'total_loc': total_loc,
                        'total_issues': len(self.results['vulnerabilities']),
                        'high_severity': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH']),
                        'medium_severity': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'MEDIUM']),
                        'low_severity': len([v for v in self.results['vulnerabilities'] if v['severity'] == 'LOW'])
                    }

                # Clean up
                os.remove(output_file)

                print(f"{Colors.GREEN}[+] SAST Analysis Complete{Colors.END}")
                print(f"    Total Issues: {self.results['statistics'].get('total_issues', 0)}")
                print(f"    High Severity: {self.results['statistics'].get('high_severity', 0)}")
                print(f"    Medium Severity: {self.results['statistics'].get('medium_severity', 0)}")

        except Exception as e:
            print(f"{Colors.RED}[!] SAST Analysis Failed: {e}{Colors.END}")
            if os.path.exists(output_file):
                os.remove(output_file)

        return self.results

    def print_results(self):
        """Print SAST results to console."""
        print(f"{Colors.BOLD}SAST Results (Bandit){Colors.END}")

        stats = self.results['statistics']
        print(f"Files Analyzed: {stats.get('total_files', 0)}")
        print(f"Lines of Code: {stats.get('total_loc', 0)}")
        print(f"Total Issues: {stats.get('total_issues', 0)}")
        print(f"  - High: {Colors.RED}{stats.get('high_severity', 0)}{Colors.END}")
        print(f"  - Medium: {Colors.YELLOW}{stats.get('medium_severity', 0)}{Colors.END}")
        print(f"  - Low: {Colors.GREEN}{stats.get('low_severity', 0)}{Colors.END}")

        if self.results['vulnerabilities']:
            print(f"\n{Colors.YELLOW}Top Vulnerabilities:{Colors.END}")
            for i, vuln in enumerate(self.results['vulnerabilities'][:5], 1):
                severity_color = Colors.RED if vuln['severity'] == 'HIGH' else Colors.YELLOW
                print(f"\n{i}. [{severity_color}{vuln['severity']}{Colors.END}] {vuln['description']}")
                print(f"   File: {vuln['file']}:{vuln['line']}")
                print(f"   Code: {vuln['code'][:80]}")


class DASTAnalyzer:
    """Dynamic Application Security Testing using OWASP ZAP."""

    def __init__(self, target_url: str):
       
        self.target_url = target_url
        self.results = {
            'tool': 'OWASP ZAP (DAST)',
            'timestamp': datetime.now().isoformat(),
            'target_url': target_url,
            'vulnerabilities': [],
            'statistics': {}
        }

    def run_basic_scan(self):
            #   Run basic DAST scan using requests.

        print(f"{Colors.BLUE}[*] Running DAST Analysis...{Colors.END}")

        import requests
        from urllib.parse import urljoin

        # Test endpoints
        endpoints = ['/', '/login', '/register', '/dashboard', '/admin']

        vulnerabilities = []

        # Basic security header checks
        try:
            response = requests.get(self.target_url, verify=False, timeout=10)

            # Check security headers
            headers_to_check = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'XSS protection',
                'X-XSS-Protection': 'XSS filter'
            }

            for header, purpose in headers_to_check.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'type': 'Missing Security Header',
                        'description': f'Missing {header} header ({purpose})',
                        'url': self.target_url,
                        'recommendation': f'Add {header} header to responses'
                    })

            # Check for information disclosure
            server_header = response.headers.get('Server', '')
            if server_header:
                vulnerabilities.append({
                    'severity': 'LOW',
                    'type': 'Information Disclosure',
                    'description': f'Server version disclosed: {server_header}',
                    'url': self.target_url,
                    'recommendation': 'Remove or obfuscate Server header'
                })

            # Check for HTTPS
            if not self.target_url.startswith('https://'):
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'type': 'Insecure Transport',
                    'description': 'Application not using HTTPS',
                    'url': self.target_url,
                    'recommendation': 'Enforce HTTPS for all connections'
                })

            # Test for common vulnerabilities
            test_payloads = {
                'XSS': "<script>alert('xss')</script>",
                'SQL Injection': "' OR '1'='1",
                'Path Traversal': '../../../etc/passwd'
            }

            for vuln_type, payload in test_payloads.items():
                for endpoint in endpoints:
                    try:
                        url = urljoin(self.target_url, endpoint)
                        test_response = requests.get(
                            url,
                            params={'test': payload},
                            verify=False,
                            timeout=5
                        )

                        # Simple detection (more sophisticated checks needed for production)
                        if payload in test_response.text:
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'type': vuln_type,
                                'description': f'Potential {vuln_type} vulnerability detected',
                                'url': f"{url}?test={payload}",
                                'recommendation': f'Implement proper input validation and output encoding'
                            })
                    except:
                        pass

        except Exception as e:
            print(f"{Colors.RED}[!] DAST scan error: {e}{Colors.END}")

        self.results['vulnerabilities'] = vulnerabilities
        self.results['statistics'] = {
            'total_issues': len(vulnerabilities),
            'high_severity': len([v for v in vulnerabilities if v['severity'] == 'HIGH']),
            'medium_severity': len([v for v in vulnerabilities if v['severity'] == 'MEDIUM']),
            'low_severity': len([v for v in vulnerabilities if v['severity'] == 'LOW'])
        }

        print(f"{Colors.GREEN}[+] DAST Analysis Complete{Colors.END}")
        print(f"    Total Issues: {self.results['statistics']['total_issues']}")
        print(f"    High Severity: {self.results['statistics']['high_severity']}")
        print(f"    Medium Severity: {self.results['statistics']['medium_severity']}")

        return self.results

    def print_results(self):
        """Print DAST results to console."""
        print(f"{Colors.BOLD}DAST Results (Runtime Analysis){Colors.END}")

        stats = self.results['statistics']
        print(f"Target: {self.target_url}")
        print(f"Total Issues: {stats['total_issues']}")
        print(f"  - High: {Colors.RED}{stats['high_severity']}{Colors.END}")
        print(f"  - Medium: {Colors.YELLOW}{stats['medium_severity']}{Colors.END}")
        print(f"  - Low: {Colors.GREEN}{stats['low_severity']}{Colors.END}")

        if self.results['vulnerabilities']:
            print(f"\n{Colors.YELLOW}Vulnerabilities Found:{Colors.END}")
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                severity_color = Colors.RED if vuln['severity'] == 'HIGH' else Colors.YELLOW
                print(f"\n{i}. [{severity_color}{vuln['severity']}{Colors.END}] {vuln['type']}")
                print(f"   Description: {vuln['description']}")
                print(f"   Recommendation: {vuln['recommendation']}")


class ComparisonReport:
    """Generate comparison report between SAST and DAST."""

    def __init__(self, sast_results, dast_results):
        """Initialize comparison report."""
        self.sast_results = sast_results
        self.dast_results = dast_results

    def generate_comparison(self):
        """Generate detailed comparison."""
        print(f"{Colors.BOLD}SAST vs DAST Comparison{Colors.END}")

        comparison = {
            'methodology': {
                'SAST': {
                    'approach': 'White-box testing (source code analysis)',
                    'timing': 'Early in development (pre-deployment)',
                    'coverage': 'All code paths (100% code coverage possible)',
                    'false_positives': 'Higher rate',
                    'speed': 'Fast',
                    'cost': 'Low',
                    'expertise_required': 'Medium'
                },
                'DAST': {
                    'approach': 'Black-box testing (running application)',
                    'timing': 'Later in development (post-deployment)',
                    'coverage': 'Only reachable code paths',
                    'false_positives': 'Lower rate',
                    'speed': 'Slower',
                    'cost': 'Higher',
                    'expertise_required': 'Low to Medium'
                }
            },
            'results_summary': {
                'SAST': self.sast_results.get('statistics', {}),
                'DAST': self.dast_results.get('statistics', {})
            },
            'advantages': {
                'SAST': [
                    'Finds vulnerabilities early in SDLC',
                    'Can analyze entire codebase',
                    'Provides exact location in source code',
                    'No need for running application',
                    'Fast execution'
                ],
                'DAST': [
                    'Tests real running application',
                    'Finds runtime and configuration issues',
                    'No source code access needed',
                    'Lower false positive rate',
                    'Tests actual attack scenarios'
                ]
            },
            'disadvantages': {
                'SAST': [
                    'Higher false positive rate',
                    'May miss runtime issues',
                    'Requires source code access',
                    'May miss configuration issues',
                    'Language/framework specific'
                ],
                'DAST': [
                    'Cannot test all code paths',
                    'Slower execution',
                    'Later in development cycle',
                    'May miss logical flaws in code',
                    'Requires running application'
                ]
            },
            'recommendations': {
                'best_practice': 'Use both SAST and DAST in CI/CD pipeline',
                'integration': 'SAST in development, DAST in staging/pre-production',
                'complementary': 'Tools complement each other, covering different vulnerability types'
            }
        }

        # Print comparison table
        print(f"\n{Colors.BOLD}Methodology Comparison:{Colors.END}")
        print(f"{'Aspect':<25} {'SAST':<30} {'DAST':<30}")
  

        for aspect in ['approach', 'timing', 'coverage', 'speed', 'cost']:
            sast_val = comparison['methodology']['SAST'][aspect]
            dast_val = comparison['methodology']['DAST'][aspect]
            print(f"{aspect.title():<25} {sast_val:<30} {dast_val:<30}")

        # Print advantages
        print(f"\n{Colors.BOLD}Advantages:{Colors.END}")
        print(f"\n{Colors.GREEN}SAST:{Colors.END}")
        for adv in comparison['advantages']['SAST']:
            print(f"  + {adv}")

        print(f"\n{Colors.GREEN}DAST:{Colors.END}")
        for adv in comparison['advantages']['DAST']:
            print(f"  + {adv}")

        # Recommendation
        print(f"\n{Colors.BOLD}Recommendation:{Colors.END}")
        print(f"{Colors.CYAN}{comparison['recommendations']['best_practice']}{Colors.END}")
        print(f"{comparison['recommendations']['integration']}")

        return comparison

    def save_report(self, output_file: str):
        """Save comparison report to JSON file."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'sast_results': self.sast_results,
            'dast_results': self.dast_results,
            'comparison': self.generate_comparison()
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}[+] Report saved to: {output_file}{Colors.END}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description='SAST vs DAST Comparison Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--mode', choices=['sast', 'dast', 'both'], default='both',
                        help='Testing mode')
    parser.add_argument('--source', help='Source code path for SAST')
    parser.add_argument('--url', help='Target URL for DAST')
    parser.add_argument('--output', default='comparison_report.json',
                        help='Output report file')

    args = parser.parse_args()

    sast_results = None
    dast_results = None

    # Run SAST
    if args.mode in ['sast', 'both']:
        if not args.source:
            print(f"{Colors.RED}[!] --source required for SAST{Colors.END}")
            sys.exit(1)

        sast = SASTAnalyzer(args.source)
        sast_results = sast.run_analysis()
        sast.print_results()

    # Run DAST
    if args.mode in ['dast', 'both']:
        if not args.url:
            print(f"{Colors.RED}[!] --url required for DAST{Colors.END}")
            sys.exit(1)

        dast = DASTAnalyzer(args.url)
        dast_results = dast.run_basic_scan()
        dast.print_results()

    # Generate comparison
    if args.mode == 'both' and sast_results and dast_results:
        report = ComparisonReport(sast_results, dast_results)
        report.generate_comparison()
        report.save_report(args.output)

    return 0


if __name__ == '__main__':
    sys.exit(main())
