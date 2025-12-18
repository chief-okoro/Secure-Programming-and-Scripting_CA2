# Security Automation Scripts

## Overview

This directory contains three comprehensive security automation scripts demonstrating various aspects of automated security testing and deployment.

## Scripts

### 1. Fuzz Testing Tool (`fuzz_testing.py`)
### 2. SAST vs DAST Comparison Tool (`sast_dast_comparison.py`)
### 3. Deployment Automation Script (`deployment_automation.sh`)

---

## Script 1: Fuzz Testing Tool

### Purpose
Automated fuzzing tool to discover network vulnerabilities in web applications through systematic payload injection.

### Features
- **SQL Injection Testing:** 20+ payloads
- **XSS Detection:** 18+ payloads
- **Command Injection:** System command payloads
- **Path Traversal:** Directory traversal attacks
- **Buffer Overflow:** Large input testing
- **Format String:** Format specifier exploitation
- **Header Injection:** HTTP header manipulation
- **Concurrent Testing:** Multi-threaded execution
- **Report Generation:** JSON output with details

### Installation

```bash
pip install requests
```

### Usage

#### Basic Usage
```bash
# Test all vulnerability types on target
python fuzz_testing.py --url http://localhost:5000 --type all

# Test specific vulnerability type
python fuzz_testing.py --url http://target.com --type sql

# Generate JSON report
python fuzz_testing.py --url http://target.com --type all --output report.json
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target URL (required) | - |
| `--type` | Vulnerability type (`all`, `sql`, `xss`, `cmd`, `path`, `buffer`) | `all` |
| `--endpoints` | List of endpoints to test | `['/']` |
| `--timeout` | Request timeout in seconds | `10` |
| `--threads` | Number of concurrent threads | `5` |
| `--output` | Output JSON report file | None |

### Vulnerability Types

#### SQL Injection
Tests for SQL injection vulnerabilities using:
- Basic OR conditions (`' OR '1'='1`)
- Comment injection (`admin' --`)
- UNION-based injection
- Time-based blind injection
- Stacked queries

**Example Output:**
```
[!] VULNERABILITY FOUND: SQL Injection
    Endpoint: /login
    Payload: ' OR '1'='1
    Status: 200
```

#### XSS (Cross-Site Scripting)
Tests for reflected and stored XSS:
- Script tags
- Event handlers
- JavaScript protocol
- Encoded payloads
- Bypass techniques

#### Command Injection
Tests for OS command injection:
- Shell command separators (`;`, `|`, `&`)
- Command substitution
- File reading attempts
- Network commands

#### Path Traversal
Tests for directory traversal:
- Relative path sequences (`../`)
- Encoded sequences
- Windows/Unix variations
- Sensitive file access attempts

### Output Format

#### Console Output
- Color-coded severity levels
- Real-time vulnerability discovery
- Summary statistics
- Request count

#### JSON Report
```json
{
  "target": "http://localhost:5000",
  "scan_date": "2025-01-15T10:30:00",
  "duration_seconds": 45.23,
  "requests_sent": 250,
  "vulnerabilities_found": 5,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "endpoint": "/login",
      "payload": "' OR '1'='1",
      "status_code": 200,
      "response_time": 0.125,
      "response_length": 1523,
      "timestamp": "2025-01-15T10:30:15"
    }
  ]
}
```



---

## Script 2: SAST vs DAST Comparison Tool

### Purpose
Demonstrates and compares Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) methodologies.

### Features

#### SAST Analysis
- Uses Bandit for Python code analysis
- Identifies vulnerabilities in source code
- Provides exact file location and line numbers
- Checks for:
  - Hardcoded passwords and secrets
  - SQL injection patterns
  - Weak cryptography usage
  - Insecure deserialization
  - Shell injection risks
  - Assert usage in production
  - And more...

#### DAST Analysis
- Tests running application
- Checks security headers
- Tests for runtime vulnerabilities
- Validates configuration
- Identifies:
  - Missing security headers
  - HTTPS usage
  - Information disclosure
  - Potential XSS/SQLi
  - Configuration issues

#### Comparison Report
- Side-by-side methodology comparison
- Advantages and disadvantages
- Results summary
- Best practice recommendations

### Installation

```bash
# SAST tool (Bandit)
pip install bandit

# DAST requirements
pip install requests
```

### Usage

#### Run Both SAST and DAST
```bash
python sast_dast_comparison.py \
  --source ../web_application/app \
  --url http://localhost:5000 \
  --output comparison_report.json
```

#### Run Only SAST
```bash
python sast_dast_comparison.py \
  --mode sast \
  --source ../web_application/app
```

#### Run Only DAST
```bash
# Ensure application is running first!
python sast_dast_comparison.py \
  --mode dast \
  --url http://localhost:5000
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--mode` | Testing mode (`sast`, `dast`, `both`) | `both` |
| `--source` | Source code path for SAST | - |
| `--url` | Target URL for DAST | - |
| `--output` | Output report file (JSON) | `comparison_report.json` |

### Understanding Results

#### SAST Results

**Example Output:**
```
SAST Results (Bandit)
=====================
Files Analyzed: 15
Lines of Code: 2,543
Total Issues: 8
  - High: 2
  - Medium: 4
  - Low: 2

Top Vulnerabilities:

1. [HIGH] Possible hardcoded password
   File: app/config.py:25
   Code: SECRET_KEY = "hardcoded_secret"

2. [MEDIUM] Use of insecure MD5 hash
   File: app/utils.py:45
   Code: hashlib.md5(data)
```

**Severity Levels:**
- **High:** Critical security issues requiring immediate fix
- **Medium:** Important issues that should be addressed
- **Low:** Best practice violations or potential issues

#### DAST Results

**Example Output:**
```
DAST Results (Runtime Analysis)
===============================
Target: http://localhost:5000
Total Issues: 6
  - High: 1
  - Medium: 3
  - Low: 2

Vulnerabilities Found:

1. [HIGH] Insecure Transport
   Description: Application not using HTTPS
   Recommendation: Enforce HTTPS for all connections

2. [MEDIUM] Missing Security Header
   Description: Missing X-Frame-Options header
   Recommendation: Add X-Frame-Options: DENY
```


**Recommendation:** Use **BOTH** SAST and DAST

**Integrated Approach:**
1. **SAST** during development (early detection)
2. **DAST** in staging (runtime verification)
3. Both in CI/CD pipeline (automated security)

**Pipeline Integration:**
```
Commit → SAST → Unit Tests → Build → Container Scan → Deploy → DAST → Monitor
```

---

## Script 3: Deployment Automation

### Purpose
Secure CI/CD deployment pipeline with automated security checks and container deployment.

### Features

#### Pre-Deployment Checks
- Git status verification
- Secrets detection
- .env file validation
- Uncommitted changes detection

#### Security Scanning
- SAST analysis with Bandit
- Dependency vulnerability scanning (Safety)
- Container image scanning (Trivy)

#### Deployment
- Docker containerization
- Security-hardened container configuration
- Automated backup creation
- Health check verification

#### Rollback
- Automated rollback capability
- Backup restoration
- Quick recovery from failed deployments

### Prerequisites

```bash
# Required tools
- Docker
- Git
- Python 3.9+
- pip
- jq (for JSON parsing)

# Optional
- Trivy (for container scanning)
```

### Installation

```bash
# Make script executable
chmod +x deployment_automation.sh

# Install Python dependencies
pip install bandit safety
```

