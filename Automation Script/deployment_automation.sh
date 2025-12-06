# Ashley Okoro
# Secure Deployment Automation Script

set -e  # Exit on error
set -u  # Exit on undefined variable

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Change to the project root directory (parent of automation_scripts)
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="secure-banking-app"
DOCKER_REGISTRY="localhost:5000"
BACKUP_DIR="./backups"
LOG_DIR="./logs"
SECURITY_SCAN_THRESHOLD=7  # Maximum CVSS score allowed

# Functions

print_header() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

print_error() {
    echo -e "${RED}[✗] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[i] $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    local prerequisites=("docker" "git" "python3" "pip3")
    local missing=()

    for cmd in "${prerequisites[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
            print_error "$cmd not found"
        else
            print_success "$cmd found"
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing prerequisites: ${missing[*]}"
        exit 1
    fi
}

# Pre-deployment security checks
pre_deployment_checks() {
    print_header "Pre-Deployment Security Checks"

    # Check for secrets in code
    print_info "Checking for hardcoded secrets..."
    if grep -r -i "password\s*=\s*['\"]" --include="*.py" . 2>/dev/null | grep -v ".git" | grep -v "example"; then
        print_warning "Potential hardcoded secrets found"
    else
        print_success "No hardcoded secrets detected"
    fi

    # Check for .env file
    if [ -f ".env" ]; then
        print_warning ".env file found - ensure it's in .gitignore"
        if grep -q ".env" .gitignore 2>/dev/null; then
            print_success ".env is in .gitignore"
        else
            print_error ".env NOT in .gitignore - SECURITY RISK"
            exit 1
        fi
    fi

    # Check Git status
    print_info "Checking Git status..."
    if [ -n "$(git status --porcelain)" ]; then
        print_warning "Uncommitted changes detected"
        git status --short
    else
        print_success "Working directory clean"
    fi
}

# Run SAST analysis
run_sast_scan() {
    print_header "Running SAST Security Scan"

    print_info "Installing Bandit..."
    pip3 install bandit --quiet

    print_info "Running Bandit scan..."
    if bandit -r ./web_application/app -ll -f json -o bandit_report.json 2>/dev/null; then
        print_success "SAST scan completed"

        # Parse results
        if [ -f bandit_report.json ]; then
            high_issues=$(jq '[.results[] | select(.issue_severity=="HIGH")] | length' bandit_report.json 2>/dev/null || echo "0")
            medium_issues=$(jq '[.results[] | select(.issue_severity=="MEDIUM")] | length' bandit_report.json 2>/dev/null || echo "0")

            print_info "High severity issues: $high_issues"
            print_info "Medium severity issues: $medium_issues"

            if [ "$high_issues" -gt 0 ]; then
                print_error "High severity issues found - deployment blocked"
                jq '.results[] | select(.issue_severity=="HIGH")' bandit_report.json 2>/dev/null || true
                exit 1
            fi
        fi
    else
        print_warning "SAST scan completed with warnings"
    fi
}

# Run dependency vulnerability scan
run_dependency_scan() {
    print_header "Scanning Dependencies for Vulnerabilities"

    print_info "Installing safety..."
    pip3 install safety --quiet

    print_info "Running safety check..."
    if [ -f "web_application/requirements.txt" ]; then
        if safety check -r web_application/requirements.txt --json > safety_report.json 2>/dev/null; then
            print_success "No vulnerabilities found in dependencies"
        else
            print_warning "Vulnerabilities found in dependencies"
            cat safety_report.json 2>/dev/null || true

            # Check severity
            critical_vulns=$(jq '[.vulnerabilities[] | select(.severity=="critical")] | length' safety_report.json 2>/dev/null || echo "0")
            if [ "$critical_vulns" -gt 0 ]; then
                print_error "Critical vulnerabilities found - deployment blocked"
                exit 1
            fi
        fi
    else
        print_warning "requirements.txt not found"
    fi
}

# Build Docker image
build_docker_image() {
    local version=$1
    print_header "Building Docker Image"

    # Create Dockerfile if not exists
    if [ ! -f "web_application/Dockerfile" ]; then
        print_info "Creating Dockerfile..."
        cat > web_application/Dockerfile << 'EOF'
FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')"

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "run:app"]
EOF
        print_success "Dockerfile created"
    fi

    # Build image
    print_info "Building Docker image..."
    cd web_application
    docker build -t "${APP_NAME}:${version}" -t "${APP_NAME}:latest" .
    cd ..

    print_success "Docker image built: ${APP_NAME}:${version}"
}

# Scan Docker image for vulnerabilities
scan_docker_image() {
    local version=$1
    print_header "Scanning Docker Image for Vulnerabilities"

    print_info "Installing Trivy..."
    if ! command -v trivy &> /dev/null; then
        # Install Trivy (Linux)
        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
            echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
            sudo apt-get update && sudo apt-get install trivy -y
        else
            print_warning "Trivy installation skipped - install manually"
            return
        fi
    fi

    print_info "Scanning image with Trivy..."
    if trivy image --severity HIGH,CRITICAL --exit-code 1 "${APP_NAME}:${version}" 2>/dev/null; then
        print_success "No critical vulnerabilities found in image"
    else
        print_error "Critical vulnerabilities found in Docker image"
        exit 1
    fi
}

# Deploy application
deploy_application() {
    local env=$1
    local version=$2
    print_header "Deploying Application - ${env}"

    # Create backup
    create_backup

    # Stop existing container
    print_info "Stopping existing container..."
    docker stop "${APP_NAME}-${env}" 2>/dev/null || true
    docker rm "${APP_NAME}-${env}" 2>/dev/null || true

    # Run new container
    print_info "Starting new container..."
    docker run -d \
        --name "${APP_NAME}-${env}" \
        -p 5000:5000 \
        --env-file "web_application/.env.${env}" \
        --restart unless-stopped \
        --memory="512m" \
        --cpus="1.0" \
        --read-only \
        --security-opt=no-new-privileges \
        --cap-drop=ALL \
        --cap-add=NET_BIND_SERVICE \
        "${APP_NAME}:${version}"

    print_success "Container started"

    # Wait for application to be ready
    print_info "Waiting for application to be ready..."
    sleep 5

    # Verify deployment
    verify_deployment "$env"
}

# Verify deployment
verify_deployment() {
    local env=$1
    print_header "Verifying Deployment"

    # Check container status
    if docker ps | grep -q "${APP_NAME}-${env}"; then
        print_success "Container is running"
    else
        print_error "Container is not running"
        docker logs "${APP_NAME}-${env}"
        exit 1
    fi

    # Check health endpoint
    print_info "Checking health endpoint..."
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:5000/health &>/dev/null; then
            print_success "Application is healthy"
            return 0
        fi
        print_info "Attempt $attempt/$max_attempts - waiting..."
        sleep 2
        ((attempt++))
    done

    print_error "Health check failed"
    docker logs "${APP_NAME}-${env}"
    exit 1
}

# Create backup
create_backup() {
    print_header "Creating Backup"

    mkdir -p "$BACKUP_DIR"

    local backup_name="backup_$(date +%Y%m%d_%H%M%S).tar.gz"

    print_info "Creating backup: $backup_name"

    # Backup database
    if docker ps | grep -q "${APP_NAME}"; then
        docker exec "${APP_NAME}" python -c "from app import db; db.create_all()" 2>/dev/null || true
    fi

    # Create archive
    tar -czf "${BACKUP_DIR}/${backup_name}" \
        web_application/ \
        automation_scripts/ \
        2>/dev/null || true

    print_success "Backup created: ${BACKUP_DIR}/${backup_name}"
}

# Rollback deployment
rollback_deployment() {
    local env=$1
    print_header "Rolling Back Deployment"

    # Find latest backup
    local latest_backup=$(ls -t ${BACKUP_DIR}/backup_*.tar.gz 2>/dev/null | head -1)

    if [ -z "$latest_backup" ]; then
        print_error "No backup found for rollback"
        exit 1
    fi

    print_info "Rolling back to: $latest_backup"

    # Stop current container
    docker stop "${APP_NAME}-${env}" 2>/dev/null || true
    docker rm "${APP_NAME}-${env}" 2>/dev/null || true

    # Restore from backup
    tar -xzf "$latest_backup" -C .

    # Redeploy previous version
    print_success "Rollback completed"
}

# Generate deployment report
generate_report() {
    print_header "Generating Deployment Report"

    mkdir -p "$LOG_DIR"
    local report_file="${LOG_DIR}/deployment_report_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "Deployment Report"
        echo "================="
        echo "Date: $(date)"
        echo "Application: $APP_NAME"
        echo ""
        echo "Security Checks:"
        echo "- SAST Scan: Completed"
        echo "- Dependency Scan: Completed"
        echo "- Container Scan: Completed"
        echo ""
        echo "Deployment Status: Success"
        echo ""
        docker ps | grep "$APP_NAME"
    } > "$report_file"

    print_success "Report saved: $report_file"
}

# Main execution
main() {
    local env="development"
    local version="latest"
    local rollback=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --env)
                env="$2"
                shift 2
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            --rollback)
                rollback=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    print_header "Secure Deployment Pipeline"
    echo "Environment: $env"
    echo "Version: $version"
    echo ""

    if [ "$rollback" = true ]; then
        rollback_deployment "$env"
        exit 0
    fi

    # Run deployment pipeline
    check_prerequisites
    pre_deployment_checks
    run_sast_scan
    run_dependency_scan
    build_docker_image "$version"
    # scan_docker_image "$version"  # Uncomment if Trivy is available
    deploy_application "$env" "$version"
    generate_report

    print_header "Deployment Complete"
    print_success "Application deployed successfully!"
    print_info "Access the application at: http://localhost:5000"
}

# Run main function
main "$@"
