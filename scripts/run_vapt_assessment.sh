#!/bin/bash
# Comprehensive VAPT Assessment Runner
# This script orchestrates all security testing phases

set -e

echo "=========================================="
echo "Comprehensive VAPT Assessment"
echo "=========================================="
echo ""

# Make scripts executable
chmod +x /workspace/scripts/*.py
chmod +x /workspace/scripts/*.sh

# Phase 1: Technology Stack Analysis
echo "Phase 1: Technology Stack Analysis"
echo "-----------------------------------"
python3 /workspace/scripts/technology_stack_analysis.py
echo ""

# Phase 2: Security Headers Analysis
echo "Phase 2: Security Headers Analysis"
echo "-----------------------------------"
python3 /workspace/scripts/security_headers_analysis.py
echo ""

# Phase 3: SSL/TLS Analysis
echo "Phase 3: SSL/TLS Configuration Analysis"
echo "----------------------------------------"
python3 /workspace/scripts/ssl_tls_analysis.py
echo ""

# Phase 4: Infrastructure Scanning
echo "Phase 4: Infrastructure Scanning"
echo "----------------------------------"
python3 /workspace/scripts/infrastructure_scan.py
echo ""

# Phase 5: API Endpoint Discovery
echo "Phase 5: API Endpoint Discovery"
echo "--------------------------------"
python3 /workspace/scripts/api_endpoint_discovery.py
echo ""

# Phase 6: Run Nuclei scans
echo "Phase 6: Running Nuclei Vulnerability Scans"
echo "-------------------------------------------"
if command -v nuclei &> /dev/null; then
    echo "Running Nuclei scan on aps.academicae.com..."
    nuclei -u https://aps.academicae.com -o /workspace/results/nuclei_aps_academicae.txt -silent || true
    
    echo "Running Nuclei scan on app.hello-teacher.ai..."
    nuclei -u https://app.hello-teacher.ai -o /workspace/results/nuclei_hello_teacher.txt -silent || true
else
    echo "Nuclei not installed, skipping..."
fi
echo ""

# Phase 7: Run Nikto scans
echo "Phase 7: Running Nikto Web Server Scans"
echo "---------------------------------------"
if command -v nikto &> /dev/null; then
    echo "Running Nikto scan on aps.academicae.com..."
    nikto -h https://aps.academicae.com -Format txt -output /workspace/results/nikto_aps_academicae.txt || true
    
    echo "Running Nikto scan on app.hello-teacher.ai..."
    nikto -h https://app.hello-teacher.ai -Format txt -output /workspace/results/nikto_hello_teacher.txt || true
else
    echo "Nikto not installed, skipping..."
fi
echo ""

echo "=========================================="
echo "VAPT Assessment Complete!"
echo "Results saved to /workspace/results/"
echo "=========================================="
