#!/usr/bin/env python3
"""
Dynamic Application Security Testing (DAST) Scanner
Performs automated security testing on live applications
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class DASTScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_sql_injection(self):
        """Check for SQL injection vulnerabilities"""
        print(f"  Checking for SQL injection vulnerabilities...")
        sql_payloads = [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1--"
        ]
        
        # Test common endpoints
        test_paths = ['/login', '/api/login', '/search', '/api/search']
        findings = []
        
        for path in test_paths:
            full_url = urljoin(self.base_url, path)
            for payload in sql_payloads:
                try:
                    # Test in query parameters
                    response = self.session.get(full_url, params={'q': payload}, timeout=5)
                    if any(error in response.text.lower() for error in [
                        'sql syntax', 'mysql', 'postgresql', 'oracle', 
                        'sqlite', 'database error', 'sql error'
                    ]):
                        findings.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'path': full_url,
                            'payload': payload,
                            'evidence': 'Database error message detected'
                        })
                except:
                    pass
        
        return findings
    
    def check_xss(self):
        """Check for Cross-Site Scripting vulnerabilities"""
        print(f"  Checking for XSS vulnerabilities...")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        test_paths = ['/search', '/api/search', '/comment']
        findings = []
        
        for path in test_paths:
            full_url = urljoin(self.base_url, path)
            for payload in xss_payloads:
                try:
                    response = self.session.get(full_url, params={'q': payload}, timeout=5)
                    if payload in response.text:
                        findings.append({
                            'type': 'Reflected XSS',
                            'severity': 'Medium',
                            'path': full_url,
                            'payload': payload,
                            'evidence': 'Payload reflected in response'
                        })
                except:
                    pass
        
        return findings
    
    def check_sensitive_files(self):
        """Check for exposed sensitive files"""
        print(f"  Checking for exposed sensitive files...")
        sensitive_files = [
            '.env',
            '.git/config',
            '.gitignore',
            'package.json',
            'composer.json',
            'web.config',
            '.htaccess',
            'robots.txt',
            'sitemap.xml',
            'backup.sql',
            'config.php',
            'database.yml'
        ]
        
        findings = []
        for file_path in sensitive_files:
            full_url = urljoin(self.base_url, file_path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    # Check if it's actually the file (not a 404 page)
                    content_type = response.headers.get('Content-Type', '')
                    if 'text' in content_type or 'application/json' in content_type:
                        if len(response.text) < 10000:  # Reasonable file size
                            findings.append({
                                'type': 'Sensitive File Exposure',
                                'severity': 'Medium',
                                'path': full_url,
                                'status_code': response.status_code,
                                'content_type': content_type
                            })
            except:
                pass
        
        return findings
    
    def check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        print(f"  Checking for directory listing...")
        test_dirs = ['/images/', '/static/', '/assets/', '/uploads/', '/admin/']
        findings = []
        
        for dir_path in test_dirs:
            full_url = urljoin(self.base_url, dir_path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    # Check for directory listing indicators
                    if any(indicator in response.text.lower() for indicator in [
                        'index of', 'directory listing', 'parent directory',
                        '<a href', 'last modified'
                    ]):
                        findings.append({
                            'type': 'Directory Listing',
                            'severity': 'Low',
                            'path': full_url,
                            'evidence': 'Directory listing enabled'
                        })
            except:
                pass
        
        return findings
    
    def check_cors_misconfiguration(self):
        """Check for CORS misconfigurations"""
        print(f"  Checking CORS configuration...")
        try:
            response = self.session.options(self.base_url, headers={
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }, timeout=5)
            
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
            }
            
            findings = []
            if cors_headers['Access-Control-Allow-Origin'] == '*':
                if cors_headers.get('Access-Control-Allow-Credentials') == 'true':
                    findings.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'High',
                        'issue': 'Wildcard origin with credentials allowed',
                        'cors_headers': cors_headers
                    })
                else:
                    findings.append({
                        'type': 'CORS Misconfiguration',
                        'severity': 'Medium',
                        'issue': 'Wildcard origin allowed',
                        'cors_headers': cors_headers
                    })
            
            return findings
        except:
            return []
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        print(f"  Checking for information disclosure...")
        findings = []
        
        try:
            response = self.session.get(self.base_url, timeout=5)
            
            # Check for stack traces
            if any(indicator in response.text for indicator in [
                'stack trace', 'exception', 'error in', 'at ', 'traceback',
                'file:', 'line:', 'python', 'django', 'flask'
            ]):
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Medium',
                    'issue': 'Stack trace or error information exposed',
                    'evidence': 'Error details found in response'
                })
            
            # Check headers for information
            server = response.headers.get('Server', '')
            if 'version' in server.lower() or any(char.isdigit() for char in server):
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'issue': 'Server version information disclosed',
                    'header': server
                })
            
            x_powered_by = response.headers.get('X-Powered-By', '')
            if x_powered_by:
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'issue': 'Technology stack information disclosed',
                    'header': x_powered_by
                })
        
        except:
            pass
        
        return findings
    
    def scan(self):
        """Run all DAST checks"""
        print(f"Running DAST scan on: {self.base_url}")
        
        all_findings = []
        all_findings.extend(self.check_sql_injection())
        all_findings.extend(self.check_xss())
        all_findings.extend(self.check_sensitive_files())
        all_findings.extend(self.check_directory_listing())
        all_findings.extend(self.check_cors_misconfiguration())
        all_findings.extend(self.check_information_disclosure())
        
        return {
            'url': self.base_url,
            'total_findings': len(all_findings),
            'findings': all_findings,
            'severity_breakdown': {
                'Critical': sum(1 for f in all_findings if f.get('severity') == 'Critical'),
                'High': sum(1 for f in all_findings if f.get('severity') == 'High'),
                'Medium': sum(1 for f in all_findings if f.get('severity') == 'Medium'),
                'Low': sum(1 for f in all_findings if f.get('severity') == 'Low')
            }
        }

def main():
    targets = [
        'https://aps.academicae.com',
        'https://app.hello-teacher.ai'
    ]
    
    results = {}
    for target in targets:
        scanner = DASTScanner(target)
        results[target] = scanner.scan()
    
    # Save results
    output_file = '/workspace/results/dast_scan_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print("\nDAST Scan Summary:")
    for url, result in results.items():
        print(f"\n{url}:")
        print(f"  Total Findings: {result['total_findings']}")
        print(f"  Severity Breakdown: {result['severity_breakdown']}")
    
    return results

if __name__ == '__main__':
    main()
