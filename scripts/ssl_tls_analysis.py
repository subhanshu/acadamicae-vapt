#!/usr/bin/env python3
"""
SSL/TLS Configuration Analysis
Analyzes SSL/TLS configuration using ssl module and external APIs
"""

import ssl
import socket
import json
import requests
from urllib.parse import urlparse
import subprocess

def analyze_ssl_tls(url):
    """Analyze SSL/TLS configuration"""
    print(f"Analyzing SSL/TLS for: {url}")
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    analysis = {
        'url': url,
        'hostname': hostname,
        'port': port,
        'certificate_info': {},
        'protocols_supported': [],
        'cipher_suites': [],
        'vulnerabilities': [],
        'recommendations': []
    }
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                analysis['certificate_info'] = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serialNumber': cert.get('serialNumber'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                    'subjectAltName': cert.get('subjectAltName', [])
                }
                
                # Get protocol version
                analysis['protocol_version'] = ssock.version()
                analysis['protocols_supported'] = [ssock.version()]
                
                # Get cipher
                analysis['cipher'] = ssock.cipher()
        
        # Check SSL Labs API (if available)
        try:
            ssl_labs_url = f"https://api.ssllabs.com/api/v3/analyze?host={hostname}&publish=off&fromCache=on&maxAge=1"
            response = requests.get(ssl_labs_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if 'endpoints' in data and len(data['endpoints']) > 0:
                    endpoint = data['endpoints'][0]
                    analysis['ssl_labs_grade'] = endpoint.get('grade', 'N/A')
                    analysis['ssl_labs_details'] = {
                        'protocols': endpoint.get('details', {}).get('protocols', []),
                        'suites': endpoint.get('details', {}).get('suites', [])
                    }
        except Exception as e:
            analysis['ssl_labs_error'] = str(e)
        
        # Basic vulnerability checks
        if analysis.get('protocol_version') in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
            analysis['vulnerabilities'].append({
                'severity': 'High',
                'issue': f"Outdated protocol version: {analysis['protocol_version']}",
                'description': 'Older TLS/SSL versions are vulnerable and should be disabled'
            })
            analysis['recommendations'].append(
                f"Disable {analysis['protocol_version']} and use TLS 1.2 or higher"
            )
        
        # Check certificate expiration
        from datetime import datetime
        not_after = analysis['certificate_info'].get('notAfter')
        if not_after:
            try:
                exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (exp_date - datetime.now()).days
                if days_until_expiry < 30:
                    analysis['vulnerabilities'].append({
                        'severity': 'Medium',
                        'issue': f'Certificate expires in {days_until_expiry} days',
                        'description': 'Certificate should be renewed before expiration'
                    })
            except:
                pass
        
    except Exception as e:
        analysis['error'] = str(e)
        analysis['vulnerabilities'].append({
            'severity': 'Informational',
            'issue': 'Could not complete SSL/TLS analysis',
            'description': str(e)
        })
    
    return analysis

def main():
    targets = [
        'https://aps.academicae.com',
        'https://app.hello-teacher.ai'
    ]
    
    results = {}
    for target in targets:
        results[target] = analyze_ssl_tls(target)
    
    # Save results
    output_file = '/workspace/results/ssl_tls_analysis.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to: {output_file}")
    print("\nSSL/TLS Analysis Summary:")
    for url, analysis in results.items():
        if 'error' not in analysis:
            print(f"\n{url}:")
            print(f"  Protocol: {analysis.get('protocol_version', 'Unknown')}")
            if 'ssl_labs_grade' in analysis:
                print(f"  SSL Labs Grade: {analysis['ssl_labs_grade']}")
            print(f"  Vulnerabilities Found: {len(analysis.get('vulnerabilities', []))}")
    
    return results

if __name__ == '__main__':
    main()
