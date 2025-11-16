#!/usr/bin/env python3
"""
Security Headers Analysis Script
Comprehensive analysis of HTTP security headers
"""

import requests
import json
import sys
from urllib.parse import urlparse

def analyze_security_headers(url):
    """Analyze security headers for a given URL"""
    print(f"Analyzing security headers for: {url}")
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = dict(response.headers)
        
        security_analysis = {
            'url': url,
            'status_code': response.status_code,
            'headers_present': {},
            'headers_missing': [],
            'recommendations': [],
            'score': 0,
            'max_score': 0
        }
        
        # Define security headers and their importance
        security_headers = {
            'Content-Security-Policy': {
                'required': True,
                'description': 'Prevents XSS attacks by controlling resource loading',
                'score': 20
            },
            'Strict-Transport-Security': {
                'required': True,
                'description': 'Forces HTTPS connections',
                'score': 20
            },
            'X-Frame-Options': {
                'required': True,
                'description': 'Prevents clickjacking attacks',
                'score': 15
            },
            'X-Content-Type-Options': {
                'required': True,
                'description': 'Prevents MIME type sniffing',
                'score': 10
            },
            'X-XSS-Protection': {
                'required': False,
                'description': 'Enables XSS filtering (legacy)',
                'score': 5
            },
            'Referrer-Policy': {
                'required': True,
                'description': 'Controls referrer information',
                'score': 10
            },
            'Permissions-Policy': {
                'required': True,
                'description': 'Controls browser features and APIs',
                'score': 10
            },
            'X-Permitted-Cross-Domain-Policies': {
                'required': False,
                'description': 'Controls cross-domain policies',
                'score': 5
            }
        }
        
        # Analyze each header
        for header_name, header_info in security_headers.items():
            security_analysis['max_score'] += header_info['score']
            
            if header_name in headers:
                security_analysis['headers_present'][header_name] = {
                    'value': headers[header_name],
                    'description': header_info['description'],
                    'score': header_info['score']
                }
                security_analysis['score'] += header_info['score']
            else:
                if header_info['required']:
                    security_analysis['headers_missing'].append(header_name)
                    security_analysis['recommendations'].append(
                        f"Missing required header: {header_name} - {header_info['description']}"
                    )
        
        # Calculate percentage
        if security_analysis['max_score'] > 0:
            security_analysis['score_percentage'] = (security_analysis['score'] / security_analysis['max_score']) * 100
        else:
            security_analysis['score_percentage'] = 0
        
        # Additional checks
        if 'Server' in headers:
            security_analysis['server_info'] = headers['Server']
            if 'version' in headers['Server'].lower():
                security_analysis['recommendations'].append(
                    "Server header reveals version information - consider hiding this"
                )
        
        if 'X-Powered-By' in headers:
            security_analysis['x_powered_by'] = headers['X-Powered-By']
            security_analysis['recommendations'].append(
                "X-Powered-By header reveals technology stack - remove this header"
            )
        
        return security_analysis
        
    except Exception as e:
        return {
            'url': url,
            'error': str(e),
            'score': 0,
            'score_percentage': 0
        }

def main():
    targets = [
        'https://aps.academicae.com',
        'https://app.hello-teacher.ai'
    ]
    
    results = {}
    for target in targets:
        results[target] = analyze_security_headers(target)
    
    # Save results
    output_file = '/workspace/results/security_headers_analysis.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print("\nSecurity Headers Analysis Summary:")
    for url, analysis in results.items():
        if 'error' not in analysis:
            print(f"\n{url}:")
            print(f"  Security Score: {analysis.get('score_percentage', 0):.1f}%")
            print(f"  Headers Present: {len(analysis.get('headers_present', {}))}")
            print(f"  Headers Missing: {len(analysis.get('headers_missing', []))}")
            if analysis.get('recommendations'):
                print(f"  Recommendations: {len(analysis['recommendations'])}")
    
    return results

if __name__ == '__main__':
    main()
