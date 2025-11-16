#!/usr/bin/env python3
"""
Technology Stack Analysis Script
Analyzes live applications to identify technology stack
"""

import requests
import json
import sys
from urllib.parse import urljoin
import re

def get_headers(url):
    """Fetch HTTP headers from target URL"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        return {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'url': response.url,
            'server': response.headers.get('Server', 'Unknown'),
            'x_powered_by': response.headers.get('X-Powered-By', 'Not disclosed'),
            'content_type': response.headers.get('Content-Type', 'Unknown')
        }
    except Exception as e:
        return {'error': str(e)}

def analyze_tech_stack(url):
    """Analyze technology stack from headers and content"""
    print(f"Analyzing technology stack for: {url}")
    
    headers_info = get_headers(url)
    if 'error' in headers_info:
        print(f"Error: {headers_info['error']}")
        return headers_info
    
    tech_stack = {
        'url': url,
        'server': headers_info.get('server', 'Unknown'),
        'x_powered_by': headers_info.get('x_powered_by', 'Not disclosed'),
        'content_type': headers_info.get('content_type', 'Unknown'),
        'security_headers': {},
        'detected_technologies': []
    }
    
    # Check for common technology indicators
    headers = headers_info.get('headers', {})
    
    # Check for React/Next.js indicators
    if 'x-nextjs-cache' in headers or 'x-vercel-id' in headers:
        tech_stack['detected_technologies'].append('Next.js')
    
    # Check for Node.js
    if 'node' in headers_info.get('server', '').lower() or 'express' in headers_info.get('x_powered_by', '').lower():
        tech_stack['detected_technologies'].append('Node.js/Express')
    
    # Security headers analysis
    security_headers = [
        'Content-Security-Policy',
        'Strict-Transport-Security',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    for header in security_headers:
        tech_stack['security_headers'][header] = headers.get(header, 'Missing')
    
    return tech_stack

def main():
    targets = [
        'https://aps.academicae.com',
        'https://app.hello-teacher.ai'
    ]
    
    results = {}
    for target in targets:
        results[target] = analyze_tech_stack(target)
    
    # Save results
    output_file = '/workspace/results/technology_stack_analysis.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print("\nTechnology Stack Summary:")
    print(json.dumps(results, indent=2))
    
    return results

if __name__ == '__main__':
    main()
