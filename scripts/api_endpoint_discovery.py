#!/usr/bin/env python3
"""
API Endpoint Discovery Script
Discovers API endpoints through various methods
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

def discover_endpoints_from_robots(url):
    """Check robots.txt for endpoints"""
    endpoints = []
    try:
        robots_url = urljoin(url, '/robots.txt')
        response = requests.get(robots_url, timeout=10)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if line.startswith('Disallow:') or line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        endpoints.append({
                            'path': path,
                            'source': 'robots.txt',
                            'method': 'GET'
                        })
    except:
        pass
    return endpoints

def discover_endpoints_from_sitemap(url):
    """Check sitemap.xml for endpoints"""
    endpoints = []
    try:
        sitemap_url = urljoin(url, '/sitemap.xml')
        response = requests.get(sitemap_url, timeout=10)
        if response.status_code == 200:
            # Simple XML parsing
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            for url_path in urls:
                endpoints.append({
                    'path': url_path,
                    'source': 'sitemap.xml',
                    'method': 'GET'
                })
    except:
        pass
    return endpoints

def discover_endpoints_from_js(url):
    """Discover API endpoints from JavaScript files"""
    endpoints = []
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            # Find all script tags
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            
            for script in scripts:
                script_url = urljoin(url, script['src'])
                try:
                    script_response = requests.get(script_url, timeout=10)
                    if script_response.status_code == 200:
                        # Look for API patterns
                        api_patterns = [
                            r'["\'](/api/[^"\']+)["\']',
                            r'["\'](/v\d+/[^"\']+)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']'
                        ]
                        
                        for pattern in api_patterns:
                            matches = re.findall(pattern, script_response.text)
                            for match in matches:
                                if isinstance(match, tuple):
                                    path = match[-1]
                                else:
                                    path = match
                                if path.startswith('/'):
                                    endpoints.append({
                                        'path': path,
                                        'source': 'javascript',
                                        'file': script_url,
                                        'method': 'GET'
                                    })
                except:
                    continue
    except:
        pass
    return endpoints

def test_endpoint(base_url, endpoint):
    """Test an endpoint to see if it's accessible"""
    full_url = urljoin(base_url, endpoint['path'])
    try:
        response = requests.get(full_url, timeout=5, allow_redirects=False)
        endpoint['status_code'] = response.status_code
        endpoint['accessible'] = True
        endpoint['headers'] = dict(response.headers)
    except:
        endpoint['accessible'] = False
    return endpoint

def main():
    targets = [
        'https://aps.academicae.com',
        'https://app.hello-teacher.ai'
    ]
    
    all_results = {}
    
    for target in targets:
        print(f"Discovering endpoints for: {target}")
        endpoints = []
        
        # Discover from various sources
        endpoints.extend(discover_endpoints_from_robots(target))
        endpoints.extend(discover_endpoints_from_sitemap(target))
        endpoints.extend(discover_endpoints_from_js(target))
        
        # Remove duplicates
        seen = set()
        unique_endpoints = []
        for ep in endpoints:
            key = ep['path']
            if key not in seen:
                seen.add(key)
                unique_endpoints.append(ep)
        
        # Test endpoints (limited to avoid overwhelming the server)
        tested_endpoints = []
        for ep in unique_endpoints[:50]:  # Limit to first 50
            tested_endpoints.append(test_endpoint(target, ep))
        
        all_results[target] = {
            'total_discovered': len(unique_endpoints),
            'endpoints': tested_endpoints
        }
    
    # Save results
    output_file = '/workspace/results/api_endpoint_discovery.json'
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    print("\nAPI Endpoint Discovery Summary:")
    for url, data in all_results.items():
        print(f"\n{url}:")
        print(f"  Total Endpoints Discovered: {data['total_discovered']}")
        accessible = sum(1 for ep in data['endpoints'] if ep.get('accessible', False))
        print(f"  Accessible Endpoints: {accessible}")
    
    return all_results

if __name__ == '__main__':
    main()
