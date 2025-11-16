#!/usr/bin/env python3
"""
Infrastructure Scanning Script
Performs port scanning and service enumeration
"""

import subprocess
import json
import sys
from urllib.parse import urlparse
import socket

def nmap_scan(hostname):
    """Perform nmap scan on target"""
    print(f"Running nmap scan on: {hostname}")
    
    try:
        # Basic port scan
        result = subprocess.run(
            ['nmap', '-sV', '--script', 'vuln', '-oJ', '-', hostname],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            try:
                nmap_output = json.loads(result.stdout)
                return {
                    'hostname': hostname,
                    'scan_result': nmap_output,
                    'status': 'success'
                }
            except json.JSONDecodeError:
                return {
                    'hostname': hostname,
                    'raw_output': result.stdout,
                    'status': 'success'
                }
        else:
            return {
                'hostname': hostname,
                'error': result.stderr,
                'status': 'failed'
            }
    except subprocess.TimeoutExpired:
        return {
            'hostname': hostname,
            'error': 'Scan timeout',
            'status': 'timeout'
        }
    except FileNotFoundError:
        # Nmap not available, do basic port check
        return basic_port_check(hostname)
    except Exception as e:
        return {
            'hostname': hostname,
            'error': str(e),
            'status': 'error'
        }

def basic_port_check(hostname):
    """Basic port connectivity check if nmap is not available"""
    print(f"Performing basic port check on: {hostname}")
    
    common_ports = [80, 443, 22, 21, 25, 3306, 5432, 8080, 8443]
    results = {
        'hostname': hostname,
        'open_ports': [],
        'method': 'basic_socket_check'
    }
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                results['open_ports'].append({
                    'port': port,
                    'status': 'open'
                })
            sock.close()
        except Exception as e:
            pass
    
    return results

def main():
    targets = [
        'aps.academicae.com',
        'app.hello-teacher.ai'
    ]
    
    results = {}
    for target in targets:
        results[target] = nmap_scan(target)
    
    # Save results
    output_file = '/workspace/results/infrastructure_scan.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\nResults saved to: {output_file}")
    return results

if __name__ == '__main__':
    main()
