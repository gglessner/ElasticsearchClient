#!/usr/bin/env python3
"""
Elasticsearch Security Auditor Client
Author: Garland Glessner <gglessner@gmail.com>
License: GNU General Public License v3.0

A comprehensive security auditing tool for Elasticsearch clusters.
Designed for security testers, auditors, and penetration testers.
"""

import argparse
import json
import sys
import time
import urllib3
from datetime import datetime
from elasticsearch import Elasticsearch, ConnectionTimeout, ConnectionError, AuthenticationException
from elasticsearch.exceptions import NotFoundError, RequestError
import ssl
import socket
import requests
from requests.exceptions import RequestException
import warnings
import nvdlib

# Suppress SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def json_serializer(obj):
    """Custom JSON serializer for objects not serializable by default json code"""
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    elif hasattr(obj, 'to_dict'):
        return obj.to_dict()
    elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes, bytearray)):
        return list(obj)
    else:
        return str(obj)

class ElasticsearchAuditor:
    def __init__(self, host, port, use_tls=False, username=None, password=None, timeout=30):
        """
        Initialize the Elasticsearch auditor
        
        Args:
            host (str): Elasticsearch host
            port (int): Elasticsearch port
            use_tls (bool): Whether to use TLS/SSL
            username (str): Username for authentication
            password (str): Password for authentication
            timeout (int): Connection timeout in seconds
        """
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.timeout = timeout
        self.client = None
        self.audit_results = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{host}:{port}",
            'tls_enabled': use_tls,
            'findings': []
        }
        
    def connect(self):
        """Establish connection to Elasticsearch"""
        try:
            protocol = "https" if self.use_tls else "http"
            url = f"{protocol}://{self.host}:{self.port}"
            
            # Configure authentication if provided
            auth = None
            if self.username and self.password:
                auth = (self.username, self.password)
            
            # Configure SSL verification
            verify_ssl = True
            if self.use_tls:
                # For security testing, we might want to verify SSL
                # but allow self-signed certificates
                verify_ssl = False
            
            self.client = Elasticsearch(
                [url],
                basic_auth=auth,
                verify_certs=verify_ssl,
                request_timeout=self.timeout,
                max_retries=3,
                retry_on_timeout=True
            )
            
            # Test connection
            if self.client.ping():
                self.add_finding("INFO", "Connection successful", "Successfully connected to Elasticsearch")
                return True
            else:
                self.add_finding("ERROR", "Connection failed", "Could not ping Elasticsearch server")
                return False
                
        except AuthenticationException as e:
            self.add_finding("HIGH", "Authentication failed", f"Authentication error: {str(e)}")
            return False
        except ConnectionError as e:
            self.add_finding("HIGH", "Connection error", f"Connection error: {str(e)}")
            return False
        except Exception as e:
            self.add_finding("ERROR", "Unexpected error", f"Unexpected error during connection: {str(e)}")
            return False
    
    def add_finding(self, severity, title, description, details=None):
        """Add a security finding to the audit results"""
        finding = {
            'severity': severity,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        if details:
            finding['details'] = details
        self.audit_results['findings'].append(finding)
    
    def get_server_info(self):
        """Get server version and basic information"""
        try:
            info = self.client.info()
            version = info.get('version', {})
            
            self.add_finding("INFO", "Server Information", "Retrieved server information", {
                'version': version.get('number'),
                'build_hash': version.get('build_hash'),
                'build_date': version.get('build_date'),
                'lucene_version': version.get('lucene_version'),
                'cluster_name': info.get('cluster_name'),
                'cluster_uuid': info.get('cluster_uuid'),
                'name': info.get('name')
            })
            
            return info
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get server info", f"Error retrieving server information: {str(e)}")
            return None
    
    def check_cluster_health(self):
        """Check cluster health and status"""
        try:
            health = self.client.cluster.health()
            
            self.add_finding("INFO", "Cluster Health", "Retrieved cluster health information", {
                'cluster_name': health.get('cluster_name'),
                'status': health.get('status'),
                'number_of_nodes': health.get('number_of_nodes'),
                'active_primary_shards': health.get('active_primary_shards'),
                'active_shards': health.get('active_shards'),
                'relocating_shards': health.get('relocating_shards'),
                'initializing_shards': health.get('initializing_shards'),
                'unassigned_shards': health.get('unassigned_shards'),
                'delayed_unassigned_shards': health.get('delayed_unassigned_shards'),
                'number_of_pending_tasks': health.get('number_of_pending_tasks'),
                'number_of_in_flight_fetch': health.get('number_of_in_flight_fetch'),
                'task_max_waiting_in_queue_millis': health.get('task_max_waiting_in_queue_millis'),
                'active_shards_percent_as_number': health.get('active_shards_percent_as_number')
            })
            
            # Check for potential issues
            if health.get('status') == 'red':
                self.add_finding("HIGH", "Cluster Status Red", "Cluster is in RED status - data may be unavailable")
            elif health.get('status') == 'yellow':
                self.add_finding("MEDIUM", "Cluster Status Yellow", "Cluster is in YELLOW status - some replicas may be unavailable")
            
            if health.get('unassigned_shards', 0) > 0:
                self.add_finding("MEDIUM", "Unassigned Shards", f"Found {health.get('unassigned_shards')} unassigned shards")
                
            return health
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get cluster health", f"Error retrieving cluster health: {str(e)}")
            return None
    
    def check_indices(self):
        """Check indices and their settings"""
        try:
            indices = self.client.cat.indices(format='json')
            
            self.add_finding("INFO", "Indices Information", f"Found {len(indices)} indices", {
                'indices': indices
            })
            
            # Check for sensitive indices
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'credential', 'auth']
            for index in indices:
                index_name = index.get('index', '')
                for pattern in sensitive_patterns:
                    if pattern.lower() in index_name.lower():
                        self.add_finding("MEDIUM", "Potentially Sensitive Index", 
                                       f"Index '{index_name}' may contain sensitive data", {
                                           'index_name': index_name,
                                           'pattern_matched': pattern
                                       })
                        break
            
            return indices
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get indices", f"Error retrieving indices: {str(e)}")
            return None
    
    def check_security_settings(self):
        """Check security-related settings and configurations"""
        try:
            # Check if security is enabled
            settings = self.client.cluster.get_settings()
            
            # Check for security settings
            security_settings = {}
            
            # Check if security is enabled
            if 'xpack.security.enabled' in str(settings):
                self.add_finding("INFO", "Security Enabled", "X-Pack security appears to be enabled")
                security_settings['security_enabled'] = True
            else:
                self.add_finding("HIGH", "Security Disabled", "X-Pack security may not be enabled - cluster may be unprotected")
                security_settings['security_enabled'] = False
            
            # Check for SSL/TLS settings
            if self.use_tls:
                self.add_finding("INFO", "TLS Enabled", "TLS/SSL is enabled for this connection")
                security_settings['tls_enabled'] = True
            else:
                self.add_finding("MEDIUM", "TLS Disabled", "TLS/SSL is not enabled - traffic may be unencrypted")
                security_settings['tls_enabled'] = False
            
            self.add_finding("INFO", "Security Settings", "Retrieved security-related settings", security_settings)
            
            return security_settings
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get security settings", f"Error retrieving security settings: {str(e)}")
            return None
    
    def check_users_and_roles(self):
        """Check users and roles (if accessible)"""
        try:
            # Try to get users (requires appropriate permissions)
            users = self.client.security.get_user()
            
            self.add_finding("INFO", "Users Information", f"Found {len(users)} users", {
                'users': list(users.keys())
            })
            
            # Check for default/admin users
            default_users = ['elastic', 'kibana', 'logstash_system', 'beats_system']
            for user in default_users:
                if user in users:
                    self.add_finding("MEDIUM", "Default User Found", f"Default user '{user}' is present", {
                        'user': user,
                        'enabled': users[user].get('enabled', False)
                    })
            
            return users
            
        except Exception as e:
            self.add_finding("INFO", "Users Access Restricted", f"Cannot access user information: {str(e)}")
            return None
    
    def check_plugins(self):
        """Check installed plugins"""
        try:
            plugins = self.client.cat.plugins(format='json')
            
            self.add_finding("INFO", "Plugins Information", f"Found {len(plugins)} plugins", {
                'plugins': [p.get('name') for p in plugins]
            })
            
            # Check for security-related plugins
            security_plugins = ['security', 'shield', 'x-pack']
            for plugin in plugins:
                plugin_name = plugin.get('name', '').lower()
                for sec_plugin in security_plugins:
                    if sec_plugin in plugin_name:
                        self.add_finding("INFO", "Security Plugin Found", f"Security-related plugin: {plugin.get('name')}")
                        break
            
            return plugins
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get plugins", f"Error retrieving plugins: {str(e)}")
            return None
    
    def check_node_info(self):
        """Check node information"""
        try:
            nodes = self.client.cat.nodes(format='json')
            
            self.add_finding("INFO", "Nodes Information", f"Found {len(nodes)} nodes", {
                'nodes': [{'name': n.get('name'), 'role': n.get('node.role')} for n in nodes]
            })
            
            # Check for master nodes
            master_nodes = [n for n in nodes if 'm' in n.get('node.role', '')]
            if len(master_nodes) == 1:
                self.add_finding("MEDIUM", "Single Master Node", "Only one master node found - single point of failure")
            elif len(master_nodes) == 0:
                self.add_finding("HIGH", "No Master Node", "No master nodes found - cluster may be unstable")
            
            return nodes
            
        except Exception as e:
            self.add_finding("ERROR", "Failed to get node info", f"Error retrieving node information: {str(e)}")
            return None
    
    def check_ssl_certificate(self):
        """Check SSL certificate information if TLS is enabled"""
        if not self.use_tls:
            return None
            
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.add_finding("INFO", "SSL Certificate Information", "Retrieved SSL certificate details", {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    })
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.add_finding("HIGH", "Certificate Expiring Soon", 
                                       f"SSL certificate expires in {days_until_expiry} days")
                    elif days_until_expiry < 90:
                        self.add_finding("MEDIUM", "Certificate Expiring", 
                                       f"SSL certificate expires in {days_until_expiry} days")
                    
                    return cert
                    
        except Exception as e:
            self.add_finding("ERROR", "Failed to get SSL certificate", f"Error retrieving SSL certificate: {str(e)}")
            return None
    
    def check_version_vulnerabilities(self, version):
        """Check for known vulnerabilities based on version using NVD API (live CVE lookup)"""
        try:
            # Use nvdlib to search for CVEs for Elasticsearch with this version
            cves = list(nvdlib.searchCVE(keywordSearch='elasticsearch', version=version, limit=10))
            if cves:
                cve_list = []
                for cve in cves:
                    cve_list.append({
                        'id': cve.id,
                        'description': cve.descriptions[0].value if cve.descriptions else '',
                        'cvssV3': getattr(cve, 'cvssV3', None),
                        'published': cve.published,
                        'lastModified': cve.lastModified
                    })
                self.add_finding("HIGH", "Known Vulnerabilities (NVD)", f"Version {version} has known CVEs in NVD", {'version': version, 'cves': cve_list})
            else:
                self.add_finding("INFO", "No Known Vulnerabilities (NVD)", f"No known vulnerabilities found for version {version} in NVD")
        except Exception as e:
            self.add_finding("ERROR", "CVE Lookup Failed", f"Error during NVD CVE lookup: {str(e)}")
    
    def check_audit_logging(self):
        """Check if audit logging is enabled (X-Pack or other)"""
        try:
            settings = self.client.cluster.get_settings()
            audit_enabled = False
            if 'xpack.security.audit.enabled' in str(settings):
                audit_enabled = True
            if audit_enabled:
                self.add_finding("INFO", "Audit Logging Enabled", "Audit logging is enabled in cluster settings.")
            else:
                self.add_finding("MEDIUM", "Audit Logging Disabled", "Audit logging is not enabled in cluster settings.")
        except Exception as e:
            self.add_finding("ERROR", "Audit Logging Check Failed", f"Error checking audit logging: {str(e)}")

    def check_ip_filtering(self):
        """Check if IP filtering or traffic filtering is enabled (Cloud or X-Pack)"""
        try:
            # Try to get IP filtering settings (may not be available on all clusters)
            settings = self.client.cluster.get_settings()
            if 'xpack.security.transport.filter.allow' in str(settings) or 'xpack.security.transport.filter.deny' in str(settings):
                self.add_finding("INFO", "IP Filtering Enabled", "IP filtering is enabled in cluster settings.")
            else:
                self.add_finding("MEDIUM", "IP Filtering Not Detected", "No IP filtering settings found in cluster settings.")
        except Exception as e:
            self.add_finding("ERROR", "IP Filtering Check Failed", f"Error checking IP filtering: {str(e)}")

    def check_secure_settings(self):
        """Check for secure settings in the keystore (not just config files)"""
        try:
            # This is a best-effort check; actual keystore contents are not accessible via API
            # But we can check if secure settings are referenced in the config
            settings = self.client.cluster.get_settings()
            if 'keystore.seed' in str(settings):
                self.add_finding("INFO", "Secure Settings Referenced", "Secure settings are referenced in the cluster config.")
            else:
                self.add_finding("INFO", "No Secure Settings Referenced", "No secure settings referenced in cluster config.")
        except Exception as e:
            self.add_finding("ERROR", "Secure Settings Check Failed", f"Error checking secure settings: {str(e)}")

    def check_compliance(self):
        """Check for compliance features: FIPS mode, encryption at rest, security plugins"""
        try:
            settings = self.client.cluster.get_settings()
            # FIPS mode
            if 'xpack.security.fips_mode.enabled' in str(settings):
                self.add_finding("INFO", "FIPS Mode Enabled", "FIPS mode is enabled in cluster settings.")
            else:
                self.add_finding("INFO", "FIPS Mode Not Detected", "FIPS mode is not enabled in cluster settings.")
            # Encryption at rest (best effort)
            if 'xpack.security.encrypt_at_rest' in str(settings):
                self.add_finding("INFO", "Encryption at Rest Enabled", "Encryption at rest is enabled in cluster settings.")
            else:
                self.add_finding("INFO", "Encryption at Rest Not Detected", "Encryption at rest is not detected in cluster settings.")
        except Exception as e:
            self.add_finding("ERROR", "Compliance Check Failed", f"Error checking compliance features: {str(e)}")

    def check_snapshot_repositories(self):
        """Check for snapshot repositories and their settings"""
        try:
            repos = self.client.snapshot.get_repository(repository='_all')
            if repos:
                self.add_finding("INFO", "Snapshot Repositories Found", f"Found {len(repos)} snapshot repositories", {'repositories': list(repos.keys())})
                # Check for public or insecure repositories (best effort)
                for name, repo in repos.items():
                    if repo.get('type') == 'fs' and 'location' in repo.get('settings', {}):
                        self.add_finding("MEDIUM", "Filesystem Snapshot Repository", f"Repository '{name}' uses filesystem storage at {repo['settings']['location']}")
                    if repo.get('type') == 's3' and 'bucket' in repo.get('settings', {}):
                        self.add_finding("INFO", "S3 Snapshot Repository", f"Repository '{name}' uses S3 bucket {repo['settings']['bucket']}")
            else:
                self.add_finding("INFO", "No Snapshot Repositories", "No snapshot repositories found.")
        except Exception as e:
            self.add_finding("ERROR", "Snapshot Repository Check Failed", f"Error checking snapshot repositories: {str(e)}")

    def check_remote_clusters(self):
        """Check for remote clusters and cross-cluster search/replication settings"""
        try:
            remotes = self.client.cluster.remote_info()
            if remotes:
                self.add_finding("INFO", "Remote Clusters Found", f"Found {len(remotes)} remote clusters", {'remote_clusters': list(remotes.keys())})
            else:
                self.add_finding("INFO", "No Remote Clusters", "No remote clusters configured.")
        except Exception as e:
            self.add_finding("ERROR", "Remote Cluster Check Failed", f"Error checking remote clusters: {str(e)}")

    def check_api_keys(self):
        """Check for API keys (if permissions allow)"""
        try:
            api_keys = self.client.security.get_api_key()
            if api_keys and 'api_keys' in api_keys:
                self.add_finding("INFO", "API Keys Found", f"Found {len(api_keys['api_keys'])} API keys", {'api_keys': api_keys['api_keys']})
            else:
                self.add_finding("INFO", "No API Keys", "No API keys found or accessible.")
        except Exception as e:
            self.add_finding("INFO", "API Key Access Restricted", f"Cannot access API key information: {str(e)}")

    def check_kibana(self):
        """Detect if Kibana is present and check its security posture"""
        try:
            # Try common Kibana ports and endpoints
            kibana_ports = [5601]
            for port in kibana_ports:
                protocol = "https" if self.use_tls else "http"
                url = f"{protocol}://{self.host}:{port}/api/status"
                try:
                    resp = requests.get(url, verify=False, timeout=5)
                    if resp.status_code == 200 and 'kibana' in resp.text.lower():
                        self.add_finding("INFO", "Kibana Detected", f"Kibana detected on port {port}")
                        # Try to get version
                        data = resp.json()
                        version = data.get('version', {}).get('number', 'Unknown')
                        self.add_finding("INFO", "Kibana Version", f"Kibana version: {version}")
                        # Check for known Kibana CVEs
                        cves = list(nvdlib.searchCVE(keywordSearch='kibana', version=version, limit=5))
                        if cves:
                            cve_list = []
                            for cve in cves:
                                cve_list.append({
                                    'id': cve.id,
                                    'description': cve.descriptions[0].value if cve.descriptions else '',
                                    'cvssV3': getattr(cve, 'cvssV3', None),
                                    'published': cve.published,
                                    'lastModified': cve.lastModified
                                })
                            self.add_finding("HIGH", "Kibana Known Vulnerabilities (NVD)", f"Kibana version {version} has known CVEs in NVD", {'version': version, 'cves': cve_list})
                        else:
                            self.add_finding("INFO", "No Known Kibana Vulnerabilities (NVD)", f"No known vulnerabilities found for Kibana version {version} in NVD")
                        return
                except Exception:
                    continue
            self.add_finding("INFO", "Kibana Not Detected", "Kibana not detected on common ports.")
        except Exception as e:
            self.add_finding("ERROR", "Kibana Check Failed", f"Error checking Kibana: {str(e)}")

    def run_full_audit(self):
        """Run a complete security audit"""
        print(f"[*] Starting security audit of {self.host}:{self.port}")
        print(f"[*] TLS Enabled: {self.use_tls}")
        print("-" * 60)
        
        # Connect to Elasticsearch
        if not self.connect():
            print("[!] Failed to connect to Elasticsearch")
            return False
        
        # Get server information
        print("[*] Getting server information...")
        info = self.get_server_info()
        if info:
            version = info.get('version', {}).get('number', 'Unknown')
            print(f"[+] Elasticsearch version: {version}")
            self.check_version_vulnerabilities(version)
        
        # Check cluster health
        print("[*] Checking cluster health...")
        self.check_cluster_health()
        
        # Check indices
        print("[*] Checking indices...")
        self.check_indices()
        
        # Check security settings
        print("[*] Checking security settings...")
        self.check_security_settings()
        
        # Check audit logging
        print("[*] Checking audit logging...")
        self.check_audit_logging()
        
        # Check IP filtering
        print("[*] Checking IP filtering...")
        self.check_ip_filtering()
        
        # Check secure settings
        print("[*] Checking secure settings...")
        self.check_secure_settings()
        
        # Check compliance features
        print("[*] Checking compliance features...")
        self.check_compliance()
        
        # Check users and roles
        print("[*] Checking users and roles...")
        self.check_users_and_roles()
        
        # Check plugins
        print("[*] Checking plugins...")
        self.check_plugins()
        
        # Check node information
        print("[*] Checking node information...")
        self.check_node_info()
        
        # Check snapshot repositories
        print("[*] Checking snapshot repositories...")
        self.check_snapshot_repositories()
        
        # Check remote clusters
        print("[*] Checking remote clusters...")
        self.check_remote_clusters()
        
        # Check API keys
        print("[*] Checking API keys...")
        self.check_api_keys()
        
        # Check SSL certificate if TLS is enabled
        if self.use_tls:
            print("[*] Checking SSL certificate...")
            self.check_ssl_certificate()
        
        # Check Kibana
        print("[*] Checking Kibana...")
        self.check_kibana()
        
        print("-" * 60)
        print("[*] Audit completed")
        
        return True
    
    def generate_report(self, output_file=None):
        """Generate a comprehensive security report"""
        report = {
            'audit_metadata': {
                'tool': 'Elasticsearch Security Auditor',
                'author': 'Garland Glessner <gglessner@gmail.com>',
                'license': 'GNU General Public License v3.0',
                'scan_timestamp': datetime.now().isoformat(),
                'target': {
                    'host': self.host,
                    'port': self.port,
                    'full_address': f"{self.host}:{self.port}"
                },
                'connection': {
                    'tls_enabled': self.use_tls,
                    'protocol': 'https' if self.use_tls else 'http',
                    'username': self.username if self.username else 'none'
                }
            },
            'summary': {
                'total_findings': len(self.audit_results['findings']),
                'high_severity': len([f for f in self.audit_results['findings'] if f['severity'] == 'HIGH']),
                'medium_severity': len([f for f in self.audit_results['findings'] if f['severity'] == 'MEDIUM']),
                'low_severity': len([f for f in self.audit_results['findings'] if f['severity'] == 'LOW']),
                'info': len([f for f in self.audit_results['findings'] if f['severity'] == 'INFO'])
            },
            'findings': self.audit_results['findings']
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=json_serializer)
            print(f"[+] Report saved to {output_file}")
        else:
            print(json.dumps(report, indent=2, default=json_serializer))
        
        return report
    
    def cleanup(self):
        """Clean up resources"""
        if self.client:
            try:
                self.client.close()
            except:
                pass
        self.client = None

def main():
    parser = argparse.ArgumentParser(
        description='Elasticsearch Security Auditor - A comprehensive security assessment tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ElasticsearchClient.py localhost 9200
  python ElasticsearchClient.py elasticsearch.example.com 9200 --tls
  python ElasticsearchClient.py localhost 9200 --username elastic --password changeme
  python ElasticsearchClient.py localhost 9200 --output report.json
        """
    )
    
    parser.add_argument('host', help='Elasticsearch host')
    parser.add_argument('port', type=int, help='Elasticsearch port')
    parser.add_argument('--tls', action='store_true', help='Use TLS/SSL connection')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--timeout', type=int, default=30, help='Connection timeout in seconds (default: 30)')
    parser.add_argument('--output', help='Output file for JSON report')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.port < 1 or args.port > 65535:
        print("[!] Invalid port number. Must be between 1 and 65535.")
        sys.exit(1)
    
    if args.username and not args.password:
        print("[!] Password is required when username is provided.")
        sys.exit(1)
    
    # Create auditor instance
    auditor = ElasticsearchAuditor(
        host=args.host,
        port=args.port,
        use_tls=args.tls,
        username=args.username,
        password=args.password,
        timeout=args.timeout
    )
    
    try:
        # Run the audit
        success = auditor.run_full_audit()
        
        if success:
            # Generate report
            auditor.generate_report(args.output)
            
            # Print summary
            findings = auditor.audit_results['findings']
            high_count = len([f for f in findings if f['severity'] == 'HIGH'])
            medium_count = len([f for f in findings if f['severity'] == 'MEDIUM'])
            
            print(f"\n[*] Audit Summary:")
            print(f"    Total findings: {len(findings)}")
            print(f"    High severity: {high_count}")
            print(f"    Medium severity: {medium_count}")
            
            if high_count > 0:
                print(f"\n[!] {high_count} high severity findings detected!")
                for finding in findings:
                    if finding['severity'] == 'HIGH':
                        print(f"    - {finding['title']}: {finding['description']}")
        
    except KeyboardInterrupt:
        print("\n[!] Audit interrupted by user")
    except Exception as e:
        print(f"[!] Unexpected error: {str(e)}")
    finally:
        # Always cleanup
        auditor.cleanup()

if __name__ == "__main__":
    main() 