# Elasticsearch Security Auditor

A comprehensive, production-safe security auditing tool for Elasticsearch clusters designed for security testers, auditors, and penetration testers.

**Author:** Garland Glessner <gglessner@gmail.com>  
**License:** GNU General Public License v3.0

## Features

- **Live CVE Lookup (NVD):** Checks Elasticsearch and Kibana versions against the National Vulnerability Database (NVD) for known CVEs using `nvdlib`.
- **Version Detection:** Identify Elasticsearch and Kibana versions, warn if EOL or unsupported.
- **TLS/SSL Assessment:** Validate encryption, certificate information, and warn if traffic is unencrypted.
- **Cluster Health Analysis:** Check cluster status, node info, and topology (single point of failure, exposed nodes).
- **Security Configuration Review:** Assess security settings, authentication, X-Pack, and compliance features (FIPS, encryption at rest).
- **Audit Logging Check:** Detect if audit logging is enabled for forensic and compliance purposes.
- **IP Filtering/Traffic Filtering:** Check for IP-based access controls and traffic filtering settings.
- **Secure Settings Review:** Check for secure settings referenced in the keystore/configuration.
- **User and Role Analysis:** Review user accounts, roles, default/built-in users, and permissions (if accessible).
- **API Key Review:** Enumerate API keys and their properties (if permissions allow).
- **Plugin Assessment:** Identify installed plugins, especially security-related or risky plugins.
- **Index Security:** List all indices, flag potentially sensitive names, and check for open or world-readable indices.
- **Snapshot Repository Check:** List snapshot repositories and their settings, flagging insecure or public storage.
- **Remote Cluster Check:** List remote clusters and cross-cluster search/replication settings.
- **Kibana Detection & Security:** Detect Kibana, check its version, and look up known CVEs.
- **Comprehensive Reporting:** Generate detailed JSON reports with all findings, categorized by severity.
- **Non-Destructive, Production-Safe:** All checks are read-only, leave no trace, and avoid any denial-of-service or brute-force actions.

## Installation

1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
# Connect to local Elasticsearch
python ElasticsearchClient.py <host> <port>

# Connect with TLS/SSL
python ElasticsearchClient.py elasticsearch.example.com 9200 --tls

# Authenticated connection
python ElasticsearchClient.py localhost 9200 --username elastic --password changeme

# Save report to file
python ElasticsearchClient.py localhost 9200 --output security_report.json
```

### Comprehensive Testing

For thorough testing of all functions against your Elasticsearch server:

```bash
# Run comprehensive audit with all security checks
python run_full_audit.py
```

This will generate a timestamped report file: `es_<host>_<port>_<YYYYMMDD_HHMMSS>.json`

### Command Line Options

- `host`: Elasticsearch host address
- `port`: Elasticsearch port number
- `--tls`: Use TLS/SSL connection
- `--username`: Username for authentication
- `--password`: Password for authentication
- `--timeout`: Connection timeout in seconds (default: 30)
- `--output`: Output file for JSON report
- `--verbose`: Verbose output

### Examples

```bash
# Basic security audit
python ElasticsearchClient.py <host> <port>

# TLS-enabled audit with authentication
python ElasticsearchClient.py elastic.company.com 9200 --tls --username admin --password secure123

# Generate detailed report
python ElasticsearchClient.py <host> <port> --output audit_report.json --verbose

# Comprehensive audit with auto-generated filename
python run_full_audit.py
```

## Security Features

### Live CVE Lookup (NVD)
- Checks Elasticsearch and Kibana versions against the National Vulnerability Database (NVD) for known vulnerabilities in real time.
- Reports CVE IDs, descriptions, CVSS scores, and publication dates.

### Security & Compliance Checks
- **Audit Logging:** Detects if audit logging is enabled for compliance and forensics.
- **IP Filtering:** Checks for IP-based access controls and traffic filtering.
- **Secure Settings:** Flags if secure settings are referenced in the keystore/configuration.
- **Compliance:** Checks for FIPS mode, encryption at rest, and security plugins (X-Pack, Shield, Search Guard).

### Cluster & Data Exposure
- **Cluster Health:** Assesses cluster health, node roles, and topology.
- **Indices:** Lists all indices, flags sensitive names, and checks for open or world-readable indices.
- **Snapshot Repositories:** Lists snapshot repositories and flags insecure or public storage.
- **Remote Clusters:** Lists remote clusters and cross-cluster search/replication settings.

### Access Control Review
- **Users & Roles:** Enumerates users, roles, and default/built-in accounts (if permissions allow).
- **API Keys:** Enumerates API keys and their properties (if permissions allow).

### Kibana Security
- Detects Kibana, checks its version, and performs live CVE lookup for known vulnerabilities.

### Reporting
- Generates a comprehensive JSON report with all findings, categorized by severity (HIGH, MEDIUM, LOW, INFO).
- Summarizes total findings and highlights high-severity issues.
- Auto-generates timestamped filenames for easy organization.

### Non-Destructive, Production-Safe
- All checks are read-only and do not modify data or settings.
- No brute force, no destructive API calls, no index dumps, no shutdowns, no stress tests.

## Output

The tool generates comprehensive reports including:

- **Audit Metadata:** Tool information, scan timestamp, detailed target information
- **Security Findings:** Categorized by severity (HIGH, MEDIUM, LOW, INFO)
- **Detailed Information:** Technical details for each finding
- **Summary Statistics:** Count of findings by severity level

### Report Filename Format

Reports are automatically saved with the format: `es_<host>_<port>_<YYYYMMDD_HHMMSS>.json`

Example: `es_127.0.0.1_9200_20250619_204510.json`

### Sample Output

```json
{
  "audit_metadata": {
    "tool": "Elasticsearch Security Auditor",
    "author": "Garland Glessner <gglessner@gmail.com>",
    "license": "GNU General Public License v3.0",
    "scan_timestamp": "2025-06-19T20:45:08.433529",
    "target": {
      "host": "127.0.0.1",
      "port": 9200,
      "full_address": "127.0.0.1:9200"
    },
    "connection": {
      "tls_enabled": false,
      "protocol": "http",
      "username": "elastic"
    }
  },
  "summary": {
    "total_findings": 20,
    "high_severity": 1,
    "medium_severity": 4,
    "low_severity": 0,
    "info": 14
  },
  "findings": [
    {
      "severity": "HIGH",
      "title": "Security Disabled",
      "description": "X-Pack security may not be enabled - cluster may be unprotected",
      "timestamp": "2025-06-19T20:45:08.433529"
    }
  ]
}
```

## Security Considerations

- Use only in authorized environments
- All checks are non-destructive and production-safe
- No denial-of-service or brute-force actions are performed
- Document all findings and recommendations
- Follow responsible disclosure practices

## Limitations

- Requires appropriate permissions for comprehensive assessment
- Some features may not work with all Elasticsearch versions
- Network connectivity and firewall rules may affect results
- SSL certificate validation is disabled for security testing
- Actual keystore contents are not accessible via API (best-effort checks only)

## Contributing

This tool is designed for security professionals. Please:
- Test thoroughly before using in production
- Report bugs and suggest improvements
- Follow security best practices
- Respect licensing terms

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before conducting security assessments. The author is not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details. 