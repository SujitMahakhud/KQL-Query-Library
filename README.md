# 🔍 KQL-Query-Library

[![GitHub license](https://img.shields.io/github/license/SujitMahakhud/KQL-Query-Library)](https://github.com/SujitMahakhud/KQL-Query-Library/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/SujitMahakhud/KQL-Query-Library)](https://github.com/SujitMahakhud/KQL-Query-Library/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/SujitMahakhud/KQL-Query-Library)](https://github.com/SujitMahakhud/KQL-Query-Library/network)
[![Azure Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?logo=microsoft)](https://azure.microsoft.com/en-us/services/azure-sentinel/)
[![KQL](https://img.shields.io/badge/Language-KQL-00D4FF)](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)

> **Production-ready KQL queries for Microsoft Sentinel threat hunting, SOC analysis, and security monitoring**

A curated collection of 50+ Kusto Query Language (KQL) queries designed for cybersecurity professionals working with Microsoft Sentinel, Azure Log Analytics, and Microsoft Defender. Each query includes detailed explanations, use cases, and performance optimization tips.

## 🚀 Quick Start

### Prerequisites
- Microsoft Sentinel workspace
- Azure Log Analytics workspace
- Appropriate data connectors configured
- KQL query permissions

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/SujitMahakhud/KQL-Query-Library.git
   ```
2. Browse to query categories in the `/queries` directory
3. Copy and paste queries into your Sentinel workspace
4. Modify time ranges and parameters as needed

## 📚 Query Categories

### 🔥 Threat Hunting
- **Advanced Persistent Threats (APT)**: Detection of sophisticated attack patterns
- **Lateral Movement**: Identifying unauthorized network traversal
- **Command & Control**: C2 communication detection
- **Data Exfiltration**: Unusual data transfer patterns

### 🚨 Incident Response
- **Timeline Analysis**: Event correlation and chronology
- **Impact Assessment**: Scope and severity evaluation
- **Evidence Collection**: Forensic data gathering
- **Root Cause Analysis**: Attack vector identification

### 📊 Performance Monitoring
- **Resource Utilization**: System performance metrics
- **Query Optimization**: Performance tuning queries
- **Data Ingestion**: Log collection statistics
- **Alert Efficiency**: Detection rule performance

### ✅ Compliance & Auditing
- **Access Reviews**: User activity monitoring
- **Configuration Drift**: Security baseline validation
- **Privileged Operations**: Administrative action tracking
- **Data Governance**: Information classification monitoring

## 🔥 Featured Queries

### 1. Suspicious PowerShell Activity
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4688
| where ProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any ("Invoke-Expression", "DownloadString", "WebClient", "Base64")
| project TimeGenerated, Computer, Account, ProcessCommandLine
| order by TimeGenerated desc
```
**Use Case**: Detect obfuscated PowerShell execution commonly used in malware.

### 2. Failed Login Brute Force Detection
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
| project TimeGenerated, UserPrincipalName, IPAddress, FailedAttempts
| order by FailedAttempts desc
```
**Use Case**: Identify potential brute force attacks against user accounts.

### 3. Anomalous Network Traffic
```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Palo Alto Networks"
| summarize TotalBytes = sum(SentBytes + ReceivedBytes) by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| where TotalBytes > 1000000000  // 1GB threshold
| project TimeGenerated, SourceIP, DestinationIP, TotalBytes
| order by TotalBytes desc
```
**Use Case**: Detect unusual data transfer volumes that may indicate data exfiltration.

### 4. Privilege Escalation Attempts
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4672, 4624, 4625)
| where AccountType == "User"
| where LogonType in (2, 3, 10)
| project TimeGenerated, Computer, Account, EventID, LogonType
| order by TimeGenerated desc
```
**Use Case**: Monitor for unauthorized privilege elevation activities.

### 5. DNS Tunneling Detection
```kql
DnsEvents
| where TimeGenerated > ago(24h)
| where QueryType == "TXT" or SubType == "request"
| summarize RequestCount = count(), UniqueQueries = dcount(Name) by ClientIP, bin(TimeGenerated, 10m)
| where RequestCount > 100 or UniqueQueries > 50
| project TimeGenerated, ClientIP, RequestCount, UniqueQueries
| order by RequestCount desc
```
**Use Case**: Identify potential DNS tunneling for data exfiltration or C2 communication.

## 📖 Documentation

- [KQL Query Best Practices](docs/best-practices.md)
- [Performance Optimization Guide](docs/performance-tuning.md)
- [Common Use Cases](docs/use-cases.md)
- [Alert Rule Templates](docs/alert-templates.md)
- [Hunting Playbooks](docs/hunting-playbooks.md)

## 🛡️ Security Focus Areas

| Category | Queries | Difficulty | Use Case |
|----------|---------|------------|----------|
| **Identity & Access** | 15+ | Beginner-Advanced | User behavior analytics, privilege monitoring |
| **Network Security** | 12+ | Intermediate-Advanced | Traffic analysis, threat detection |
| **Endpoint Security** | 18+ | Beginner-Expert | Process monitoring, malware detection |
| **Cloud Security** | 10+ | Intermediate-Advanced | Azure resource monitoring, SaaS security |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-query`)
3. Add your KQL query with documentation
4. Test the query in your environment
5. Commit changes (`git commit -am 'Add new threat hunting query'`)
6. Push to branch (`git push origin feature/new-query`)
7. Create a Pull Request

### Query Submission Guidelines
- Include query description and use case
- Add performance considerations
- Provide sample output when possible
- Follow KQL best practices
- Test thoroughly before submission

## 📋 Requirements

- **Microsoft Sentinel**: Workspace with appropriate data connectors
- **Azure Log Analytics**: Workspace access and query permissions
- **Data Sources**: Security events, sign-in logs, DNS events, network logs
- **Permissions**: SecurityReader or higher role in Azure

## 🏆 Featured By

- Microsoft Security Community
- Azure Sentinel Technical Documentation
- KQL Query Gallery
- Threat Hunting Community

## 📞 Support & Contact

- 🐛 **Issues**: [GitHub Issues](https://github.com/SujitMahakhud/KQL-Query-Library/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/SujitMahakhud/KQL-Query-Library/discussions)
- 📧 **Email**: sujit@secbyte.in
- 🌐 **Blog**: [SecByte.in](https://secbyte.in)
- 💼 **LinkedIn**: [@SujitMahakhud](https://linkedin.com/in/sujitmahakhud)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Microsoft Security Community for KQL best practices
- Azure Sentinel team for excellent documentation
- Security researchers and practitioners who shared their knowledge
- Open source contributors who helped improve these queries

---

**⭐ Star this repository if you find it useful!**

**🔗 Connect with me**: [LinkedIn](https://linkedin.com/in/sujitmahakhud) | [Blog](https://secbyte.in) | [GitHub](https://github.com/SujitMahakhud)
