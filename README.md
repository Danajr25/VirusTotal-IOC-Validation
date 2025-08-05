# VirusTotal IOC Automation Tool

An automated Python solution for processing and analyzing Indicators of Compromise (IOCs) using the VirusTotal API. This tool streamlines threat intelligence workflows by automatically categorizing file hashes, IP addresses, and CVEs based on Palo Alto Networks XDR detection capabilities.

## 🎯 Overview

The VirusTotal IOC Automation Tool eliminates manual IOC analysis by automatically processing mixed security indicators and organizing them into actionable threat intelligence categories. It integrates seamlessly with Palo Alto Networks XDR to determine coverage gaps and prioritize security responses.

## ✨ Key Features

- **🔍 Multi-IOC Support**: Processes file hashes (MD5/SHA1/SHA256), IP addresses, and CVE identifiers
- **🤖 Intelligent Categorization**: Automatically routes IOCs based on Palo Alto Networks XDR coverage
- **📊 Excel Integration**: Seamless input/output via Excel spreadsheets
- **⚡ Bulk Processing**: Handles mixed IOC types in a single batch operation
- **🛡️ XDR Gap Analysis**: Identifies threats not covered by current XDR deployment
- **📈 Threat Intelligence**: Generates organized reports for security teams

## 🏗️ Architecture

```
File2.xlsx (Input) → IOC Detection → VirusTotal API → Palo Alto Analysis → Categorized Output (File1_filled.xlsx)
```

## 🚀 Quick Start

### Prerequisites

```bash
pip install requests pandas openpyxl
```

### Setup

1. **Get VirusTotal API Key**
   - Sign up at [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Generate your API key

2. **Configure the Tool**
   ```python
   # Update in run.py
   VT_API_KEY = 'your_virustotal_api_key_here'
   ```

3. **Prepare Input File**
   - Add IOCs to column A in `File2.xlsx`
   - Supports mixed formats (hashes, IPs, CVEs)

### Usage

```bash
python run.py
```

## 📊 IOC Processing Logic

### 🔐 File Hash Analysis
```
Hash Input → VirusTotal Lookup → Palo Alto Verdict Check
├── Malicious + PA Detects → Sheet1 (XDR Covered)
├── Malicious + PA Misses → Sheet3 (Coverage Gap)
└── Clean/Unknown → Sheet2 (No Action Needed)
```

### 🌐 IP Address Analysis
```
IP Input → VirusTotal Reputation → Palo Alto Engine Check
└── All IPs → DomainIP Sheet (with verdict classification)
```

### 🚨 CVE Processing
```
CVE Input → Direct Cataloging → CVE Sheet (No analysis required)
```

## 📋 Output Categories

### XDR Coverage Analysis
| Sheet | Category | Description |
|-------|----------|-------------|
| **Sheet1** | 🛡️ **XDR Covered** | Threats detected by Palo Alto XDR |
| **Sheet2** | ✅ **Clean/Unknown** | Non-malicious or unfound IOCs |
| **Sheet3** | ⚠️ **Coverage Gap** | Malicious IOCs missed by XDR |
| **DomainIP** | 🌐 **IP Intelligence** | All IP addresses with verdicts |
| **CVE** | 🚨 **Vulnerabilities** | CVE identifiers for tracking |

### Verdict Classifications
- **"Malware Covered by XDR"** - Threats your XDR will catch
- **"Malware Not Covered by XDR"** - Security gaps requiring attention
- **"Clean"** - Legitimate resources
- **"Not Found"** - Unknown IOCs requiring investigation

## 🔧 Configuration

### Input Format (File2.xlsx)
Place IOCs in Column A - the tool auto-detects formats:

```
Column A Examples:
5d41402abc4b2a76b9719d911017c592        # MD5 Hash
356a192b7913b04c54574d18c28d46e6395428ab  # SHA1 Hash
e3b0c44298fc1c149afbf4c8996fb924...        # SHA256 Hash
192.168.1.1                              # IP Address
2001:db8::1                              # IPv6 Address
CVE-2023-1234                            # CVE Identifier
random_string_not_hash                   # Treated as unknown hash
```

### API Configuration
The tool uses VirusTotal API v3 endpoints:
- **Files**: `/files/{hash}` for hash analysis
- **IPs**: `/ip_addresses/{ip}` for reputation data
- **Engine Focus**: Specifically monitors "Paloalto" engine verdicts

## 📈 Sample Output

```bash
Checking: 5d41402abc4b2a76b9719d911017c592
  → Sheet3: Malware not covered by XDR (Palo Alto verdict: Not Found)

Checking: 192.168.1.100
  → DomainIP: Malicious IP covered by XDR (Palo Alto verdict: malicious)

Checking: CVE-2023-0001
  → CVE: Added to CVE sheet

✅ Done. Output saved to File1_filled.xlsx
```

## 🛠️ Advanced Features

### Error Handling
- **Rate Limiting**: Respects VirusTotal API constraints
- **Network Issues**: Graceful handling of connection problems
- **Invalid IOCs**: Unknown formats treated appropriately
- **Missing Data**: Comprehensive logging for troubleshooting

## 🔍 Use Cases

### Security Operations Center (SOC)
- **Threat Hunting**: Bulk IOC validation from threat feeds
- **Incident Response**: Quick analysis of compromise indicators
- **Coverage Assessment**: Identify XDR detection gaps

### Threat Intelligence Teams
- **Feed Processing**: Automated analysis of intelligence feeds
- **IOC Enrichment**: Add context to raw indicators
- **Report Generation**: Create categorized threat reports

### Red Team / Penetration Testing
- **Tool Validation**: Test XDR detection capabilities
- **Coverage Testing**: Identify security blind spots
- **Baseline Assessment**: Document current detection posture

## ⚠️ Important Notes

### Security Considerations
- **API Key Protection**: Store API keys securely, never commit to version control
- **Rate Limiting**: Free VirusTotal accounts have request limits
- **Data Sensitivity**: IOCs may contain sensitive threat intelligence

### Performance Tips
- **Batch Size**: Process IOCs in reasonable batches to avoid timeouts
- **Network Stability**: Ensure stable internet connection for API calls
- **Disk Space**: Large outputs may require adequate storage

**Built for Security Teams** | **Powered by VirusTotal** | **Optimized for Palo Alto XDR**
