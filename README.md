# 🛡 Wazuh SIEM – VirusTotal Threat Intelligence Integration

## 📘 Project Overview
This repository documents a hands-on SOC project implementing **Wazuh SIEM integrated with VirusTotal** to enrich File Integrity Monitoring (FIM) alerts with external threat intelligence and enable accurate malware detection and alert analysis.

The project reflects **real SOC workflows**, including deployment, integration, testing, alert validation, and incident response.

📄 **Detailed Documentation**
- **Technical Report (PDF):** [Wazuh With VirusTotal Integration](./Wazuh%20With%20VirusTotal.pdf)
- **Commands & Execution Guide:** ([Commands.md](https://github.com/MSafwanAwan/VirusTotal-integration-with-Wazuh/blob/main/Commands.md))

---

## 🎯 Project Objectives
- Deploy and validate Wazuh Manager and Agent
- Configure real-time File Integrity Monitoring (FIM)
- Integrate VirusTotal API for automated hash reputation checks
- Detect and classify malicious, benign, and modified files
- Analyze enriched alerts using the Wazuh Dashboard
- Demonstrate SOC-aligned incident response workflow


## 🏗 Architecture Overview
- **Wazuh Manager:** Centralized log analysis and correlation
- **Wazuh Agent (Ubuntu):** Endpoint monitoring and file activity detection
- **VirusTotal API:** External malware intelligence enrichment
- **Wazuh Dashboard:** Alert visualization and investigation


## ⚙️ Technologies & Tools
- Wazuh SIEM (Manager & Agent)
- VirusTotal Threat Intelligence API
- Linux (Kali Linux, Ubuntu)
- File Integrity Monitoring (Syscheck)
- SOC Alert Analysis & Triage


## 🧪 Validation & Testing
The following scenarios were executed to validate detection accuracy:

- **Benign File Creation:** Correctly classified with no VirusTotal detections  
- **Known Malicious Hash (Text):** Validated hash-based detection logic  
- **EICAR Test File:** High-severity alert with multi-engine detection  
- **File Modification:** Integrity checksum change detected  


## 📊 Alert Severity Mapping
| Event Type | VirusTotal Result | Alert Severity |
|-----------|------------------|----------------|
| Benign File | No records | Low |
| Hash as Text | Not malicious | Low |
| EICAR File | Detected | High |
| File Modification | Checksum changed | Medium |


## 🚨 Incident Response Workflow
1. File activity detected by Wazuh FIM  
2. Cryptographic hash generated automatically  
3. VirusTotal reputation lookup performed  
4. Alert enriched with threat intelligence  
5. SOC investigation and classification  
6. Alert closure or escalation  

---

## 📁 Repository Structure


