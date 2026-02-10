# 🛠 Wazuh SIEM – VirusTotal Integration (Commands & Execution)

## 📘 Execution Overview

This document contains the **exact commands and execution workflow** used to deploy Wazuh SIEM, onboard agents, integrate VirusTotal threat intelligence, configure File Integrity Monitoring (FIM), and validate detections. The steps align strictly with the lab implementation documented in the PDF.


## 🔹 Phase 1: Wazuh Manager Verification (Kali Linux)

### Check Wazuh Manager Service Status

```bash
sudo systemctl status wazuh-manager
```

### Restart Wazuh Manager (After Configuration Changes)

```bash
sudo systemctl restart wazuh-manager
```

### Confirm Manager Is Active

```bash
sudo systemctl is-active wazuh-manager
```

### Access Wazuh Dashboard

Open in browser:

```
https://<WAZUH_MANAGER_IP>
```


## 🔹 Phase 2: Wazuh Agent Deployment (Ubuntu Endpoint)

### Download Wazuh Agent Package

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.13.1-1_amd64.deb
```

### Install Agent and Configure Manager Connection

```bash
sudo WAZUH_MANAGER='<WAZUH_MANAGER_IP>' \
WAZUH_AGENT_NAME='ubuntu-agent' \
dpkg -i ./wazuh-agent_4.13.1-1_amd64.deb
```

### Reload systemd Services

```bash
sudo systemctl daemon-reload
```

### Enable Agent at Boot

```bash
sudo systemctl enable wazuh-agent
```

### Start Wazuh Agent Service

```bash
sudo systemctl start wazuh-agent
```


## 🔹 Phase 3: Agent Verification (Manager Side)

### List Registered Agents

```bash
sudo /var/ossec/bin/agent_control -l
```


## 🔹 Phase 4: VirusTotal Integration Configuration

### Edit Wazuh Configuration File

```bash
sudo nano /var/ossec/etc/ossec.conf
```

### VirusTotal Integration Block

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

### Restart Wazuh Manager to Apply Integration

```bash
sudo systemctl restart wazuh-manager
```


## 🔹 Phase 5: Integration Script Verification

### Navigate to Integration Scripts Directory

```bash
cd /var/ossec/integrations/
```

### Verify VirusTotal Script Presence

```bash
ls | grep virustotal.py
```

### Set Correct Ownership and Permissions

```bash
sudo chown root:wazuh virustotal.py
sudo chmod 750 virustotal.py
```

### Verify Permissions

```bash
ls -la virustotal.py
```


## 🔹 Phase 6: File Integrity Monitoring (FIM) Configuration

### Create Monitored Directory (Ubuntu Agent)

```bash
mkdir ~/FIM
```

### Update FIM Configuration on Manager

```bash
sudo nano /var/ossec/etc/ossec.conf
```

### FIM Directory Configuration

```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/home/safwan/FIM</directories>
```

### Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
```


## 🔹 Phase 7: Malware Detection Validation

### Create EICAR Test File

```bash
touch eicar.com
chmod 777 eicar.com
nano eicar.com
```

### Insert EICAR Test String

```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

### Verify File Creation

```bash
ls -l eicar.com
```


## 🔹 Phase 8: Benign File Test

### Create Benign File

```bash
touch benignfile.txt
```


## 🔹 Phase 9: Suspicious Hash Test

### Create File Containing Known Malicious Hash

```bash
touch knownmalware.txt
nano knownmalware.txt
```


## 🔹 Phase 10: File Modification Test

### Modify Existing File

```bash
nano benignfile.txt
```


## ✅ Expected Results

* FIM detects file creation and modification
* VirusTotal enriches alerts automatically
* EICAR file triggers high-severity alert
* Benign files generate low-severity alerts
* Modified files trigger checksum violation alerts

---

**Author:** Muhammad Safwan
**Domain:** SOC Operations • SIEM • Threat Intelligence


