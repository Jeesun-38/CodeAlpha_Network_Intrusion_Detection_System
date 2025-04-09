# 📡 CodeAlpha_Network_Intrusion_Detection_System

This repository provides a step-by-step guide for setting up a Network Intrusion Detection System (NIDS) using Snort, developed during Task 3 of my Cybersecurity Internship at CodeAlpha.
The project includes a set of custom Snort rules designed to detect common attack patterns such as reconnaissance, brute-force.

---

## ⚙️ Setup Instructions

### 🧰 Prerequisites
- ✅ A working installation of **Snort 3**
- 🔐 Root or administrative access to modify Snort configuration files

### 📥 Step-by-Step Configuration

1. **📁 Save Local Rules File**  
   Place the custom rules into the following file:
   ```
   /usr/local/etc/snort/rules/local.rules
   ```

2. **📝 Modify Snort Configuration**  
   Ensure your `snort.lua` configuration includes the local rule set:
   ```lua
   include = 'local.rules'
   ```

3. **🚀 Run Snort in Alert Mode**  
   Launch Snort with the interface in promiscuous mode and fast alerting:
   ```bash
   sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast
   ```

---

## 🛡️ Rule Descriptions

### 🔍 Rule 1: ICMP Ping Detection
```snort
alert icmp any any -> 192.168.100.6 any (msg: "ICMP Ping Detected"; sid:100001;)
```
**Purpose**: Flags incoming ICMP echo requests, typically used in ping scans.

### 🔒 Rule 2: SSH Authentication Attempt
```snort
alert tcp any any -> 192.168.100.6 22 (msg: "SSH Authentication Attempt"; sid:100002; rev:1;)
```
**Purpose**: Detects initial connection attempts to SSH service, possibly indicative of brute-force or unauthorized access.

### 📡 Rule 3: FTP Authentication Attempt
```snort
alert tcp any any -> 192.168.100.6 21 (msg: "FTP Authentication Attempt On Metasploitable2"; sid:100003; rev:1;)
```
**Purpose**: Monitors access to FTP services on port 21.

### 🚨 Rule 4: Potential TCP SYN Flood (HTTP)
```snort
alert tcp any any -> 192.168.100.6 80 (msg: "Possible TCP DoS! Be Careful!"; flags: S; flow: stateless; sid:100004; rev:1;)
```
**Purpose**: Identifies TCP SYN packets sent to port 80, which may indicate a SYN flood attack.

### 🧪 Optional Rule: Advanced SYN Flood Detection (Commented Out)
```snort
# alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"SYN flood detected"; flags:S; flow:to_server,established; detection_filter:track by_src, count 10, seconds 1; sid:100005; rev:1;)
```
**Purpose**: Uses a threshold-based detection filter to catch high-rate SYN floods.

---

## 📁 Logging and Analysis

Snort alerts are output to the console by default using the `alert_fast` format. To store logs:

- 📂 Use the `-l` option to specify a logging directory:
  ```bash
  sudo snort -c /usr/local/etc/snort/snort.lua -i eth0 -A alert_fast -l /var/log/snort
  ```

- 📊 Convert logs to readable formats using tools such as:
  - `u2json` (Unified2 to JSON)
  - `barnyard2`
  - Custom log parsers

---

## 📈 Visualization Options

For enhanced analysis and monitoring, consider integrating your Snort logs with visualization platforms:

- 📦 **ELK Stack** (Elasticsearch, Logstash, Kibana)
- 📉 **Grafana** with Loki or Prometheus
- 🖥️ **Python-based Dashboards** (Tkinter, PyQt, Flask)

These tools can transform raw log files into intuitive dashboards for threat monitoring and incident response.

---

## ⚠️ Disclaimer

These rules are provided as-is and are intended strictly for **educational and lab use**. They may require tuning or adjustment to fit production environments or advanced use cases. False positives may occur without adequate context and environment-specific calibration.

---

## 🤝 Contributions

Contributions and improvements are welcome. If you'd like to share additional Snort rules or enhancements, feel free to submit updates or suggestions. 🚀

