# 🚨 CodeAlpha_Network_Intrusion_Detection_System

## 🔍 Overview
This repository provides a step-by-step guide for setting up a **Network Intrusion Detection System (NIDS)** using **Snort**, developed during **Task 3** of my **Cybersecurity Internship at CodeAlpha**.  
The project includes a set of **custom Snort rules** designed to detect common attack patterns such as reconnaissance, brute-force, and web application exploitation.

---

## 🧰 Requirements

- A virtualized lab network (VMware/VirtualBox) where all virtual machines can communicate with each other.
- One Linux VM (preferably **Ubuntu**) to install and configure **Snort**.
- **Administrative/Root privileges** on the Snort machine.
- Download and import **Metasploitable2** as the vulnerable target machine:  
  🔗 [Metasploitable2 Download](https://sourceforge.net/projects/metasploitable/)
- Recommended attacker machine: **Kali Linux** with tools like **nmap** and **Metasploit Framework** installed.

---

## ⚙️ Snort Installation & Configuration

### 🔧 Ubuntu Setup
Follow this tutorial to install Snort on Ubuntu:  
➡️ https://www.zenarmor.com/docs/linux-tutorials/how-to-install-and-configure-snort-on-ubuntu-linux

### 🐈 Kali Linux (Optional)
For Kali users, you can refer to this guide:  
➡️ https://bin3xish477.medium.com/installing-snort-on-kali-linux-9c96f3ab2910

> **Note:** After installation, **back up your `snort.conf` file** before making modifications:
```bash
sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.bak
```

---

## 📜 Local Rules

Custom Snort rules are located in:
```bash
/etc/snort/rules/local.rules
```

These rules cover:

1. **ICMP Ping Detection** – Detects potential reconnaissance.
2. **SSH Login Attempts** – Flags incoming SSH connection attempts.
3. **FTP Login to Metasploitable2** – Monitors login activity on FTP port.
4. **SYN Flood Detection** – Alerts on possible DoS via SYN flood on HTTP.
5. **Brute-force Login via HTTP POST** – Detects repeated POST login attempts.
6. **SQL Injection Attempts** – Captures suspicious SQL keywords and patterns.
7. **XSS Injection Attempts** – Looks for `<script>` tags in HTTP traffic.

Each rule is documented with a unique **SID**, **message**, **classification**, and **detection technique**.

---

## 🚀 How to Use

### 1. Launch your lab environment:
- Start **Snort (Ubuntu)**, **Metasploitable2**, and **Kali Linux** (or any attack VM).
- Ensure they are all on the same network/subnet.

### 2. Start Snort:
```bash
sudo snort -q -l /var/log/snort -i eth0 -A console -c /etc/snort/snort.conf
```
> Replace `eth0` with your actual network interface:
```bash
ip a
```

### 3. Generate Traffic:
- Use **nmap** to scan Metasploitable2:
```bash
nmap -sS your meta-ip
```
- Use **Metasploit** to launch attacks such as:
  - SSH brute-force
  - FTP login attempts
  - SQL injection
  - XSS payloads

### 4. Monitor Snort Output:
Snort will display alerts on the console and log them under:
```bash
/var/log/snort/
```

---

## 🧪 Testing Scenarios

| Attack Type           | Tool        | Rule Triggered                            |
|-----------------------|-------------|--------------------------------------------|
| ICMP Ping Sweep       | `nmap -sn`  | ICMP Ping Detection                        |
| SSH Brute-force       | Hydra/MSF   | SSH Authentication Attempt                 |
| FTP Login             | MSF/Hydra   | FTP Login Attempt                          |
| SYN Flood             | hping3      | SYN Flood Attempt on HTTP                  |
| HTTP Brute-force POST | Burp/ZAP    | Brute-Force Login Attempt via HTTP POST    |
| SQL Injection         | Manual/MSF  | SQL Injection Attempt                      |
| XSS                   | Manual      | XSS Attempt Detected                       |

---

## 🧐 Troubleshooting Tips

- **Error with config?** Double-check your `snort.conf` file paths for `rules`, `preprocessors`, and `output`.
- **No alerts showing?** Confirm that traffic is actually reaching the Snort interface (`tcpdump` can help).
- **Interface not found?** Use `ip a` or `ifconfig` to find the correct name.

---

## 📚 Resources

- 🎥 [Snort IDS Lab Guide - YouTube](https://www.youtube.com/watch?v=Gh0sweT-G30)
- 🎥 [Metasploitable2 + Snort - YouTube](https://www.youtube.com/watch?v=r1Z7SxewjhM)
- 📘 [Snort Rule Writing Guide (PDF)](https://snort.org/documents)
- 📘 [Snort Official Documentation](https://docs.snort.org/)


