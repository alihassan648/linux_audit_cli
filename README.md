
# Linux Security Audit CLI

## 🚀 Project Overview

Linux Security Audit CLI is a lightweight DevOps-style automation tool designed to scan Linux filesystem permissions and detect potential security risks.

The tool helps system administrators, DevOps engineers, and security freelancers perform automated filesystem security auditing.

---

## 🎯 Problem Statement

Linux servers may contain insecure file permissions that can lead to privilege escalation, unauthorized access, or system compromise.

Manual auditing of filesystem security is time-consuming and error-prone, especially when managing production servers.

This tool automates permission auditing by recursively scanning directories and identifying high-risk configurations.

---

## 💡 Real-World Use Case

This tool is useful for:

- VPS server security maintenance  
- Web application deployment auditing  
- Detection of misconfigured executable scripts  
- Post-deployment security verification  
- Security compliance checking  

Example scenario:

A production backend server hosting web applications may accidentally contain world-writable files inside `/var/www`. This tool helps detect such risks automatically.

---

## 🛡 Security Features

The CLI scans directories and detects:

- World writable files  
- SUID and SGID binaries  
- Executable files owned by non-root users  
- Root group writable files  
- Non-root ownership inside system directories  

It also generates:

- Risk scoring metrics  
- Structured audit reports  
- JSON export capability  

---

## 📦 Installation

### Clone Repository

```bash
git clone https://github.com/alihassan648/linux_audit_cli.git
cd linux_audit_cli

Create Virtual Environment

python3 -m venv venv
source venv/bin/activate

Install Package

pip install -e .


⸻

🔧 Usage

Basic Scan

linuxaudit scan --path /home


⸻

Minimum Risk Filter

linuxaudit scan --path /home --min-risk HIGH


⸻

Output Format Options

Text Report

linuxaudit scan --path /var/www --format text

JSON Report

linuxaudit scan --path /var/www --format json --output report.json


⸻

📊 Example Output

Scan Summary
------------
Total Files Scanned: 1523

Risks Found:
World Writable Files: 3
SUID Files: 12
Executable Non-Root Files: 8

Overall Risk Assessment
Risk Score: 7
Risk Level: MEDIUM


⸻

🧠 Technical Highlights
	•	Recursive filesystem scanning
	•	Bitwise permission detection
	•	Risk scoring engine
	•	CLI reporting engine
	•	Test-driven architecture
	•	Production-style modular design

⸻

⚠️ Disclaimer

This tool is intended for security auditing and system maintenance.

Always verify remediation actions before applying security fixes.

⸻

👨‍💻 Author

Sohail Ali

GitHub: https://github.com/alihassan648

⸻

⭐ Future Improvements
	•	Real-time filesystem monitoring
	•	Cloud server integration
	•	Privilege escalation heuristic detection
	•	Web dashboard reporting

⸻

📜 License

MIT License

---




