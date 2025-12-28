# PhishGuard-Config
Overview

This repository contains the sanitized configuration exports and infrastructure setup used in the PhishGuard project.

PhishGuard is an automated phishing detection and response system that integrates:

Machine Learning (Flask application)

Threat Intelligence (VirusTotal, MISP)

SIEM (Wazuh)

SOAR (Shuffle)

AWS EC2 infrastructure

Important:
This repository does not contain secrets, API keys, passwords, or credentials. All sensitive information has been removed.

Repository Structure
PhishGuard-Config/
│
├── phishguard_vm/
│   ├── Flask application
│   ├── Machine learning model and training scripts
│   ├── Dashboard templates
│   └── Application-level configuration
│
├── wazuh_manager_vm/
│   └── wazuh_export/
│       ├── ossec.conf
│       ├── local_rules.xml
│       └── Wazuh service and status notes
│
├── shuffle_vm/
│   └── shuffle_export/
│       ├── Docker and service status
│       └── Shuffle SOAR configuration notes
│
├── misp_vm/
│   └── misp_export/
│       ├── MISP configuration files
│       └── Service and integration notes
│
├── .gitignore
└── README.md

Purpose of This Repository

This repository is used to:

Version control security tool configurations

Document a real-world SOC-style architecture

Demonstrate end-to-end integration between ML, SIEM, SOAR, and Threat Intelligence

Support academic submission and professional portfolio review

How to Use
Clone the repository
git clone https://github.com/mariamwatheqi-ops/PhishGuard-Config.git
cd PhishGuard-Config

Review configurations

Each VM folder represents one system component

Files are provided as reference templates

Paths, IP addresses, and credentials must be adapted for any new deployment

Security Notice

No secrets or credentials are stored in this repository

Environment files are excluded

Any values present are placeholders only

This repository is safe for public access.

Project Context

Project Name: PhishGuard

Domain: Cybersecurity / SOC Automation

Technologies: AWS, Flask, Wazuh, Shuffle, MISP, VirusTotal

Purpose: Final-year cybersecurity capstone and professional portfolio

Author

Mariam Watheqi
Cybersecurity Graduate
PhishGuard Project
