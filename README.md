# SecureTask - Secure Python Task Management Application

SecureTask is a Python Flask task management application built to demonstrate secure software development practices, DevSecOps methodology, and security testing (SAST, SCA, Secrets Detection, and DAST).

---

## 🛠️ Technology Stack & Tools

* **Backend:** Python, Flask, SQLAlchemy, SQLite, JWT (JSON Web Tokens)
* **Frontend:** HTML, CSS, Bootstrap, Jinja2
* **Static Application Security Testing (SAST):** Bandit, Semgrep[cite: 1]
* **Software Composition Analysis (SCA):** `pip-audit`, Safety, OWASP Dependency-Check[cite: 1]
* **Secrets Detection:** Gitleaks[cite: 1]
* **Dynamic Application Security Testing (DAST):** OWASP ZAP[cite: 1]

---
[![Quality Gate Status](http://localhost:9000/api/project_badges/measure?project=securetask-project&metric=alert_status)](http://localhost:9000/dashboard?id=securetask-project)
## 📅 Project Progress Summary (Weeks 1 – 6)

### Week 1: Environment Setup & Core Authentication
* Set up Flask project structure, SQLite database, and Git version control[cite: 1].
* Implemented user registration, login, password hashing, and JWT-based session authentication[cite: 1].

### Week 2: Functional Features & API Documentation
* Implemented full CRUD operations for tasks, categories, and user profile management[cite: 1].
* Developed a dashboard and search feature[cite: 1].
* Created API documentation endpoint (`/api_docs`)[cite: 1].

### Week 3: Vulnerability Insertion (Intentional Vulnerabilities)
* Introduced standard web security vulnerabilities for DevSecOps testing[cite: 1]:
  * **SQL Injection (SQLi):** Unsanitized raw queries in search endpoints[cite: 1].
  * **Cross-Site Scripting (XSS):** Unencoded output rendering in Jinja2 templates[cite: 1].
  * **Hardcoded Secrets:** API credentials and secret keys checked into source files[cite: 1].
  * **Directory Traversal & Insecure File Upload:** Inadequate file validation on user uploads[cite: 1].
  * **Authentication & Error Handling:** Weak hashing, authorization bypasses, and verbose error handling[cite: 1].

### Week 4: SAST & Secrets Scanning
* Executed **Bandit** and **Semgrep** to identify Python code-level vulnerabilities[cite: 1].
* Ran **Gitleaks** to detect hardcoded keys and tokens[cite: 1].
* Generated automated JSON/TXT reports stored under `/reports/`[cite: 1].

### Week 5: Dependency Security Analysis (SCA)
* Analyzed third-party package vulnerabilities using **`pip-audit`**, **Safety**, and **OWASP Dependency-Check**[cite: 1].
* Exported vulnerabilities across multiple formats (JSON, XML, HTML, CSV, SARIF)[cite: 1].

### Week 6: Dynamic Security Testing (DAST)
* Configured **OWASP ZAP** for spidering and active scanning[cite: 1].
* Tested authentication flows, session handling, CSRF protections, and missing security headers[cite: 1].
* Generated complete DAST reports (`zap-report.html` and `zap-report.json`)[cite: 1].

---

## 📊 Security Scanning Findings Matrix

| Tool | Focus Area | Status | Primary Findings / Severity |
| :--- | :--- | :---: | :--- |
| **Bandit** | Python SAST | Completed | High/Medium (SQLi, Hardcoded Keys) |
| **Semgrep** | Code Quality & SAST | Completed | OWASP Top 10 Rule Matches |
| **Gitleaks** | Secrets Detection | Completed | Hardcoded credentials detected |
| **pip-audit / Safety** | Dependency SCA | Completed | Known CVEs in outdated packages |
| **OWASP ZAP** | Web DAST | Completed | Missing Security Headers, Reflected XSS, CSRF |

---

## 📁 Security Reports Directory (`/reports`)

All automated scan outputs are stored in the project repository for auditing:

```text
reports/
├── bandit-report.json
├── bandit-report.txt
├── dependency-check-report.html
├── gitleaks-report.json
├── pip-audit-report.json
├── safety-report.json
├── SAST_FINDINGS.md
├── semgrep-report.json
├── semgrep-report.txt
└── zap-report.html