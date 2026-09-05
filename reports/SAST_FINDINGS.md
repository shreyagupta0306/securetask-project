# Week 4: SAST & Secret Detection Report

## 1. Bandit Findings (Python SAST)
- **CWE-327 / B303 (Use of Insecure Hash):** Detected `hashlib.md5()` in `app.py` at `/register`. MD5 is cryptographically broken and prone to collision attacks.
- **CWE-89 / B608 (SQL Injection):** Detected dynamic string formatting (`f"SELECT ... {search_query}"`) executed via `db.session.execute()`.

## 2. Semgrep Findings (Semantic Code Analysis)
- **SQL Injection:** Flagged raw concatenation passed to database session queries without parameterization.
- **Path Traversal / Arbitrary File Access:** Detected `open(file_path, 'r')` in `/view-file` accepting unsanitized user query input.
- **Cross-Site Scripting (XSS):** Detected unescaped template output rendering (`| safe` filter) in `templates/dashboard.html`.

## 3. Gitleaks Findings (Secret Detection)
- **Generic API Key / Hardcoded Secret:** Flagged `AWS_SECRET_KEY = "AKIAIOSFODNN7ABCD1234567890SECKEY"` on line 15 of `app.py`.