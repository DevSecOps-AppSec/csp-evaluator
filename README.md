# 🛡️ CSP Evaluator (Flask App)

A simple Flask-based web application to evaluate Content Security Policy (CSP) headers for common security issues. It highlights missing directives, dangerous values, overly permissive configurations, and provides suggestions for modern security enhancements.

Hosted Example: [https://csp-evaluator.onrender.com](https://csp-evaluator.onrender.com)

---

## 🚀 Features

* Detects missing critical CSP directives
* Flags dangerous values like `unsafe-inline`, `eval()`, `data:`, wildcards, and `http:`
* Warns on overly permissive policies (e.g., `*`, missing `'self'`)
* Suggests modern directives (e.g., `upgrade-insecure-requests`, `trusted-types`)
* Detects redundant directives
* Displays CSP syntax errors (e.g., use of `:` instead of space)
* Generates a clean, readable HTML report via web interface

---

## 🧑‍💻 Local Development

### 🔧 Prerequisites

* Python 3.7+
* Flask

### 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

### ▶️ Run Locally

```bash
python CSP_evulator.py
```

Visit `http://localhost:5000` in your browser.

---

## 🌐 Deployment on Render

### 1. Create `requirements.txt`

```
Flask==2.3.3
```

### 2. Create `render.yaml`

```yaml
services:
  - type: web
    name: csp-evaluator
    env: python
    buildCommand: ""
    startCommand: "python CSP_evulator.py"
```

### 3. Push to GitHub

```bash
git init
git add .
git commit -m "Initial CSP Evaluator"
git remote add origin https://github.com/yourname/csp-evaluator.git
git push -u origin main
```

### 4. Deploy on Render

* Go to [https://render.com](https://render.com)
* Create a new Web Service
* Link your GitHub repo
* Set Python as runtime
* Set start command: `python CSP_evulator.py`

---

## 📘 References

* [W3C CSP Level 3 Specification](https://www.w3.org/TR/CSP3/)
* [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [MDN CSP Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
* [Google CSP Evaluator Tool](https://csp-evaluator.withgoogle.com/)

---

## 📄 License

MIT License. Use freely, contribute if you’d like!
