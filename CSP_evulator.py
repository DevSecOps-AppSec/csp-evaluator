from flask import Flask, request, render_template_string
from collections import defaultdict
import os

app = Flask(__name__)

DANGEROUS_VALUES = {
    "'unsafe-inline'": "Allows inline JS or CSS — XSS risk.",
    "'unsafe-eval'": "Allows eval() — high code injection risk.",
    "*": "Wildcard allows all origins — dangerous.",
    "data:": "Inline resources can be malicious.",
    "blob:": "Potential bypass vector.",
    "http:": "Unencrypted — use HTTPS.",
}

CRITICAL_DIRECTIVES = {
    "default-src": "Fallback for all content types.",
    "script-src": "Controls JS source — critical for XSS protection.",
    "object-src": "Should be 'none' to block plugins.",
    "base-uri": "Prevents <base> tag abuse.",
    "form-action": "Controls where forms can submit.",
    "frame-ancestors": "Prevents clickjacking.",
}

MODERN_DIRECTIVES = [
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "trusted-types",
    "require-trusted-types-for",
    "report-uri",
    "report-to"
]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>CSP Evaluator</title>
    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap\" rel=\"stylesheet\">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f8f9fa;
            color: #212529;
            margin: 0;
            padding: 2rem;
        }
        textarea {
            width: 100%;
            height: 150px;
            padding: 1rem;
            font-size: 1rem;
            border: 1px solid #ced4da;
            border-radius: 0.5rem;
            box-sizing: border-box;
        }
        button {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            cursor: pointer;
            font-size: 1rem;
            transition: background-color 0.3s ease;
        }
        button:hover {
            background-color: #0056b3;
        }
        h1 {
            text-align: center;
        }
        .container {
            max-width: 960px;
            margin: auto;
        }
        .card {
            background: white;
            padding: 2rem;
            border-radius: 1rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            margin-bottom: 2rem;
        }
        code {
            background: #f4f4f4;
            padding: 2px 4px;
            border-radius: 3px;
        }
        .error { color: red; font-weight: bold; }
        .warn { color: orange; font-weight: bold; }
        .ok { color: green; font-weight: bold; }
        .suggest { color: #007acc; }
        .info { color: gray; }
        footer {
            text-align: center;
            color: gray;
            margin-top: 2rem;
        }
        ul.refs {
            padding-left: 1.25rem;
        }
        ul.refs li {
            margin-bottom: 0.5rem;
        }
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
        }
    </style>
</head>
<body>
<div class=\"container\">
    <h1>🛡️ CSP Evaluator</h1>
    <div class=\"card\">
        <form method=\"POST\">
            <textarea name=\"csp_input\" placeholder=\"Paste your CSP header here...\">{{ csp_input }}</textarea><br><br>
            <button type=\"submit\">Evaluate</button>
        </form>
    </div>
    <div class=\"card\">
        {{ report|safe }}
    </div>
    <div class=\"card\">
        <h2>📘 Standards and References</h2>
        <ul class=\"refs\">
            <li><a href=\"https://www.w3.org/TR/CSP3/\" target=\"_blank\">W3C CSP Level 3 Specification</a></li>
            <li><a href=\"https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html\" target=\"_blank\">OWASP CSP Cheat Sheet</a></li>
            <li><a href=\"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP\" target=\"_blank\">MDN CSP Documentation</a></li>
            <li><a href=\"https://csp-evaluator.withgoogle.com/\" target=\"_blank\">Google CSP Evaluator Tool</a></li>
        </ul>
    </div>
    <footer>&copy; 2025 DevSecOps AppSec Team</footer>
</div>
</body>
</html>
"""

def parse_csp(header: str):
    directives = defaultdict(list)
    syntax_warnings = []
    for part in header.split(";"):
        if not part.strip():
            continue
        tokens = part.strip().split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        if directive.endswith(":"):
            syntax_warnings.append(f"Directive <code>{escape_html(directive)}</code> uses a colon — should use space instead.")
            directive = directive.rstrip(":")
        values = tokens[1:]
        directives[directive] = values
    return directives, syntax_warnings

def escape_html(text):
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

def evaluate_csp(header: str):
    directives, syntax_warnings = parse_csp(header)
    html = ["<h2>Evaluation Results</h2>"]
    html.append("<pre><code>" + escape_html(header) + "</code></pre>")

    if syntax_warnings:
        html.append("<h3>🚫 CSP Syntax Issues:</h3><ul>")
        for warn in syntax_warnings:
            html.append(f"<li><span class='error'>⚠️ {warn}</span></li>")
        html.append("</ul>")

    html.append("<h3>🔍 Missing Critical Directives:</h3><ul>")
    for directive, reason in CRITICAL_DIRECTIVES.items():
        if directive not in directives:
            html.append(f"<li><span class='error'>❌ {directive}</span>: {escape_html(reason)}</li>")
    html.append("</ul>")

    html.append("<h3>⚠️ Dangerous or Insecure Values:</h3><ul>")
    for directive, values in directives.items():
        for value in values:
            for pattern, explanation in DANGEROUS_VALUES.items():
                if pattern in value:
                    html.append(f"<li><span class='warn'>⚠️ {directive}</span> uses <code>{escape_html(value)}</code> — {escape_html(explanation)}</li>")
    html.append("</ul>")

    html.append("<h3>🔓 Overly Permissive Checks:</h3><ul>")
    for directive, values in directives.items():
        if "*" in values and directive not in ["img-src", "font-src"]:
            html.append(f"<li><span class='warn'>⚠️ {directive}</span> uses wildcard <code>*</code> — too permissive.</li>")
        if "'self'" not in values and directive in ["script-src", "style-src", "connect-src"]:
            html.append(f"<li><span class='warn'>⚠️ {directive}</span> missing <code>'self'</code> — best practice is to include it.</li>")
    html.append("</ul>")

    html.append("<h3>🚀 Modern Security Recommendations:</h3><ul>")
    for modern in MODERN_DIRECTIVES:
        if modern not in directives:
            html.append(f"<li><span class='suggest'>💡 Consider adding</span> <code>{modern}</code>.</li>")
    html.append("</ul>")

    html.append("<h3>🧹 Redundancy Check:</h3><ul>")
    if "default-src" in directives:
        default = set(directives["default-src"])
        for directive, values in directives.items():
            if directive != "default-src" and set(values) == default:
                html.append(f"<li><span class='info'>ℹ️ {directive}</span> duplicates <code>default-src</code>.</li>")
    html.append("</ul>")

    html.append("<h3>📄 Parsed Directives:</h3><ul>")
    for directive, values in directives.items():
        html.append(f"<li><code>{escape_html(directive)}:</code> {' '.join(escape_html(v) for v in values)}</li>")
    html.append("</ul><hr>")
    return "\n".join(html)

@app.route('/', methods=['GET', 'POST'])
def index():
    csp_input = ""
    report = ""
    if request.method == 'POST':
        csp_input = request.form.get('csp_input', '')
        if csp_input:
            report = evaluate_csp(csp_input)
    return render_template_string(HTML_TEMPLATE, csp_input=csp_input, report=report)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))