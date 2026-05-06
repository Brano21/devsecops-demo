# DevSecOps demo — vulnerable Flask app

> ⚠️ **WARNING**: This repository contains intentional security
> vulnerabilities. It is meant for classroom education only.
> Do not deploy it on a public server.

A tiny Flask app with four deliberate vulnerabilities, used to demo
**SAST**, **SCA** and **DAST** — all running directly in GitHub.
No local setup needed.

---

## Quick refresher (SAST / SCA / DAST)

- **SAST** — Static Application Security Testing. Reads your source
  code (without running it) and looks for dangerous patterns like SQL
  injection, XSS, hardcoded secrets. **Tool here: GitHub CodeQL.**
- **SCA** — Software Composition Analysis. Looks at your *dependencies*
  (Flask, Jinja2, ...) and checks them against a CVE database.
  **Tools here: GitHub Dependency graph + Dependabot.**
- **DAST** — Dynamic Application Security Testing. Runs the app and
  attacks it from the outside, like a real attacker would.
  **Tool here: OWASP ZAP.**

Each catches different things — defence in depth uses all three.

---

## Setup (one-time, ~3 minutes)

1. Push these files to a GitHub repo on the `main` branch.
2. **Settings → Actions → General → Workflow permissions** →
   select **Read and write permissions** and save.
   (Needed so ZAP can open Issues with findings.)
3. Enable the security features below.

### Enable SCA — Dependency graph + Dependabot

**Settings → Code security and analysis**

- **Dependency graph** → **Enable**.
  GitHub parses your `requirements.txt` and builds a graph of every
  direct + transitive dependency. This is the data source for everything
  SCA-related.
- **Dependabot alerts** → **Enable**.
  Cross-checks that graph against the GitHub Advisory Database and
  raises an alert when one of your deps has a known CVE.
- **Dependabot security updates** → **Enable** (optional).
  Automatically opens PRs that bump vulnerable deps to a fixed version.

> **How they relate**: Dependency graph is the *what you have*,
> Dependabot is the *what's wrong with what you have*. Without the
> graph enabled, Dependabot has nothing to check, so always enable
> them together.

For this repo you should see alerts for the pinned old versions of
`Flask 1.0.2`, `Jinja2 2.10` and `Werkzeug 0.14.1` within a minute.

### Enable SAST — CodeQL (default setup)

**Settings → Code security and analysis → Code scanning →
Set up → Default**

GitHub will auto-detect Python and run CodeQL on every push and pull
request. No workflow file to maintain — they pick the queries for you.

> **What CodeQL does**: it compiles your code into a relational
> database and runs taint-tracking queries against it — e.g. "does
> any value from `request.form` reach a SQL `execute()` call without
> being sanitised?". Findings appear in the **Security tab → Code
> scanning** with the exact source line, the data flow, and a
> remediation hint.

For this repo CodeQL should flag the SQL injection in `/login`,
the XSS in `/search`, and the command injection in `/ping`.

### DAST — OWASP ZAP (already wired up)

The workflow in `.github/workflows/zap.yml` runs automatically on push
to `main` and can be triggered manually from the **Actions** tab.
It boots the Flask app inside the runner and runs a passive baseline
scan (~2-3 min). Findings show up as auto-created **Issues** and as a
report artifact on the workflow run page.

---

## Vulnerabilities in the app

### 1. SQL injection — `/login`
User input concatenated into SQL. Try `admin' --` / `anything`.
**Caught by**: CodeQL (SAST). ZAP baseline is passive and won't probe
this — show it manually during the demo.

### 2. Reflected XSS — `/search`
Query parameter rendered with `|safe` in `templates/search.html`.
Try `/search?q=<script>alert(1)</script>`.
**Caught by**: CodeQL (SAST) + ZAP baseline (DAST).

### 3. Command injection — `/ping`
`subprocess.run(..., shell=True)` with user input. Try `127.0.0.1; whoami`.
**Caught by**: CodeQL (SAST). Not by passive ZAP — show manually.

### 4. Hardcoded secret + vulnerable dependencies
- `app.secret_key` hardcoded in `app.py` → caught by CodeQL.
- `Jinja2 == 2.10`, `Werkzeug == 0.14.1`, `Flask == 1.0.2` have known
  CVEs → caught by Dependabot once the dependency graph is enabled.

---

## File overview

| File                           | Purpose                                  |
| ------------------------------ | ---------------------------------------- |
| `app.py`                       | Flask app with 4 intentional bugs        |
| `templates/`                   | Jinja2 templates (search.html is XSS-vulnerable) |
| `requirements.txt`             | Pinned to old, vulnerable versions       |
| `.github/workflows/zap.yml`    | OWASP ZAP DAST in GitHub Actions         |
| `.gitignore`                   | Standard Python ignores                  |
