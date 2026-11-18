# SecureLens — AI-Powered Secure Code Review Assistant for Student Projects

SecureLens is a full-stack cybersecurity platform built for B.Tech Computer Science and Engineering students to scan source-code projects, inspect static analysis findings, learn secure coding concepts through Gemini AI, propose and review code remediations, validate fixes via static rescanning, and export PDF/CSV assessment reports.

## Key Features
- **Student-Only Authentication & Workspace Isolation**: Bcrypt password hashing (`bcryptjs`), HTTP-only session cookies, CSRF double-submit token protection, login rate limiting, and strict per-student ownership enforcement.
- **Secure Project & Archive Uploads**: Validates file extensions and sizes, prevents ZIP Slip path traversal, rejects archive bombs, and isolates source files per student without executing uploaded code.
- **Multi-Engine Static Security Scanning**:
  - **Custom Deterministic & AST Analyzer** (TypeScript AST + Python `ast.parse` + pattern rules)
  - **ESLint + `eslint-plugin-security`** (controlled flat-config execution isolated from project scripts)
  - **Bandit** (Python AST SAST CLI integration)
  - **Semgrep** (Multi-language SAST CLI integration)
  - **Gitleaks** (Secret scanning with strict redaction before persistence)
  - **OSV-Scanner** (Dependency manifest & lockfile vulnerability auditing)
- **Gemini AI Integration (`@google/genai`)**: Server-side vulnerability explanations, false-positive assessments, prompt-injection-resistant context-aware Security Assistant, and diff-based AI code fix proposals.
- **Explicit Approval & Static Fix Validation**: Backup snapshots created before applying fixes, followed by automatic static rescan verification (`validated`, `partially_validated`, `not_resolved`, `new_issues_detected`, `validation_unavailable`).
- **Interactive Learning Center & PDF/CSV Reports**: 10 core security topics with quizzes and downloadable assessment reports.

## Windows PowerShell Setup & External Scanner Installation

1. **Node.js & npm** (v20+ / v22 LTS):
   ```powershell
   winget install OpenJS.NodeJS.LTS
   npm install
   ```

2. **Python (3.10+)** (needed for Python AST analysis & Bandit/Semgrep):
   ```powershell
   winget install Python.Python.3.11
   ```

3. **Bandit** (Python SAST):
   ```powershell
   py -m pip install bandit
   bandit --version
   ```

4. **Semgrep** (Multi-language SAST — WSL2 or Docker recommended on Windows):
   ```powershell
   py -m pip install semgrep
   semgrep --version
   ```

5. **Gitleaks** (Secret Detection):
   ```powershell
   winget install Gitleaks.Gitleaks
   gitleaks version
   ```

6. **OSV-Scanner** (Dependency Vulnerability Scanner):
   ```powershell
   winget install Google.OSVScanner
   osv-scanner --version
   ```

7. **ESLint Security Dependencies**:
   Already bundled inside `package.json` (`eslint`, `eslint-plugin-security`, `@typescript-eslint/parser`) and executed in an isolated sandbox.

## Environment Variables
Copy `.env.example` to `.env` and configure:
- `GEMINI_API_KEY`: Server-side Google Gemini API key.
- `GEMINI_MODEL`: Default `gemini-4-hydrogen`.
- `DATABASE_PATH`: SQLite database file path (default `./data/securelens.db`).
- `PYTHON_PATH`, `BANDIT_PATH`, `SEMGREP_PATH`, `GITLEAKS_PATH`, `OSV_SCANNER_PATH`: Optional explicit executable paths for Windows/Linux environments.
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`: Optional GitHub OAuth App credentials for private repository access.
- `GITHUB_TOKEN_ENCRYPTION_KEY`: Server-side passphrase used for AES-256-GCM encryption of stored GitHub OAuth access tokens.

## Running Development, Tests & Production Build

```bash
# Development server (Express + Vite middleware on port 3000)
npm run dev

# TypeScript static typecheck
npm run lint

# Automated test suite (Vitest)
npm test

# Production build & run
npm run build
npm start
```
