# SecureLens — AI-Powered Secure Code Review Assistant for Student Projects

SecureLens is an AI-assisted cybersecurity platform designed to help students identify, understand, and address security vulnerabilities in their software projects. It combines traditional Static Application Security Testing (SAST) tools, custom security analysis, and Google Gemini AI to provide an accessible and educational code-review experience.

The platform allows students to import projects from GitHub or upload source files, perform automated security scans, investigate detected vulnerabilities, receive AI-generated explanations, review suggested code fixes, and validate approved changes through static rescanning.

SecureLens aims to make secure coding practices easier to understand and apply, particularly for students who may not have prior experience with professional application security tools.

---

## 1. Problem Statement

Students frequently develop software projects without sufficient knowledge of secure coding practices. Common issues such as SQL injection, insecure deserialization, hardcoded credentials, weak cryptography, and insecure dependencies can remain unnoticed during development.

Traditional security tools can identify many of these issues, but their output is often difficult for beginners to interpret. They may provide technical warnings without explaining the underlying problem, its potential impact, or how it can be corrected.

SecureLens addresses this gap by combining automated security scanning with AI-assisted explanations and remediation guidance in a student-focused environment.

## 2. Key Features

### Student Authentication and Workspace Isolation
- Student registration and login.
- Bcrypt-based password hashing using `bcryptjs`.
- HTTP-only session cookies.
- CSRF double-submit token protection.
- Login rate limiting.
- Per-student project and data ownership enforcement.

### Project Management and GitHub Integration
- Create and manage individual project workspaces.
- Import public GitHub repositories.
- Authenticate through GitHub OAuth for private repository access.
- Refresh imported repositories to retrieve updated source code.
- Upload source files and ZIP archives.
- Maintain project files and security scan history.

### Secure File and Archive Processing
- File extension and size validation.
- ZIP Slip and path traversal protection.
- Archive bomb protection.
- Isolated project storage.
- Source-code analysis without executing uploaded project code.
- Controlled subprocess execution for supported external security tools.

### Multi-Engine Security Scanning

SecureLens combines custom analysis with established security tools.

| Scanner | Purpose |
|---|---|
| SecureLens AST & Deterministic Rules | Custom security rules and AST-based analysis |
| Bandit | Python security analysis |
| Semgrep | Multi-language static analysis |
| Gitleaks | Detection of exposed credentials and secrets |
| ESLint + eslint-plugin-security | JavaScript and TypeScript security linting |
| OSV-Scanner | Dependency vulnerability detection |

The platform consolidates scanner findings to reduce duplicate reporting and presents relevant evidence, severity, file paths, and source-code locations.

### Gemini AI Security Assistant
- Explains detected security vulnerabilities in understandable language.
- Provides context-aware security recommendations.
- Assists students in understanding vulnerable coding patterns.
- Provides advisory assessments of potential false positives.
- Uses project context and scanner findings to support relevant responses.

### AI-Assisted Code Remediation
- Generates suggested code changes for detected vulnerabilities.
- Presents proposed changes for student review.
- Requires explicit approval before applying a proposed fix.
- Creates backup snapshots before applying changes.
- Performs static rescanning to assess whether the issue has been resolved.

Remediation outcomes include:
- Validated
- Partially validated
- Not resolved
- New issues detected
- Validation unavailable

AI-generated fixes are treated as proposals and should be reviewed before being accepted.

### Cybersecurity Learning Center

Provides educational material on common security vulnerabilities, including:
- SQL Injection
- Cross-Site Scripting (XSS)
- Broken Authentication
- Hardcoded Credentials and Secrets
- Insecure Deserialization
- Path Traversal
- OS Command Injection
- Weak Cryptography
- Insecure Dependencies
- Security Misconfiguration

Topics include explanations, vulnerable and secure code examples, prevention recommendations, and knowledge checks.

### Security Assessment Reports
- Generate downloadable PDF reports.
- Export findings in CSV format.
- Include vulnerability details and scan information.
- Review security assessment history.

## 3. Technology Stack

| Component | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Node.js, TypeScript, Express |
| Database | SQLite |
| Database Driver | better-sqlite3 |
| AI Integration | Google Gemini API (`@google/genai`) |
| Authentication | bcryptjs, HTTP-only session cookies |
| Static Analysis | Bandit, Semgrep, ESLint |
| Secret Detection | Gitleaks |
| Dependency Analysis | OSV-Scanner |
| Version Control Integration | GitHub OAuth and GitHub API |
| Testing | Vitest |

## 4. System Architecture

SecureLens follows a client-server architecture.

1. **Frontend Layer:** Provides the student interface for authentication, project management, scanning, findings, AI assistance, learning resources, and reports.
2. **Backend Layer:** Handles authentication, project operations, scanner orchestration, AI requests, remediation approval, and report generation.
3. **Security Analysis Layer:** Runs custom deterministic rules and configured external security scanners against imported source files.
4. **AI Analysis Layer:** Uses Google Gemini to explain scanner findings and propose potential remediations.
5. **Data Layer:** Uses SQLite to persist student accounts, projects, files, scan sessions, findings, AI analyses, and remediation history.

### Security Analysis Workflow

```text
Student Login
     |
     v
Create or Import Project
     |
     v
Secure Source Ingestion
     |
     v
Static Security Scanning
     |
     v
Finding Consolidation
     |
     v
Gemini AI Explanation
     |
     v
Review Suggested Remediation
     |
     v
Student Approval
     |
     v
Apply Proposed Changes
     |
     v
Static Rescanning
     |
     v
Validation Results and Reports
```

Uploaded source code is analyzed statically rather than executed as part of the scanning process.

## 5. Installation and Setup

### Prerequisites

Install the following before running SecureLens:

- Node.js 20 or later (Node.js 22 LTS recommended).
- npm.
- Python 3.10 or later for Python analysis and Bandit.
- Git.
- Google Gemini API key.

External scanners are optional individually, but installing the supported tools enables their corresponding scanning capabilities.

### Step 1: Clone the Repository

```bash
git clone https://github.com/parthavhad78-AI/LLM-Powered-Secure-Code-Review-Assistant-for-Student-Projects.git
```

Navigate into the project:

```bash
cd LLM-Powered-Secure-Code-Review-Assistant-for-Student-Projects
```

### Step 2: Install Dependencies

```bash
npm install
```

For a clean installation using the committed lockfile, you can use:

```bash
npm ci
```

### Step 3: Configure Environment Variables

Copy `.env.example` to `.env` in the project root.

Configure the required values in the `.env` file:

```env
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-4-hydrogen

DATABASE_PATH=./data/securelens.db

PYTHON_PATH=
BANDIT_PATH=
SEMGREP_PATH=
GITLEAKS_PATH=
OSV_SCANNER_PATH=

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_TOKEN_ENCRYPTION_KEY=
```

Use actual credentials only in your local `.env` file. Never commit API keys, OAuth secrets, database credentials, or other sensitive information to GitHub.

### Step 4: Start the Development Server

```bash
npm run dev
```

The application runs locally at:

```text
http://localhost:3000
```

**Windows PowerShell note:** If PowerShell blocks `npm.ps1` because of the execution policy, use:

```powershell
npm.cmd run dev
```

You can also use `npm.cmd` for other npm commands.

## 6. External Security Scanner Installation

### Python and Bandit

Install Python and Bandit:

```powershell
winget install Python.Python.3.11
py -m pip install bandit
```

Verify:

```powershell
bandit --version
```

### Semgrep

```powershell
py -m pip install semgrep
```

Verify:

```powershell
semgrep --version
```

On Windows, use the supported execution environment and installation method for your Semgrep version, such as WSL2 or Docker where required.

### Gitleaks

```powershell
winget install Gitleaks.Gitleaks
```

Verify:

```powershell
gitleaks version
```

### OSV-Scanner

```powershell
winget install Google.OSVScanner
```

Verify:

```powershell
osv-scanner --version
```

### ESLint Security Dependencies

The ESLint security dependencies are included in the project's `package.json` and installed through npm.

These include:
- `eslint`
- `eslint-plugin-security`
- `@typescript-eslint/parser`

Refer to the Settings section of SecureLens for scanner availability and installation guidance.

## 7. GitHub Integration

SecureLens supports importing source-code projects directly from GitHub.

The integration supports:
- Public repository imports.
- GitHub OAuth authentication.
- Authorized private repository access.
- Repository validation.
- Source archive import.
- Repository refresh functionality.

GitHub OAuth credentials must be configured on the server through environment variables. Private repository access requires the appropriate OAuth permissions.

Imported repositories are treated as source-code input. Repository scripts are not executed during the import process.

## 8. Testing and Development Commands

Run the following commands from the project root.

### TypeScript Type Checking

```bash
npm run lint
```

### Automated Test Suite

```bash
npm test
```

### Production Build

```bash
npm run build
```

### Start Production Server

```bash
npm start
```

## 9. Security and Privacy Considerations

SecureLens incorporates security controls throughout its application workflow.

- Student workspaces enforce project ownership boundaries.
- Passwords are stored using bcrypt hashing.
- Session cookies use HTTP-only protection.
- CSRF protection is implemented for applicable requests.
- Uploaded source code is not executed during static scanning.
- Archive processing includes path traversal and archive bomb protections.
- Secrets detected during scanning are redacted before persistence.
- GitHub OAuth tokens are encrypted before storage.
- AI-generated remediation changes require explicit student approval.
- Applied changes are backed up and assessed through static rescanning.

Security tools and AI-generated assessments are intended to support secure development. They do not guarantee that a project is free from vulnerabilities.

## 10. Current Scope

The current implementation focuses on student-oriented secure code review and vulnerability education.

Its implemented functionality includes:
- Student authentication and isolated project workspaces.
- GitHub repository integration and source-code uploads.
- Multiple static security scanning engines.
- Consolidated vulnerability findings.
- Gemini-powered explanations and security assistance.
- Reviewable AI-generated remediation proposals.
- Static validation of applied fixes.
- Educational secure coding resources.
- PDF and CSV assessment report functionality.

Scanner coverage depends on the programming language, available tools, and supported file types.

## 11. Future Scope

Potential enhancements include:

- Expanding static analysis coverage to additional programming languages.
- Improving vulnerability detection through deeper semantic and data-flow analysis.
- Adding continuous security monitoring for connected repositories.
- Improving AI remediation accuracy through larger benchmark datasets.
- Introducing more comprehensive vulnerability benchmarking and comparative evaluation.
- Enhancing report customization and historical security analytics.
- Extending the educational content with additional practical exercises.

## 12. Project Information

**Project Name:** SecureLens

**Project Title:** LLM-Powered Secure Code Review Assistant for Student Projects

**Project Category:** Cybersecurity / Artificial Intelligence / Software Engineering

**Target Users:** Computer Science and Engineering students

**Developed By:** Parth Avhad

---

## License

No open-source license has currently been specified for this repository. Unless a license is added, standard copyright restrictions apply.
