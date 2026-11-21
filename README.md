# 🛡️ DSA File Integrity Verifier & Tamper Detection System

A modern, production-grade cryptographic file integrity and digital signature application built as a **Cryptography and Network Security (CNS)** project. It implements the **Digital Signature Algorithm (DSA)** with **2048-bit key lengths** and **SHA-256 cryptographic digests** to provide authenticity, integrity, and non-repudiation for files of any format.

The system is delivered in two complementary forms:
1. **🌐 Web & Progressive Web App (PWA):** A modern, mobile-responsive Flask web application with service workers, drag-and-drop file signing/verification, and live audit telemetry, ready for one-click cloud deployment.
2. **🖥️ Desktop Application:** A standalone, native GUI tool built with Python Tkinter and compiled into a standalone Windows binary (`.exe`) requiring zero installation.

---

## 📑 Table of Contents
- [System Architecture](#-system-architecture)
- [Core Features](#-core-features)
- [Cryptographic Principles & Mathematical Workflow](#-cryptographic-principles--mathematical-workflow)
- [Frameworks, Libraries & Tools Used](#-frameworks-libraries--tools-used)
- [Project Directory Structure](#-project-directory-structure)
- [REST API Reference](#-rest-api-reference)
- [Installation & Usage Guide](#-installation--usage-guide)
  - [1. Running the Web Application Locally](#1-running-the-web-application-locally)
  - [2. Deploying to Cloud (Render / Heroku)](#2-deploying-to-cloud-render--heroku)
  - [3. Running the Desktop Application](#3-running-the-desktop-application)
  - [4. Compiling the Desktop App with PyInstaller](#4-compiling-the-desktop-app-with-pyinstaller)
- [Git & GitHub Commands Reference](#-git--github-commands-reference)
- [Security Considerations](#-security-considerations)

---

## 🏗️ System Architecture

```
                                  +------------------------------------+
                                  |            Target File             |
                                  +------------------------------------+
                                                     |
                                            [ SHA-256 Hashing ]
                                                     |
                                                     v
                                          +---------------------+
                                          |   256-bit Digest    |
                                          +---------------------+
                                                     |
                       +-----------------------------+-----------------------------+
                       |                                                           |
                       v                                                           v
            [ Signing Operation ]                                       [ Verification Operation ]
    +---------------------------------------+                   +---------------------------------------+
    | Inputs:                               |                   | Inputs:                               |
    | - Target File Digest                  |                   | - Target File Digest                  |
    | - DSA Private Key (x, p, q, g)        |                   | - DSA Signature (r, s)                |
    | - Ephemeral Secret (k)                |                   | - DSA Public Key (y, p, q, g)         |
    |                                       |                   |                                       |
    | Output:                               |                   | Output:                               |
    | - ASN.1 DER Signature (.sig)          |                   | - Verdict: VALID (Intact)             |
    | - JSON Metadata Manifest (.sig.info)  |                   |   or INVALID (Tampered / Key Mismatch)|
    +---------------------------------------+                   +---------------------------------------+
```

---

## ✨ Core Features

- **2048-Bit DSA Key Generation**:
  - Compliant with NIST FIPS 186-4 specifications ($L = 2048$, $N = 256$).
  - Optional PKCS#8 password-based encryption using PBKDF2 with AES for private key protection.
  - Public keys formatted in standard SubjectPublicKeyInfo (X.509) PEM encoding.
- **SHA-256 Cryptographic File Digesting**:
  - High-performance, chunk-based streaming reads (handles small docs or large binaries up to 50 MB in web mode and unlimited in desktop mode).
- **Dual Signature Outputs**:
  - `.sig`: Raw binary ASN.1 DER-encoded DSS signature containing integers $(r, s)$.
  - `.sig.info`: Human-readable JSON metadata manifest with filename, SHA-256 digest, signing timestamp, and public key fingerprint.
- **Instant Tamper Detection**:
  - Bit-level sensitivity: altering even a single character or byte in the file causes the mathematical signature verification to fail immediately.
- **Public Key Fingerprinting**:
  - Generates colon-delimited SHA-256 fingerprints (e.g., `3a8f:c921:44e2:...`) for easy human verification against known public keys.
- **Persistent Audit Logging**:
  - Automatically records verification timestamps, target filenames, computed digests, and verdicts (`VALID` / `INVALID`) to `verification_history.json`.
- **Progressive Web App (PWA)**:
  - Supports offline caching and "Install App" capability on Android, iOS, Windows, and macOS via `manifest.json` and `sw.js` (Service Worker).

---

## 🔒 Cryptographic Principles & Mathematical Workflow

The application leverages the mathematical properties of the discrete logarithm problem over finite fields:

### 1. Key Generation
- A 2048-bit prime $p$ and a 256-bit prime $q$ are chosen such that $q$ divides $(p - 1)$.
- A generator $g$ is computed with multiplicative order $q$ modulo $p$ ($g = h^{(p-1)/q} \pmod p$).
- **Private Key ($x$)**: A randomly chosen integer where $1 < x < q$.
- **Public Key ($y$)**: Computed as $y = g^x \pmod p$.

### 2. Signing Algorithm
Given a file $M$:
1. Compute the cryptographic hash: $H(M) = \text{SHA-256}(M)$.
2. Select a secure per-message random integer $k$ such that $1 < k < q$.
3. Compute $r = (g^k \pmod p) \pmod q$.
4. Compute $s = \left( k^{-1} \cdot (H(M) + x \cdot r) \right) \pmod q$.
5. The signature is the pair $(r, s)$ formatted in ASN.1 DER DSS encoding.

### 3. Verification Algorithm
Given the file $M$, signature $(r, s)$, and public key $y$:
1. Verify that $0 < r < q$ and $0 < s < q$.
2. Compute $w = s^{-1} \pmod q$.
3. Compute $u_1 = (H(M) \cdot w) \pmod q$.
4. Compute $u_2 = (r \cdot w) \pmod q$.
5. Compute $v = \left( (g^{u_1} \cdot y^{u_2}) \pmod p \right) \pmod q$.
6. **Verdict**: If $v = r$, the signature is **VALID** (authenticity and integrity confirmed). If $v \neq r$, it is **INVALID** (tampering or key mismatch).

---

## 🛠️ Frameworks, Libraries & Tools Used

| Layer / Role | Tool / Technology | Version / Spec | Purpose |
| :--- | :--- | :--- | :--- |
| **Language** | **Python** | 3.10+ (tested on 3.13) | Core language for backend, GUI, and crypto logic |
| **Cryptography** | **pyca/cryptography** | `50.0.2` | FIPS-compliant DSA generation, signing, verification, and PKCS#8 serialization |
| **Web Backend** | **Flask** | `3.0.3` | Lightweight RESTful web server routing and multipart file upload handling |
| **Production WSGI**| **Gunicorn** | `21.2.0+` | Multi-worker HTTP server for production deployment on Linux / cloud |
| **Desktop GUI** | **Tkinter / ttk** | Standard Library | Native cross-platform desktop UI with customized aesthetic palette |
| **Binary Packaging**| **PyInstaller** | Latest | Bundles Python interpreter, crypto engines, and UI into a single `.exe` |
| **Web Frontend** | **HTML5 / CSS3 / ES6 JS** | Standards | Responsive interface, CSS variables, glassmorphic design, and drag-and-drop file upload |
| **Typography** | **Google Fonts** | *Plus Jakarta Sans* & *JetBrains Mono* | Modern visual hierarchy and monospaced cryptographic data display |
| **Offline / PWA** | **Service Workers & Manifest** | W3C Standard | Offline asset caching, mobile install prompt, and app icon handling |
| **Cloud Hosting** | **Render / Heroku** | `render.yaml` & `Procfile` | Configuration for automated containerized cloud deployments |
| **VCS** | **Git & GitHub** | Distributed VCS | Source code tracking and remote synchronization |

---

## 📁 Project Directory Structure

```text
CNS/
│
├── web_app.py                 # Flask backend with REST API endpoints for key gen, sign, verify
├── app_v3.py                  # Standalone Tkinter desktop application (Ultra-Smooth UI)
├── requirements.txt           # Python dependency manifest (Flask, cryptography, gunicorn)
├── Procfile                   # Cloud process execution command for Heroku/Render
├── render.yaml                # Infrastructure-as-code deployment manifest for Render
├── DSA_Verifier.spec          # PyInstaller configuration specification for building the .exe
├── verification_history.json  # Audit log file tracking verification attempts and results
│
├── templates/
│   └── index.html             # Responsive single-page web app & dashboard UI
│
├── static/
│   ├── manifest.json          # PWA metadata configuration for standalone installation
│   ├── sw.js                  # Service Worker script for offline caching
│   ├── icon-192.png           # 192x192 app launcher icon
│   └── icon-512.png           # 512x512 high-resolution app icon
│
└── dist/
    ├── DSA_Verifier.exe       # Pre-compiled standalone Windows executable
    └── README.txt             # Quick start instructions for desktop users
```

---

## 🔌 REST API Reference

The Flask backend (`web_app.py`) exposes the following JSON endpoints:

### 1. Generate Key Pair
- **Endpoint**: `POST /api/generate-keys`
- **Body** (JSON):
  ```json
  { "passphrase": "optional-secret-passphrase" }
  ```
- **Response**:
  ```json
  {
    "status": "success",
    "private_pem": "-----BEGIN ENCRYPTED PRIVATE KEY...-----",
    "public_pem": "-----BEGIN PUBLIC KEY...-----",
    "key_size": 2048,
    "q_bits": 256,
    "encrypted": true,
    "fingerprint": "1a2b:3c4d:..."
  }
  ```

### 2. Sign File
- **Endpoint**: `POST /api/sign`
- **Payload** (`multipart/form-data`):
  - `file`: The document/binary to sign.
  - `key`: The DSA private key in `.pem` format.
  - `passphrase`: *(Optional)* Passphrase if the key is encrypted.
- **Response**:
  ```json
  {
    "status": "success",
    "file_name": "contract.pdf",
    "size": 1048576,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "r": "a4f8...",
    "s": "b3e1...",
    "fingerprint": "1a2b:3c4d:...",
    "signature_hex": "302c0214...",
    "manifest": { ... }
  }
  ```

### 3. Verify File
- **Endpoint**: `POST /api/verify`
- **Payload** (`multipart/form-data`):
  - `file`: The target file to verify.
  - `signature`: The `.sig` binary signature file.
  - `key`: The DSA public key in `.pem` format.
  - `info`: *(Optional)* The `.sig.info` JSON metadata manifest.
- **Response**:
  ```json
  {
    "status": "success",
    "valid": true,
    "file_name": "contract.pdf",
    "current_hash": "e3b0c442...",
    "signed_hash": "e3b0c442...",
    "r": "a4f8...",
    "s": "b3e1...",
    "fingerprint": "1a2b:3c4d:..."
  }
  ```

### 4. Metrics & History
- `GET /api/metrics`: Returns total verifications, count of valid vs. tampered verdicts.
- `GET /api/history`: Returns audit entries ordered with the newest first.
- `POST /api/clear-history`: Resets the audit log.

---

## 🚀 Installation & Usage Guide

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.
- Git installed.

---

### 1. Running the Web Application Locally

```bash
# 1. Clone the repository (if not already inside it)
git clone https://github.com/<username>/<repo-name>.git
cd <repo-name>

# 2. Create and activate a Python virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# 3. Install required packages
pip install -r requirements.txt

# 4. Start the development server
python web_app.py
```
Open your browser and navigate to: `http://localhost:5000`

---

### 2. Deploying to Cloud (Render / Heroku)

This repository includes both `render.yaml` and `Procfile`.

#### Deploying on Render:
1. Push your repository to GitHub.
2. Sign in to [Render](https://render.com/) and click **New +** > **Blueprint**.
3. Select your GitHub repository.
4. Render will read `render.yaml`, automatically install dependencies via `pip install -r requirements.txt`, and launch `gunicorn web_app:app`.

---

### 3. Running the Desktop Application

#### Option A: Running from Python
```bash
python app_v3.py
```

#### Option B: Running the Compiled Binary
Navigate to the `dist/` directory and double-click `DSA_Verifier.exe`.
*(Requires no Python installation or command-line interaction).*

---

### 4. Compiling the Desktop App with PyInstaller

If you make modifications to `app_v3.py` and want to build a new standalone `.exe`:

```bash
# 1. Install PyInstaller
pip install pyinstaller

# 2. Build the binary using the existing spec file
pyinstaller DSA_Verifier.spec
```
The output executable will be placed in the `dist/` directory.

---

## 💻 Git & GitHub Commands Reference

### Clone the Repository
```bash
git clone https://github.com/<username>/<repo-name>.git
cd <repo-name>
```

### Pull Latest Updates from GitHub
```bash
git pull origin main
```

### Add, Commit, and Push Changes
```bash
# Check modified files
git status

# Stage all changes
git add .

# Commit with a descriptive message
git commit -m "Update project documentation and features"

# Push to GitHub
git push origin main
```

---

## 🔐 Security Considerations

1. **Private Key Protection**: Never commit or share your `.pem` private keys. Always use passphrases when generating keys in production environments.
2. **Ephemeral Secret ($k$)**: DSA strictly requires an unpredictable, non-repeating random $k$ per signature. The application uses the underlying OpenSSL/Cryptographic hazmat implementation to prevent lattice attacks and private key recovery.
3. **Audit Immutability**: Verification history is stored locally in `~/DSA_Verifier_Data/verification_history.json` to keep audit records isolated from external web modifications.

---

## 👨‍💻 Author & Academic Attribution
Developed as part of the **Cryptography and Network Security (CNS)** course. Implements standard symmetric and asymmetric cryptographic principles, hashing techniques, and digital signatures.
