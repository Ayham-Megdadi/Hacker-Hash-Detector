<h1 align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&pause=1000&color=00F7FF&center=true&vCenter=true&width=600&lines=Ayham+Hash+Detector+Tool+v2.0;Ethical+%7C+Educational+%7C+Powerful" alt="Typing SVG" />
</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Version-2.0-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Purpose-Educational-red?style=for-the-badge"/>
</p>

> Developed by **Ayham Belal Megdadi** — For Educational & Ethical Use Only

## Features
| Feature | Description |
|---|---|
| 🔍 Hash Detection | MD5, SHA1, SHA256, SHA512, SHA3, bcrypt, Argon2, scrypt... |
| ⚙️ Hash Generation | Generate any hash from plaintext |
| 🔐 HMAC | Generate HMAC with secret key |
| 📁 File Hashing | Hash any file (MD5 + SHA256 + SHA512) |
| 📦 Batch Mode | Process a list of hashes and export JSON report |
| ⚖️ Compare | Constant-time safe comparison |
| 💪 Strength Rating | Weak / Moderate / Strong rating for each hash |

## About
Ayham Hash Detector Tool is a cybersecurity educational project designed to help students and beginners understand how different hashing algorithms work, how to identify them, and how to safely analyze hash structures.

## Installation
\```bash
git clone https://github.com/Ayham-Megdadi/Hacker-Hash-Detector.git
cd Hacker-Hash-Detector
python3 AY_hash.py

## Why this tool?
Most beginners struggle with identifying hash types and understanding cryptographic strength. This tool simplifies the process and provides real-world awareness of secure and insecure hashing methods.

# CLI examples
python3 Ayham.py detect <hash>
python3 Ayham.py generate "password" -a SHA256
python3 Ayham.py hmac "message" "secret" -a SHA512
python3 Ayham.py hashfile /path/to/file
python3 Ayham.py batch hashes.txt
python3 Ayham.py compare <hash1> <hash2>
\```

## Supported Hash Types
MD5 · SHA1 · SHA224 · SHA256 · SHA384 · SHA512 · SHA3-256 · SHA3-512 · bcrypt · Argon2 · scrypt · PBKDF2 · CRC32 · MySQL323 · Tiger192

## Disclaimer
This tool is intended **strictly for educational and ethical purposes**.
