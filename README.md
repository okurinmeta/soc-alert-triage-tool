# SOC Alert Triage Tool

A Python tool that automates IP reputation checks during SOC alert triage. It cross-references IP addresses against AbuseIPDB and VirusTotal, then sends a real-time Telegram alert if the IP is flagged as malicious.

## Why this matters
SOC analysts spend significant time manually checking suspicious IPs across multiple threat intelligence sources. This tool automates that first triage step, reducing response time and giving cross-validated results from two independent sources.

## Features
- Checks IP reputation via AbuseIPDB (abuse confidence score, report count)
- Checks IP reputation via VirusTotal (multi-vendor malicious/suspicious flags)
- Sends instant Telegram alerts for flagged IPs
- Uses environment variables to keep API keys secure

## Tech Stack
- Python 3
- Requests library
- AbuseIPDB API
- VirusTotal API
- Telegram Bot API

## Setup
1. Clone this repo
2. Create a virtual environment: `python -m venv venv`
3. Activate it and install dependencies: `pip install -r requirements.txt`
4. Create a `.env` file with your API keys: