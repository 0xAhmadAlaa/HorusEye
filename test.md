# HorusEye — Full Testing Guide

This document covers how to test **all parts** of HorusEye: parser, detector, IOC extractor, reporter, real-time monitoring, configuration, and unit tests.

---

##  Setup

```bash
git clone https://github.com/0xahmadalaa/HorusEye.git
cd HorusEye

python3 -m venv venv
source venv/bin/activate  # Or .\venv\Scripts\activate on Windows

pip install -r requirements.txt
````

---

##  Basic Single-Run Test

```bash
echo "Jul 13 12:00:00 localhost sshd[123]: Failed password for user from 1.1.1.1 port 22 ssh2" > logs/auth.log
python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report
```

---

##  SSH Brute Force Rule Test

```bash
for i in {1..6}; do
  echo "Jul 13 12:00:0$i localhost sshd[123]: Failed password for invalid user from 2.2.2.2 port 22 ssh2" >> logs/auth.log
  sleep 1
done

python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report
```

---

##  Accepted Password Rule Test

```bash
echo "Jul 13 12:05:00 localhost sshd[123]: Accepted password for user from 3.3.3.3 port 22 ssh2" >> logs/auth.log

python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report
```

---

##  Sudo Command Rule Test

```bash
echo "Jul 13 12:10:00 localhost sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls" >> logs/auth.log

python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report
```

---

##  Real-Time Monitoring Test

```bash
python main.py -l logs/auth.log -r rules/rules.json -o reports/incident_report --realtime
```

Then in another terminal (or after):

```bash
echo "Jul 13 12:15:00 localhost sshd[123]: Failed password for user from 4.4.4.4 port 22 ssh2" >> logs/auth.log
```

---

##  Config File Test

Edit `config.yaml` as needed, then run:

```bash
python main.py --config config.yaml
```

Or for real-time:

```bash
python main.py --config config.yaml --realtime
```

---

## IOC Enrichment Test (Optional)

Make sure your `config.yaml` includes valid AbuseIPDB and/or VirusTotal API keys.

Then run any detection command above. The tool will try to enrich IPs and hashes automatically.

---

##  Unit Tests

```bash
pytest
```

(Optional) Coverage:

```bash
pytest --cov
```

---

##  Check Generated Reports

```bash
cat reports/incident_report.md
cat reports/incident_report.json
```

---
