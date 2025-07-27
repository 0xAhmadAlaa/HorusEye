
## HorusEye - Alert Module ##

## alerts via console, email, or Slack. ##


import smtplib
import requests
from email.mime.text import MIMEText

# codes for colors
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

def send_console_alert(message: str, priority: str = "info"):
    color = Colors.WHITE
    if priority.lower() == "high":
        color = Colors.RED
    elif priority.lower() == "medium":
        color = Colors.YELLOW
    elif priority.lower() == "low":
        color = Colors.CYAN
    
    print(f"{color}[!] {message}{Colors.RESET}")


def send_email(
    subject: str,
    body: str,
    to_email: str,
    smtp_server: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str
):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(smtp_user, smtp_pass)
            smtp.send_message(msg)
        print(f"[+] Email sent to {to_email}")
    except Exception as e:
        print(f"[x] Email send failed: {e}")


def send_slack_alert(msg: str, webhook_url: str):
    try:
        response = requests.post(webhook_url, json={"text": msg})
        if response.status_code != 200:
            print(f"[x] Slack webhook error: {response.status_code}")
        else:
            print("[+] Slack alert sent")
    except Exception as e:
        print(f"[x] Slack send failed: {e}")


