# siem_dashboard.py
import pandas as pd
import plotly.express as px
from datetime import datetime
import re

# Simulated log file path
LOG_FILE = "sample_auth"
ALERT_FILE = "alerts.txt"
DASHBOARD_FILE = "dashboard.html"
FAILED_LOGIN_THRESHOLD = 5  # Alert if >5 failed logins from an IP in 1 hour

def parse_log_line(line):
    """Parse a log line for timestamp, IP, and failure status."""
    try:
        # Example: Apr 10 14:32:01 user sshd: Failed password for user from 192.168.1.100
        pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*Failed password.*from\s+(\S+)"
        match = re.match(pattern, line)
        if match:
            timestamp = datetime.strptime(f"{match.group(1)} 2025", "%b %d %H:%M:%S %Y")
            ip = match.group(2)
            return {"timestamp": timestamp, "ip": ip, "status": "failed"}
        return None
    except:
        return None

def analyze_logs():
    """Read and analyze logs, generate dashboard and alerts."""
    # Read log file
    logs = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                logs.append(parsed)

    # Create DataFrame
    df = pd.DataFrame(logs)
    if df.empty:
        print("No failed login attempts found.")
        return

    # Group by IP and hour
    df["hour"] = df["timestamp"].dt.floor("h")
    ip_counts = df.groupby(["ip", "hour"]).size().reset_index(name="count")

    # Generate alerts for IPs exceeding threshold
    alerts = ip_counts[ip_counts["count"] > FAILED_LOGIN_THRESHOLD]
    with open(ALERT_FILE, "w") as f:
        for _, row in alerts.iterrows():
            f.write(f"Alert: IP {row['ip']} had {row['count']} failed logins at {row['hour']}\n")

    # Create Plotly dashboard
    fig = px.bar(ip_counts, x="hour", y="count", color="ip", title="Failed Login Attempts by IP and Hour")
    fig.update_layout(xaxis_title="Time", yaxis_title="Failed Logins", showlegend=True)
    fig.write_html(DASHBOARD_FILE)
    print(f"Dashboard saved to {DASHBOARD_FILE}, alerts to {ALERT_FILE}")

if __name__ == "__main__":
    analyze_logs()