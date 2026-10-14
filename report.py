import html
import json
import os
from collections import Counter
from datetime import datetime

LOG_FILE = "logs/usb_events.log"
REPORT_FILE = "reports/usb_audit_report.html"

ALERT_EVENTS = {"DEVICE_BLOCKED", "SUSPICIOUS_DEVICE", "LARGE_TRANSFER"}
FILE_EVENTS = {"FILE_CREATED", "FILE_WRITTEN", "FILE_DELETED", "FILE_MOVED"}


def load_events():
    """Read every line of the log file back into a list of dictionaries."""
    events = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass                       # skip a damaged line instead of crashing
    return events


def esc(value):
    """Make text safe to put inside HTML."""
    return html.escape(str(value))


def table(headers, rows):
    """Build an HTML table from a list of headers and a list of rows."""
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    if not rows:
        body = f'<tr><td colspan="{len(headers)}">None</td></tr>'
    else:
        body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>"
                       for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def describe(e):
    """One readable line of details for any event."""
    if "message" in e:
        return e["message"]
    if "reason" in e:
        return (f"{e.get('manufacturer', '')} {e.get('product', '')} "
                f"({e.get('vendor_id')}:{e.get('product_id')}) - {e['reason']}")
    if "file" in e:
        return e["file"]
    if "vendor_id" in e:
        return f"{e.get('manufacturer', '')} {e.get('product', '')} ({e['vendor_id']}:{e['product_id']})"
    return e.get("port", e.get("path", ""))


# ---------- 1. Read and analyse the log ----------
events = load_events()
if not events:
    raise SystemExit("The log file is empty - run usb_watch.py first.")

counts = Counter(e["event"] for e in events)

devices = {}
for e in events:
    if e["event"] in ("DEVICE_CONNECTED", "DEVICE_ALLOWED", "DEVICE_BLOCKED"):
        key = (e.get("vendor_id"), e.get("product_id"), e.get("serial"))
        d = devices.setdefault(key, {
            "name": f"{e.get('manufacturer', '')} {e.get('product', '')}",
            "first_seen": e["time"], "connections": 0, "decision": "-", "reason": ""})
        if e["event"] == "DEVICE_CONNECTED":
            d["connections"] += 1
        else:
            d["decision"] = "ALLOWED" if e["event"] == "DEVICE_ALLOWED" else "BLOCKED"
            d["reason"] = e.get("reason", "")

alerts = [e for e in events if e["event"] in ALERT_EVENTS]
file_events = [e for e in events if e["event"] in FILE_EVENTS]
files_written = counts["FILE_WRITTEN"]
bytes_written = sum(e.get("size", 0) for e in events if e["event"] == "FILE_WRITTEN")
critical = sum(1 for e in events if e.get("severity") == "CRITICAL")

if counts["LARGE_TRANSFER"] or critical:
    risk, colour = "HIGH", "#c62828"
elif counts["DEVICE_BLOCKED"]:
    risk, colour = "MEDIUM", "#ef6c00"
else:
    risk, colour = "LOW", "#2e7d32"

# ---------- 2. Build the HTML report ----------
summary_rows = [
    ("Overall risk", risk),
    ("Monitoring period", f"{events[0]['time']}  to  {events[-1]['time']}"),
    ("Total events logged", len(events)),
    ("Unique USB devices seen", len(devices)),
    ("Devices allowed (connections)", counts["DEVICE_ALLOWED"]),
    ("Devices blocked (connections)", counts["DEVICE_BLOCKED"]),
    ("Suspicious device warnings", counts["SUSPICIOUS_DEVICE"]),
    ("Files written to USB", f"{files_written} ({bytes_written} bytes)"),
    ("Large-transfer alerts", counts["LARGE_TRANSFER"]),
]

device_rows = [(d["name"], f"{k[0]}:{k[1]}", k[2], d["connections"], d["decision"],
                d["reason"], d["first_seen"]) for k, d in devices.items()]
alert_rows = [(e["time"], e["event"], e.get("severity", ""), describe(e)) for e in alerts]
file_rows = [(e["time"], e["event"], e.get("file", ""), e.get("size", ""),
              e.get("user", ""), e.get("sha256", "")[:16]) for e in file_events]
timeline_rows = [(e["time"], e["event"], describe(e)) for e in events]

page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>USB Security Audit Report</title>
<style>
 body {{ font-family: Arial, sans-serif; margin: 30px; color: #222; }}
 h1 {{ margin-bottom: 4px; }}
 h2 {{ border-bottom: 2px solid #ddd; padding-bottom: 4px; margin-top: 32px; }}
 table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
 th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }}
 th {{ background: #f0f0f0; }}
 .risk {{ color: white; background: {colour}; padding: 4px 12px; border-radius: 4px; }}
</style></head><body>
<h1>USB Security Audit Report</h1>
<p>Generated {datetime.now():%Y-%m-%d %H:%M:%S} &middot; Overall risk:
   <span class="risk">{risk}</span></p>

<h2>1. Summary</h2>{table(["Metric", "Value"], summary_rows)}
<h2>2. USB devices seen</h2>
{table(["Device", "VID:PID", "Serial", "Connections", "Last decision", "Reason", "First seen"], device_rows)}
<h2>3. Security alerts and violations</h2>
{table(["Time", "Event", "Severity", "Details"], alert_rows)}
<h2>4. File activity on USB drives</h2>
{table(["Time", "Event", "File", "Size (bytes)", "User", "SHA-256 (first 16)"], file_rows)}
<h2>5. Full event timeline</h2>
{table(["Time", "Event", "Details"], timeline_rows)}
</body></html>"""

os.makedirs("reports", exist_ok=True)
with open(REPORT_FILE, "w") as f:
    f.write(page)

# ---------- 3. Short summary in the terminal ----------
print("USB SECURITY AUDIT REPORT")
for label, value in summary_rows:
    print(f"  {label:32}: {value}")
print("\nReport saved to", REPORT_FILE)
