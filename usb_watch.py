import json
import os
from datetime import datetime

import pyudev

LOG_FILE = "logs/usb_events.log"


def read_attr(device, name):
    """Read one detail of a USB device, e.g. idVendor. Returns '(none)' if missing."""
    try:
        return device.attributes.asstring(name)
    except KeyError:
        return "(none)"


def load_policy():
    """Read the allowlist and blocklist from policy.json."""
    with open("policy.json") as f:
        return json.load(f)


def log_event(event, **details):
    """Save one event, with the current time, as a line in the log file."""
    record = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "event": event}
    record.update(details)
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
    os.chmod(LOG_FILE, 0o666)


def ids_match(rule, info):
    """True if a rule has the same Vendor ID and Product ID as the device."""
    return rule["vendor_id"] == info["vendor_id"] and rule["product_id"] == info["product_id"]


def serial_matches(rule, info):
    """True if the rule has no serial, or the serial is the same as the device's."""
    if "serial" not in rule:
        return True
    return rule["serial"] == info["serial"]


def block_device(device):
    """Block a USB device by writing 0 to its 'authorized' file."""
    path = device.sys_path + "/authorized"
    try:
        with open(path, "w") as f:
            f.write("0")
        return "device blocked by the kernel"
    except PermissionError:
        return "FAILED - run the script with sudo"
    except OSError as error:
        return "FAILED - " + str(error)


def decide(policy, info):
    """Return the decision and the reason for one device."""
    for rule in policy["blocklist"]:
        if ids_match(rule, info):
            return "BLOCKED", "in blocklist: " + rule["description"]

    spoofed_rule = None
    for rule in policy["allowlist"]:
        if ids_match(rule, info):
            if serial_matches(rule, info):
                return "ALLOWED", "in allowlist: " + rule["description"]
            spoofed_rule = rule

    if spoofed_rule is not None:
        return "BLOCKED", ("SPOOF SUSPECTED: IDs match '" + spoofed_rule["description"]
                           + "' but serial " + info["serial"]
                           + " is not the approved serial " + spoofed_rule["serial"])

    return "BLOCKED", "not in allowlist (unknown device)"


policy = load_policy()
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem="usb", device_type="usb_device")

print("Watching for USB devices... (press Ctrl+C to stop)")
log_event("MONITOR_STARTED")

try:
    for device in iter(monitor.poll, None):
        if device.action == "add":
            info = {
                "port": device.sys_name,
                "vendor_id": read_attr(device, "idVendor"),
                "product_id": read_attr(device, "idProduct"),
                "manufacturer": read_attr(device, "manufacturer"),
                "product": read_attr(device, "product"),
                "serial": read_attr(device, "serial"),
            }
            print("USB CONNECTED:", info["port"])
            print("   Vendor ID    :", info["vendor_id"])
            print("   Product ID   :", info["product_id"])
            print("   Manufacturer :", info["manufacturer"])
            print("   Product      :", info["product"])
            print("   Serial       :", info["serial"])
            log_event("DEVICE_CONNECTED", **info)

            decision, reason = decide(policy, info)
            print("   DECISION     :", decision, "-", reason)

            if decision == "BLOCKED":
                result = block_device(device)
                print("   ACTION       :", result)
                log_event("DEVICE_BLOCKED", reason=reason, action=result, **info)
            else:
                log_event("DEVICE_ALLOWED", reason=reason, **info)

        elif device.action == "remove":
            print("USB REMOVED:", device.sys_name)
            log_event("DEVICE_REMOVED", port=device.sys_name)
except KeyboardInterrupt:
    print("\nStopped.")
    log_event("MONITOR_STOPPED")
