import glob
import json
import os
import time
from datetime import datetime

import pyudev

LOG_FILE = "logs/usb_events.log"

CLASS_NAMES = {"03": "HID (keyboard/mouse)", "08": "Mass Storage", "09": "Hub",
               "e0": "Wireless", "ff": "Vendor Specific"}
GENERIC_SERIALS = {"0", "00000000", "000000000000", "0123456789", "123456789",
                   "1234567890", "123456789abcdef"}


def read_attr(device, name):
    """Read one detail of a USB device, e.g. idVendor. Returns '(none)' if missing."""
    try:
        return device.attributes.asstring(name)
    except KeyError:
        return "(none)"


def load_policy():
    """Read the allowlist, blocklist and attack hardware list from policy.json."""
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


def get_interface_classes(device):
    """Find which kinds of interfaces (keyboard, storage...) a device has."""
    paths = []
    for _ in range(10):              # interfaces appear a moment after the device
        paths = glob.glob(device.sys_path + "/*:*/bInterfaceClass")
        if paths:
            break
        time.sleep(0.1)
    classes = []
    for path in paths:
        with open(path) as f:
            c = f.read().strip()
        if c not in classes:
            classes.append(c)
    return sorted(classes)


def describe_classes(classes):
    """Turn ['03', '08'] into 'HID (keyboard/mouse), Mass Storage'."""
    names = [CLASS_NAMES.get(c, "Class " + c) for c in classes]
    return ", ".join(names) or "unknown"


def looks_fake(serial):
    """True for serials like '000000000000', 'AAAAAAAA' or '123456789'."""
    if serial == "(none)":
        return False
    s = serial.lower()
    return len(s) < 4 or len(set(s)) == 1 or s in GENERIC_SERIALS


def ids_match(rule, info):
    """True if a rule has the same Vendor ID and Product ID as the device."""
    return rule["vendor_id"] == info["vendor_id"] and rule["product_id"] == info["product_id"]


def serial_matches(rule, info):
    """True if the rule has no serial, or the serial is the same as the device's."""
    if "serial" not in rule:
        return True
    return rule["serial"] == info["serial"]


def check_suspicious(policy, info):
    """Run the BadUSB and spoofing checks. Returns a list of (severity, message)."""
    flags = []
    classes = info["interfaces"]
    if "03" in classes and "08" in classes:
        flags.append(("CRITICAL", "BadUSB pattern: device is BOTH a keyboard/HID and a storage device"))
    for hw in policy.get("known_attack_hardware", []):
        if ids_match(hw, info):
            flags.append(("CRITICAL", "Known attack hardware: " + hw["description"]))
    if looks_fake(info["serial"]):
        flags.append(("WARNING", "Serial '" + info["serial"] + "' looks fake or generic"))
    if "08" in classes and info["serial"] == "(none)":
        flags.append(("WARNING", "Storage device without a serial number cannot be uniquely identified"))
    return flags


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


def decide(policy, info, flags):
    """Return the decision and the reason for one device."""
    for rule in policy["blocklist"]:
        if ids_match(rule, info):
            return "BLOCKED", "in blocklist: " + rule["description"]

    critical = [message for severity, message in flags if severity == "CRITICAL"]
    if critical:
        return "BLOCKED", "SUSPICIOUS DEVICE: " + critical[0]

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


def main():
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
                    "interfaces": get_interface_classes(device),
                }
                print("USB CONNECTED:", info["port"])
                print("   Vendor ID    :", info["vendor_id"])
                print("   Product ID   :", info["product_id"])
                print("   Manufacturer :", info["manufacturer"])
                print("   Product      :", info["product"])
                print("   Serial       :", info["serial"])
                print("   Interfaces   :", describe_classes(info["interfaces"]))
                log_event("DEVICE_CONNECTED", **info)

                flags = check_suspicious(policy, info)
                for severity, message in flags:
                    print("   !!", severity, ":", message)
                    log_event("SUSPICIOUS_DEVICE", severity=severity, message=message, **info)

                decision, reason = decide(policy, info, flags)
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


if __name__ == "__main__":
    main()
