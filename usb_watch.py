import json
import pyudev


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


def matches(rule, vendor, product):
    """True if a rule has the same Vendor ID and Product ID as the device."""
    return rule["vendor_id"] == vendor and rule["product_id"] == product


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


def decide(policy, vendor, product):
    """Return the decision and the reason for one device."""
    for rule in policy["blocklist"]:
        if matches(rule, vendor, product):
            return "BLOCKED", "in blocklist: " + rule["description"]
    for rule in policy["allowlist"]:
        if matches(rule, vendor, product):
            return "ALLOWED", "in allowlist: " + rule["description"]
    return "BLOCKED", "not in allowlist (unknown device)"


policy = load_policy()
context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem="usb", device_type="usb_device")

print("Watching for USB devices... (press Ctrl+C to stop)")

try:
    for device in iter(monitor.poll, None):
        if device.action == "add":
            vendor = read_attr(device, "idVendor")
            product = read_attr(device, "idProduct")
            print("USB CONNECTED:", device.sys_name)
            print("   Vendor ID    :", vendor)
            print("   Product ID   :", product)
            print("   Manufacturer :", read_attr(device, "manufacturer"))
            print("   Product      :", read_attr(device, "product"))
            print("   Serial       :", read_attr(device, "serial"))

            decision, reason = decide(policy, vendor, product)
            print("   DECISION     :", decision, "-", reason)

            if decision == "BLOCKED":
                result = block_device(device)
                print("   ACTION       :", result)
        elif device.action == "remove":
            print("USB REMOVED:", device.sys_name)
except KeyboardInterrupt:
    print("\nStopped.")
