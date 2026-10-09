import pyudev


def read_attr(device, name):
    """Read one detail of a USB device, e.g. idVendor. Returns '(none)' if missing."""
    try:
        return device.attributes.asstring(name)
    except KeyError:
        return "(none)"


context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem="usb", device_type="usb_device")

print("Watching for USB devices... (press Ctrl+C to stop)")

try:
    for device in iter(monitor.poll, None):
        if device.action == "add":
            print("USB CONNECTED:", device.sys_name)
            print("   Vendor ID    :", read_attr(device, "idVendor"))
            print("   Product ID   :", read_attr(device, "idProduct"))
            print("   Manufacturer :", read_attr(device, "manufacturer"))
            print("   Product      :", read_attr(device, "product"))
            print("   Serial       :", read_attr(device, "serial"))
        elif device.action == "remove":
            print("USB REMOVED:", device.sys_name)
except KeyboardInterrupt:
    print("\nStopped.")
