import pyudev

context = pyudev.Context()
monitor = pyudev.Monitor.from_netlink(context)
monitor.filter_by(subsystem="usb", device_type="usb_device")

print("Watching for USB devices... (press Ctrl+C to stop)")

try:
    for device in iter(monitor.poll, None):
        if device.action == "add":
            print("USB CONNECTED:", device.sys_name)
        elif device.action == "remove":
            print("USB REMOVED:", device.sys_name)
except KeyboardInterrupt:
    print("\nStopped.")

