# Lab Notes – USB Device Control & Monitoring Framework

## Environment
- Host: Windows, VirtualBox
- Guest: Kali GNU/Linux Rolling
- Kernel: 6.16.8+kali-amd64
- Test device: YSPRINGTECH USB Optical Mouse (10c4:0005)

## Stage 1 – How USB talks to Linux

### 1.1 Listing devices – lsusb  (02_lsusb_after.png)
- At first only "VirtualBox USB Tablet" (80ee:0021) and a root hub were visible
- Problem: in a VM, real USB devices are not visible to the guest
- Fix: passed the mouse through via VirtualBox Devices → USB
- Result: ID 10c4:0005 Silicon Labs USB OPTICAL MOUSE (Vendor 10c4, Product 0005)
- Device number changed (003 → 004) after reconnecting, so it cannot identify a device

### 1.2 Live USB events – udevadm monitor  (03_udevadm_monitor.png)
- Command: sudo udevadm monitor --udev --subsystem-match=usb
- Unplug: unbind → remove ; Plug in: add → bind
- 1-2 = the device (port), 1-2:1.0 = its interface (what it does)
- bind = driver attached, unbind = driver detached
- My program will listen to these same kernel events

### 1.3 Device details – sysfs  (04_sysfs_details.png)
- Linux shows each USB device as files in /sys/bus/usb/devices/<port>/
- idVendor = 10c4, idProduct = 0005
- manufacturer = YSPRINGTECH, product = USB OPTICAL MOUSE
- Interface class = 03 (HID: keyboard/mouse). A pen drive shows 08 (mass storage)
- A device showing BOTH 03 and 08 is suspicious: that is the BadUSB pattern
- No serial file: the mouse has no serial number
- Security point: without a serial, two identical devices cannot be told apart
- lsusb showed "Silicon Labs" (looked up from Vendor ID 10c4 in the public USB ID database)
  but the device itself reports "YSPRINGTECH" → the chip maker and the brand differ
- Security point: manufacturer/product strings are self-reported by the device and can be faked.
  The framework must combine VID + PID + serial + strings + interface class to detect spoofing.

### 1.4 Blocking a device  (05a_block_events.png, 05b_block_command.png)
- Command: echo 0 | sudo tee /sys/bus/usb/devices/1-2/authorized; sleep 10; echo 1 | sudo tee /sys/bus/usb/devices/1-2/authorized
- Result: unbind + remove of 1-2:1.0 at 1452.99 s, then add + bind at 1463.05 s (exactly 10 s later)
- The mouse stopped working but stayed in lsusb: blocked, not unplugged
- Only the interface (1-2:1.0) was removed; the device (1-2) stayed connected
- My framework will auto-block unauthorized devices by writing 0 to this file

### Stage 1 – Key learnings
1. The kernel announces every USB connect/disconnect as an event (udev)
2. Every device can be fingerprinted from sysfs: VID, PID, serial, names, interface class
3. Writing 0 to the "authorized" file blocks a device instantly
4. Device names can be faked, and many devices have no serial, so detection needs several checks
