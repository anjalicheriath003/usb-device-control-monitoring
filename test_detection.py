from usb_watch import check_suspicious, decide, load_policy

policy = load_policy()


def device(vendor, product, serial, interfaces, name):
    """Build fake device details, like the ones usb_watch.py reads from a real device."""
    return {"port": "test", "vendor_id": vendor, "product_id": product,
            "manufacturer": name, "product": name, "serial": serial,
            "interfaces": interfaces}


tests = [
    ("My real pen drive",
     device("048d", "1234", "0718361110626126583", ["08"], "DIGITEK")),
    ("My mouse",
     device("10c4", "0005", "(none)", ["03"], "YSPRINGTECH")),
    ("BadUSB: perfect copy of my pen drive + hidden keyboard",
     device("048d", "1234", "0718361110626126583", ["03", "08"], "DIGITEK")),
    ("Digispark attack board",
     device("16d0", "0753", "(none)", ["03"], "digistump")),
    ("Cheap drive with fake serial",
     device("abcd", "0001", "000000000000", ["08"], "Generic")),
    ("Clone of my pen drive (wrong serial)",
     device("048d", "1234", "1111222233334444", ["08"], "DIGITEK")),
]

for title, info in tests:
    flags = check_suspicious(policy, info)
    decision, reason = decide(policy, info, flags)
    print("TEST:", title)
    for severity, message in flags:
        print("   !!", severity, ":", message)
    print("   DECISION:", decision, "-", reason)
    print()

