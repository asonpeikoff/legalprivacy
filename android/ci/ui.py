"""Tiny helpers for the emulator smoke test: read the screen's text and tap a button by its label (uiautomator dump)."""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def dump(path="/tmp/ui.xml"):
    subprocess.run(["adb", "shell", "uiautomator", "dump", "/sdcard/ui.xml"], check=False, capture_output=True)
    subprocess.run(["adb", "pull", "/sdcard/ui.xml", path], check=False, capture_output=True)
    return ET.parse(path).getroot()


def nodes(root):
    for n in root.iter("node"):
        yield n.attrib


def center(bounds):
    a, b, c, d = map(int, re.findall(r"\d+", bounds))
    return (a + c) // 2, (b + d) // 2


def tap(label, exact=False):
    for n in nodes(dump()):
        t = (n.get("text") or "") + " " + (n.get("content-desc") or "")
        if (t.strip() == label) if exact else (label.lower() in t.lower()):
            x, y = center(n["bounds"])
            subprocess.run(["adb", "shell", "input", "tap", str(x), str(y)], check=False)
            print(f"tapped '{label}' at {x},{y}")
            return True
    print(f"no '{label}' on screen")
    return False


def texts():
    return [n["text"] for n in nodes(dump()) if n.get("text")]


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "tap":
        sys.exit(0 if tap(sys.argv[2], exact=len(sys.argv) > 3) else 1)
    if cmd == "texts":
        print("\n".join(texts()))
