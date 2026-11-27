#!/usr/bin/env bash
# Runs inside an Android emulator (see .github/workflows/android-emulator.yml): installs the APK, opens the app, taps Start,
# waits, then prints what the app's own screen says (status line and log), and tries the optional DNS VPN.
# Nothing here fails the job on a missing detail: it prints what it saw. Screenshots and logcat are kept as artifacts.
set -u
OUT=${OUT:-/tmp/shots}; mkdir -p "$OUT"
PKG=org.legalprivacy.noise
shot() { adb exec-out screencap -p > "$OUT/$1.png"; }
say()  { echo; echo "=== $1"; }
UI="python3 android/ci/ui.py"

say "install"
adb install -r "$APK" || { echo "INSTALL FAILED"; exit 1; }
adb shell pm grant $PKG android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb logcat -c

say "open the app"
adb shell am start -n $PKG/.MainActivity >/dev/null
sleep 6; shot 1-opened
$UI texts | head -30

say "tap Start (Wi-Fi only is the default; the emulator's network counts as Wi-Fi)"
$UI tap Start exact || $UI tap Start || true
sleep 75; shot 2-running
echo "--- what the screen says after 75 s:"
$UI texts | head -60

say "turn on the local DNS VPN and accept Android's prompt"
$UI tap "Local DNS VPN" || true
sleep 3; shot 3-vpn-prompt
$UI tap "OK" exact || $UI tap "Accept" || true
sleep 8; shot 4-vpn-on
adb shell ping -c 2 -W 3 example.com 2>&1 | tail -3 || true
sleep 5; shot 5-after-lookup
echo "--- what the screen says with the VPN on:"
$UI texts | head -60

say "logcat: crashes and the app's own lines"
adb logcat -d -v brief | grep -Ei "AndroidRuntime|FATAL|legalprivacy|org\.legalprivacy" | tail -60 || true
adb logcat -d > "$OUT/logcat.txt" 2>&1 || true
echo; echo "done"
