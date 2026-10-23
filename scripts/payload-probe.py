#!/usr/bin/env python3
"""Pre-build hook for the nash build.

1. Disables the native_legacy_display_probe() call in the XNU patch set: the kit
   belongs to another device and the symbol does not exist for nash yet.
2. Adds the boot-progress reset probe to the payload step so one run answers one
   question: "did the kernel get past the call to SYMBOL in arm_init?".

Environment: NASH_PROBE_SYMBOL (default _processor_bootstrap),
             NASH_PROBE_OCCURRENCE (default 1).
"""
import os
import pathlib
import sys

ROOT = pathlib.Path.cwd()

symbol = os.environ.get("NASH_PROBE_SYMBOL", "_processor_bootstrap")
occurrence = os.environ.get("NASH_PROBE_OCCURRENCE", "1")

# 1. drop the display probe calls
probe_patch = ROOT / "patches/xnu/offline-component-load-probes.patch"
if probe_patch.is_file():
    text = probe_patch.read_text()
    count = text.count("native_legacy_display_probe();")
    if count:
        probe_patch.write_text(text.replace("native_legacy_display_probe();", "/* disabled for nash */"))
    print(f"offline-component-load-probes.patch: {count} display probe call(s) disabled")
else:
    print("warning: offline-component-load-probes.patch not found")

# 2. add the reset probe to the payload step
payload = ROOT / "scripts/unixnu/payload.py"
if not payload.is_file():
    print("error: scripts/unixnu/payload.py not found")
    sys.exit(1)

text = payload.read_text()
old = "'--panic-screen', '--no-reset'"
new = (
    "'--panic-screen', '--no-reset', '--reset-after', "
    f"'{symbol}', '--in', '_arm_init', '--occurrence', '{occurrence}', '--reset-delay', '6'"
)
if old in text:
    payload.write_text(text.replace(old, new))
    print(f"payload.py: reset probe after call {occurrence} to {symbol}")
elif "--reset-after" in text:
    print("payload.py: reset probe already present")
else:
    print("error: the --panic-screen --no-reset pair was not found in payload.py")
    sys.exit(1)
