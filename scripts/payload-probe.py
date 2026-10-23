#!/usr/bin/env python3
"""Pre-build hook for the nash build.

1. Disables the native_legacy_display_probe() call in the XNU patch set: the kit
   belongs to another device and the symbol does not exist for nash yet.
2. Disables configure_misc_apple_regs() in arm_init: it writes Apple-only
   system registers that are undefined on a Qualcomm Kryo core.
3. Adds the boot-progress reset probe to the payload step so one run answers one
   question: "did the kernel get past the call to SYMBOL in arm_init?".

Environment: NASH_PROBE_SYMBOL (default _processor_bootstrap),
             NASH_PROBE_OCCURRENCE (default 1), NASH_NO_RESET=1 to drop the probe.
"""
import os
import pathlib
import sys

ROOT = pathlib.Path.cwd()


def log(message):
    print(f"[nash pre-build] {message}")


# --- 1. drop the display probe calls -------------------------------------
probe_patch = ROOT / "patches/xnu/offline-component-load-probes.patch"
if probe_patch.is_file():
    text = probe_patch.read_text()
    count = text.count("native_legacy_display_probe();")
    if count:
        probe_patch.write_text(text.replace("native_legacy_display_probe();", "/* disabled for nash */"))
    log(f"display probe calls disabled: {count}")

# --- 2. disable the Apple-only register setup ----------------------------
targets = list(ROOT.glob("out/*/tree/.cache/xnu-work/osfmk/arm/arm_init.c"))
if not targets:
    log("warning: arm_init.c not found (was unixnu fetch run?)")
for path in targets:
    text = path.read_text()
    changed = 0
    for old, new in (
        ("\tconfigure_misc_apple_regs(true);", "\t/* nash: Apple-only CPU registers are undefined on MSM8998 */"),
        ("\tconfigure_misc_apple_regs(TRUE);", "\t/* nash: Apple-only CPU registers are undefined on MSM8998 */"),
        ("\tconfigure_misc_apple_boot_args();", "\t/* nash: Apple-only boot args */"),
    ):
        if old in text:
            text = text.replace(old, new)
            changed += 1
    if changed:
        path.write_text(text)
    log(f"{path}: {changed} Apple-only call(s) disabled")

# --- 3. reset probe in the payload step ----------------------------------
symbol = os.environ.get("NASH_PROBE_SYMBOL", "_processor_bootstrap")
occurrence = os.environ.get("NASH_PROBE_OCCURRENCE", "1")
no_reset = os.environ.get("NASH_NO_RESET", "0") == "1"

payload = ROOT / "scripts/unixnu/payload.py"
if not payload.is_file():
    log("error: scripts/unixnu/payload.py not found")
    sys.exit(1)

text = payload.read_text()
old = "'--panic-screen', '--no-reset'"
if no_reset:
    log("reset probe: disabled by NASH_NO_RESET")
elif old in text:
    new = (
        "'--panic-screen', '--no-reset', '--reset-after', "
        f"'{symbol}', '--in', '_arm_init', '--occurrence', '{occurrence}', '--reset-delay', '6'"
    )
    payload.write_text(text.replace(old, new))
    log(f"reset probe: after call {occurrence} to {symbol}")
elif "--reset-after" in text:
    log("reset probe: already present")
else:
    log("error: --panic-screen --no-reset not found in payload.py")
    sys.exit(1)
