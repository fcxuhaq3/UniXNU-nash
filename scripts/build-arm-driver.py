#!/usr/bin/env python3
"""Compile the generic platform expert against the actual source-kernel ABI."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('component', choices=['ArmVirtPlatform', 'ArmDTPlatform', 'ArmCpu', 'NativeAES', 'NativeVirtioBlock', 'NativeRamBlock', 'NativeMobileDisplay', 'NativeVirtioConsole', 'NativeLegacyDisplay', 'NativeGOPPresenter', 'NativeOfflineGPU', 'NativeOfflineAccelerator', 'NativeIOGPUProviderProbe', 'NativeUfs', 'NativeHidInput', 'NativeKeyStoreEvents', 'NativeAdreno'])
parser.add_argument('--negative-aes-kat', action='store_true', help='Isolated own-source wrong-answer refusal control; never changes original inputs')
parser.add_argument('--verified-root', action='store_true', help='Authenticate all actual disk reads against an independently signed immutable policy')
parser.add_argument('--verified-root-bundle', action='store_true', help='Select exactly one capacity-matching policy per device, then independently authenticate it')
parser.add_argument('--negative-verified-block', action='store_true', help='Negative own-buffer control: corrupt only the completed DMA snapshot')
parser.add_argument('--unverified', action='store_true', help='NativeUfs: compile the bring-up transport without the verified-root policy bundle')
args = parser.parse_args()
if args.verified_root_bundle and not args.verified_root:
    parser.error('A policy bundle requires verified block mode')
if args.verified_root_bundle and args.negative_verified_block:
    parser.error('Select either bundle policy qualification or the isolated DMA snapshot fault')
if (args.verified_root or args.negative_verified_block) and args.component != 'NativeVirtioBlock':
    parser.error('Verified block mode requires the concrete read-only block transport')
if args.negative_verified_block and not args.verified_root:
    parser.error('The isolated input fault requires verified block mode')
if args.unverified and args.component != 'NativeUfs':
    parser.error('--unverified currently applies to the NativeUfs bring-up transport only')
component = args.component
recipe = ROOT / 'build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/iokit/DEVELOPMENT/IOPlatformExpert.cpo.json'
record = json.loads(recipe.read_text().strip().rstrip(','))
source = ROOT / 'drivers' / ('NativeMobileDisplay' if component in ('NativeLegacyDisplay','NativeGOPPresenter') else 'NativeMetal' if component in ('NativeOfflineGPU','NativeOfflineAccelerator','NativeIOGPUProviderProbe') else component) / {'NativeAdreno':'NativeAdrenoService.cpp'}.get(component, component + '.cpp')
out = ROOT / 'build' / {'ArmVirtPlatform': 'armvirt-platform', 'ArmDTPlatform': 'armdt-platform', 'ArmCpu': 'armcpu', 'NativeAES': 'native-aes',
                        'NativeVirtioBlock': 'native-virtio-block', 'NativeRamBlock': 'native-ram-block',
                        'NativeMobileDisplay': 'native-mobile-display', 'NativeVirtioConsole': 'native-virtio-console',
                        'NativeLegacyDisplay': 'native-legacy-display', 'NativeGOPPresenter': 'native-gop-presenter', 'NativeOfflineGPU':'native-offline-gpu','NativeOfflineAccelerator':'native-offline-accelerator','NativeIOGPUProviderProbe':'native-original-provider', 'NativeUfs':'native-ufs', 'NativeHidInput':'native-hid-input', 'NativeKeyStoreEvents':'native-keystore-events', 'NativeAdreno':'native-adreno'}[component]
if args.verified_root:
    out = ROOT / ('build/native-virtio-block-verified-fault' if args.negative_verified_block else 'build/native-virtio-block-verified')
    if args.verified_root_bundle:
        out = ROOT / 'build/native-virtio-block-verified-bundle'
out.mkdir(parents=True, exist_ok=True)
if args.negative_aes_kat:
    if component != 'NativeAES':
        parser.error('The own-source KAT control requires NativeAES')
    out = ROOT / 'build/native-aes-kat-negative'
    out.mkdir(parents=True, exist_ok=True)
    text = source.read_text()
    marker = '0x76,0x49,0xab,0xac'
    if text.count(marker) != 1:
        raise SystemExit('The exact own-source NIST answer was not uniquely identified')
    (out / 'OriginalAESABI.h').write_bytes(source.with_name('OriginalAESABI.h').read_bytes())
    source = out / 'NativeAES.cpp'
    source.write_text(text.replace(marker, '0x77,0x49,0xab,0xac'))
destination = out / (component + '.o')
arguments = record['arguments']
command = []
index = 0
while index < len(arguments):
    value = arguments[index]
    if value == record['file']:
        command.append(str(source))
    elif value == '-o':
        command.extend(['-o', str(destination)])
        index += 1
    elif value == '-Xclang' and arguments[index + 1].startswith('-W'):
        index += 1
    elif not value.startswith('-W'):
        command.append(value)
    index += 1
command.extend(['-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                '-Wno-c99-designator', '-Wno-reorder-init-list', '-Wno-deprecated-enum-enum-conversion',
                '-Wno-unnecessary-virtual-specifier', '-I', str(ROOT / '.cache/xnu-work/osfmk')])
if component in ('NativeVirtioBlock', 'NativeRamBlock', 'NativeUfs'):
    command += ['-I', str(ROOT / 'build/storage-abi/include')]
    if args.verified_root:
        command += ['-I', str(ROOT / 'kits/VerifiedRoot/include'), '-DNATIVE_VERIFIED_BLOCK=1']
    if args.negative_verified_block:
        command += ['-DNATIVE_VERIFIED_BLOCK_INJECT_FAULT=1']
    if args.verified_root_bundle:
        command += ['-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1']

def fix_unverified_ufs_source():
    """Guard the verification timers so the --unverified transport compiles.

    Operations::read() times the transfer with timerTicks()/native_ufs_read_ticks,
    but those live inside the NATIVE_VERIFIED_BLOCK block. Without the policy bundle
    the identifiers are undeclared, so the unverified build cannot compile as shipped.
    """
    source = ROOT / 'drivers/NativeUfs/NativeUfs.cpp'
    if not source.is_file():
        return
    text = source.read_text()
    old = """    IOReturn read (uint64_t lba, uint32_t blocks, void *out) {
      uint64_t t0 = timerTicks ();
      IOReturn r = hostRead4k (0, lba, blocks, out);
      __atomic_fetch_add (&native_ufs_read_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      return r;
    }"""
    new = """    IOReturn read (uint64_t lba, uint32_t blocks, void *out) {
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
      uint64_t t0 = timerTicks ();
      IOReturn r = hostRead4k (0, lba, blocks, out);
      __atomic_fetch_add (&native_ufs_read_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      return r;
#else
      return hostRead4k (0, lba, blocks, out);
#endif
    }"""
    if old in text:
        source.write_text(text.replace(old, new, 1))
        print('NativeUfs: guarded the verification timers for the unverified build')

    # nash runs the MSM8998 UFS 2.1 controller, not sheng's SM8550 part: the driver
    # has to accept our device-tree compatible and address the right host window.
    text = source.read_text()
    before = text
    text = text.replace('"qcom,sm8550-ufshc"', '"msm8998-ufshc"')
    text = text.replace('#define UFS_HC_BASE                   0x01d84000ULL',
                        '#define UFS_HC_BASE                   0x01da4000ULL')
    if text != before:
        source.write_text(text)
        print('NativeUfs: retargeted to qcom,msm8998-ufshc at 0x01da4000')

    # Log every probe and start attempt: without this the bring-up is blind, because a
    # statically linked driver that is never matched produces no output at all.
    text = source.read_text()
    if 'NATIVE_UFS: probe called' not in text:
        probe_anchor = '''IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  native_ufs_probe_calls = native_ufs_probe_calls + 1;'''
        probe_new = '''IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  IOLog ("NATIVE_UFS: probe called provider=%s class=%s\\n",
         provider ? provider->getName () : "null",
         provider ? provider->getMetaClass ()->getClassName () : "null");
  native_ufs_probe_calls = native_ufs_probe_calls + 1;'''
        if probe_anchor in text:
            text = text.replace(probe_anchor, probe_new, 1)
            source.write_text(text)
            print('NativeUfs: probe logging installed')

    # Also log what start() parses: probe() runs but start() returns early when the
    # native-ufs-probe boot argument never reaches the kernel, and that is invisible.
    text = source.read_text()
    if 'NATIVE_UFS: start probe=' not in text:
        start_anchor = '''  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  native_ufs_probe_requested = probe != 0;'''
        start_new = '''  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  IOLog ("NATIVE_UFS: start probe=%u rootMode=%u provider=%s\\n",
         probe, rootMode, provider ? provider->getName () : "null");
  native_ufs_probe_requested = probe != 0;'''
        if start_anchor in text:
            text = text.replace(start_anchor, start_new, 1)
            source.write_text(text)
            print('NativeUfs: start logging installed')

    # nash has no iBoot panic-log buffer, so gPanicBase stays 0 and panic() cannot print:
    # inspect() used to end in panic(), which hangs silently. Log the values instead and
    # mark each step so a hang is attributable.
    text = source.read_text()
    if 'NATIVE_UFS: inspect step' not in text:
        old = '''  uintptr_t gcc = mapPhys (GCC_BASE + 0x77000, 0x1000, gccMap);
  uintptr_t memPhy = mapPhys (GCC_BASE + 0x9e000, 0x1000, memPhyMap);
  if (!gcc || !memPhy) {
    panic ("NATIVE_UFS inspect: GCC map failed gcc=%p memphy=%p", (void *) gcc, (void *) memPhy);
  }'''
        new = '''  IOLog ("NATIVE_UFS: inspect step 1 (mapping GCC)\\n");
  uintptr_t gcc = mapPhys (GCC_BASE + 0x77000, 0x1000, gccMap);
  IOLog ("NATIVE_UFS: inspect step 2 gcc=%p\\n", (void *) gcc);
  uintptr_t memPhy = mapPhys (GCC_BASE + 0x9e000, 0x1000, memPhyMap);
  IOLog ("NATIVE_UFS: inspect step 3 memphy=%p\\n", (void *) memPhy);
  if (!gcc || !memPhy) {
    IOLog ("NATIVE_UFS inspect: GCC map failed gcc=%p memphy=%p\\n", (void *) gcc, (void *) memPhy);
    return;
  }'''
        if old in text:
            text = text.replace(old, new, 1)

        # the final panic(): log instead, so the numbers actually reach the console
        old_tail = '''  panic ("NATIVE_UFS inspect\\n"'''
        new_tail = '''  IOLog ("NATIVE_UFS inspect\\n"'''
        text = text.replace(old_tail, new_tail, 1)
        source.write_text(text)
        print('NativeUfs: inspect logging installed, panic replaced')

    # The first GCC read stalls the bus, which means that block is not clocked. Read the
    # UFS host controller first (firmware normally leaves it up) and log before every
    # access so a stall is attributable to a single register.
    text = source.read_text()
    if 'inspect step 4' not in text:
        anchor_read = "  uint32_t gdsc = read32 (gcc, GCC_UFS_PHY_GDSCR - 0x77000);"
        replacement = (
            '  IOLog ("NATIVE_UFS: inspect step 4 (mapping HC)");\n'
            '  {\n'
            '    OSSharedPtr<IOMemoryMap> hcProbeMap;\n'
            '    uintptr_t hcProbe = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcProbeMap);\n'
            '    IOLog ("NATIVE_UFS: inspect step 5 hc=%p", (void *) hcProbe);\n'
            '    if (hcProbe) {\n'
            '      IOLog ("NATIVE_UFS: inspect step 6 (reading CAP)");\n'
            '      IOLog ("NATIVE_UFS: CAP=%08x", read32 (hcProbe, 0x00));\n'
            '      IOLog ("NATIVE_UFS: inspect step 7 (reading VER)");\n'
            '      IOLog ("NATIVE_UFS: VER=%08x", read32 (hcProbe, 0x08));\n'
            '      IOLog ("NATIVE_UFS: inspect step 8 (reading HCS)");\n'
            '      IOLog ("NATIVE_UFS: HCS=%08x", read32 (hcProbe, 0x30));\n'
            '      IOLog ("NATIVE_UFS: inspect step 9 (reading HCE)");\n'
            '      IOLog ("NATIVE_UFS: HCE=%08x", read32 (hcProbe, 0x34));\n'
            '    }\n'
            '  }\n'
            '  IOLog ("NATIVE_UFS: inspect step 10 (reading GCC gdsc)");\n'
            '  uint32_t gdsc = read32 (gcc, GCC_UFS_PHY_GDSCR - 0x77000);\n'
            '  IOLog ("NATIVE_UFS: inspect step 11 gdsc=%08x", gdsc);')
        if anchor_read in text:
            text = text.replace(anchor_read, replacement, 1)
            source.write_text(text)
            print('NativeUfs: controller-first inspect installed')

    # Control read: the GIC distributor is a device window this kernel demonstrably uses,
    # so if it also stalls then mapPhys() is not producing real device mappings, and the
    # UFS/GCC stalls say nothing about power.
    text = source.read_text()
    if 'GIC control read' not in text:
        anchor_gic = '  IOLog ("NATIVE_UFS: inspect step 4 (mapping HC)");'
        gic_block = (
            '  IOLog ("NATIVE_UFS: GIC control read (mapping 0x17a00000)");\n'
            '  {\n'
            '    OSSharedPtr<IOMemoryMap> gicMap;\n'
            '    uintptr_t gic = mapPhys (0x17a00000ULL, 0x1000, gicMap);\n'
            '    IOLog ("NATIVE_UFS: GIC map=%p", (void *) gic);\n'
            '    if (gic) {\n'
            '      IOLog ("NATIVE_UFS: GIC CTLR=%08x", read32 (gic, 0x00));\n'
            '      IOLog ("NATIVE_UFS: GIC control read done");\n'
            '    }\n'
            '  }\n'
            '  IOLog ("NATIVE_UFS: inspect step 4 (mapping HC)");')
        if anchor_gic in text:
            text = text.replace(anchor_gic, gic_block, 1)
            source.write_text(text)
            print('NativeUfs: GIC control read installed')

if component == 'NativeUfs':
    command += ['-I', str(ROOT / 'kits/VerifiedRoot/include'), '-I', str(ROOT / 'drivers/NativeVirtioBlock'),
                '-mgeneral-regs-only']
    if args.unverified:
        fix_unverified_ufs_source()
    if not args.unverified:
        command += ['-DNATIVE_VERIFIED_BLOCK=1', '-DNATIVE_VERIFIED_BLOCK_MULTI_POLICY=1']
if component=='NativeOfflineGPU':
    command += ['-I',str(ROOT/'drivers/NativeVirtioConsole')]
if component in ('NativeLegacyDisplay','NativeHidInput'):
    command += ['-I', str(out)]
if component == 'NativeAdreno':
    command += ['-I', str(ROOT / 'kits/ArmSmmu4K'), '-I', str(ROOT / 'kits/AdrenoPM4'),
                '-I', str(ROOT / 'kits/uke'), '-I', str(ROOT / 'kits/AdrenoFirmware'),
                '-I', str(ROOT / 'build/sheng-gmu')]
(out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
result = subprocess.run(command, cwd=record['directory'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
(out / 'compile.log').write_text(result.stdout)
if result.returncode:
    bad = [line for line in result.stdout.splitlines()
           if ': error' in line or 'error:' in line or 'fatal error' in line]
    raise SystemExit('\n'.join(bad[:40]) if bad else result.stdout[-3500:])
data = destination.read_bytes()
magic, cpu, subtype, kind, count, size = struct.unpack_from('<6I', data)
if (magic, cpu, subtype, kind) != (0xfeedfacf, 0x100000c, 0, 1):
    raise SystemExit('Unexpected platform object architecture')
offset = 32
deployment = None
for _ in range(count):
    cmd, length = struct.unpack_from('<II', data, offset)
    if cmd == 0x32:
        deployment = struct.unpack_from('<II', data, offset + 8)
    offset += length
if deployment != (2, 0x110000):
    raise SystemExit(f'Unexpected platform deployment {deployment}')
archive = out / ('lib' + component + '.a')
archive.unlink(missing_ok=True)
subprocess.run(['xcrun', 'ar', 'rcs', archive, destination], check=True)
print(f'{component}: -Werror build and actual ARM64/iOS 17 object audit passed')
