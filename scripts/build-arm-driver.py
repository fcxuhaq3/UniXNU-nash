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

INSPECT_TEXT = """
    void NativeUfs::inspect (void)
    {
      OSSharedPtr<IOMemoryMap> gccMap, hcMap, gicMap;
      IOLog ("NATIVE_UFS: inspect 1 (map GIC for a control read)");
      uintptr_t gic = mapPhys (0x17a00000ULL, 0x1000, gicMap);
      IOLog ("NATIVE_UFS: inspect 2 gic=%p", (void *) gic);
      if (gic) {
        IOLog ("NATIVE_UFS: inspect 3 GIC_CTLR=%08x", read32 (gic, 0x00));
      }
      IOLog ("NATIVE_UFS: inspect 4 (map GCC 0x75000)");
      uintptr_t gcc = mapPhys (GCC_BASE + 0x75000, 0x2000, gccMap);
      IOLog ("NATIVE_UFS: inspect 5 gcc=%p", (void *) gcc);
      if (!gcc) {
        IOLog ("NATIVE_UFS: GCC map failed");
        return;
      }
      IOLog ("NATIVE_UFS: inspect 6 (read GDSCR 0x175004)");
      uint32_t gdsc = read32 (gcc, 0x004);
      IOLog ("NATIVE_UFS: inspect 7 gdsc=%08x", gdsc);
      IOLog ("NATIVE_UFS: inspect 8 (read AXI 0x175008)");
      uint32_t axi = read32 (gcc, 0x008);
      IOLog ("NATIVE_UFS: inspect 9 axi=%08x", axi);
      IOLog ("NATIVE_UFS: inspect 10 (read AHB 0x17500c)");
      uint32_t ahb = read32 (gcc, 0x00c);
      IOLog ("NATIVE_UFS: inspect 11 ahb=%08x", ahb);
      IOLog ("NATIVE_UFS: inspect 12 (map HC 0x1da4000)");
      uintptr_t hc = mapPhys (UFS_HC_BASE, UFS_HC_SIZE, hcMap);
      IOLog ("NATIVE_UFS: inspect 13 hc=%p", (void *) hc);
      if (!hc) {
        IOLog ("NATIVE_UFS: HC map failed");
        return;
      }
      IOLog ("NATIVE_UFS: inspect 14 (read CAP)");
      uint32_t cap = read32 (hc, 0x00);
      IOLog ("NATIVE_UFS: inspect 15 CAP=%08x", cap);
      IOLog ("NATIVE_UFS: inspect 16 (read VER)");
      uint32_t ver = read32 (hc, 0x08);
      IOLog ("NATIVE_UFS: inspect 17 VER=%08x", ver);
      IOLog ("NATIVE_UFS: inspect 18 (read HCS)");
      uint32_t hcs = read32 (hc, 0x30);
      IOLog ("NATIVE_UFS: inspect 19 HCS=%08x", hcs);
      IOLog ("NATIVE_UFS: inspect done");
    }

"""


def fix_unverified_ufs_source():
    """Make NativeUfs build and run on nash (MSM8998).

    - guard the verification timers so the --unverified transport compiles
    - accept our device-tree compatible and the real controller address
    - log probe/start so a silent no-match is visible
    - replace inspect() with a panic-free register read using MSM8998 offsets
    """
    source = ROOT / 'drivers/NativeUfs/NativeUfs.cpp'
    if not source.is_file():
        return
    text = source.read_text()

    old_read = """    IOReturn read (uint64_t lba, uint32_t blocks, void *out) {
      uint64_t t0 = timerTicks ();
      IOReturn r = hostRead4k (0, lba, blocks, out);
      __atomic_fetch_add (&native_ufs_read_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      return r;
    }"""
    new_read = """    IOReturn read (uint64_t lba, uint32_t blocks, void *out) {
#if defined(NATIVE_VERIFIED_BLOCK) && NATIVE_VERIFIED_BLOCK
      uint64_t t0 = timerTicks ();
      IOReturn r = hostRead4k (0, lba, blocks, out);
      __atomic_fetch_add (&native_ufs_read_ticks, timerTicks () - t0, __ATOMIC_RELAXED);
      return r;
#else
      return hostRead4k (0, lba, blocks, out);
#endif
    }"""
    if old_read in text:
        text = text.replace(old_read, new_read, 1)
        print('NativeUfs: guarded the verification timers')

    before = text
    text = text.replace('"qcom,sm8550-ufshc"', '"msm8998-ufshc"')
    if text != before:
        print('NativeUfs: retargeted the compatible to qcom,msm8998-ufshc')

    header = ROOT / 'drivers/NativeUfs/GccUfs.h'
    if header.is_file():
        h = header.read_text()
        if 'UFS_HC_BASE                   0x01d84000ULL' in h:
            h = h.replace('UFS_HC_BASE                   0x01d84000ULL',
                          'UFS_HC_BASE                   0x01da4000ULL')
            header.write_text(h)
            print('NativeUfs: retargeted UFS_HC_BASE to 0x01da4000')

    probe_anchor = """IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  native_ufs_probe_calls = native_ufs_probe_calls + 1;"""
    probe_new = """IOService *NativeUfs::probe (IOService *provider, SInt32 *score)
{
  IOLog ("NATIVE_UFS: probe called provider=%s class=%s\\n",
         provider ? provider->getName () : "null",
         provider ? provider->getMetaClass ()->getClassName () : "null");
  native_ufs_probe_calls = native_ufs_probe_calls + 1;"""
    if probe_anchor in text and 'NATIVE_UFS: probe called' not in text:
        text = text.replace(probe_anchor, probe_new, 1)
        print('NativeUfs: probe logging installed')

    start_anchor = """  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  native_ufs_probe_requested = probe != 0;"""
    start_new = """  unsigned probe = 0, rootMode = 0;
  PE_parse_boot_argn ("native-ufs-probe", &probe, sizeof (probe));
  PE_parse_boot_argn ("native-ufs-root", &rootMode, sizeof (rootMode));
  IOLog ("NATIVE_UFS: start probe=%u rootMode=%u provider=%s\\n",
         probe, rootMode, provider ? provider->getName () : "null");
  native_ufs_probe_requested = probe != 0;"""
    if start_anchor in text and 'NATIVE_UFS: start probe=' not in text:
        text = text.replace(start_anchor, start_new, 1)
        print('NativeUfs: start logging installed')

    begin = text.find("void NativeUfs::inspect (void)")
    end = text.find("// Adopt the controller the firmware left running", begin)
    if begin >= 0 and end > begin:
        text = text[:begin] + INSPECT_TEXT + text[end:]
        print('NativeUfs: inspect() replaced with the MSM8998 register probe')

    source.write_text(text)



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
