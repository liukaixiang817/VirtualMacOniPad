"""Private development-guest loader, executed inside the bundled Apple LLDB.

The native watcher verifies this file and the module before invoking LLDB.
No network listener, system binary replacement, or global policy change.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

import lldb

ROOT = Path('/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1')
MODULE = Path('/Library/Application Support/BTServer/VirtualMacSharedRadioDevelopment-v1/VM27SharedBluetoothClassicSupplementV2.dylib')
EXPECTED_MODULE_SHA256 = '__VM27_MODULE_SHA256__'
RECEIPT = ROOT / 'native-classic-autoload-v1.json'


def secure_bytes(path, limit):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > limit:
            raise RuntimeError('private loader file validation failed')
        data = bytearray()
        while len(data) < info.st_size:
            part = os.read(fd, info.st_size - len(data))
            if not part:
                raise RuntimeError('private loader file truncated')
            data.extend(part)
        return bytes(data)
    finally:
        os.close(fd)


def sysctl(name):
    return subprocess.check_output(['/usr/sbin/sysctl', '-n', name], text=True).strip()


def atomic_receipt(report):
    fd, name = tempfile.mkstemp(prefix='.classic-autoload-', dir=str(ROOT))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, str(RECEIPT))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(debugger):
    process = None
    report = {'schema': 1, 'installed': False, 'debuggerDetached': False,
              'moduleSHA256': EXPECTED_MODULE_SHA256, 'systemBinaryModified': False,
              'bootUUID': os.environ['VM27_CLASSIC_BOOT_UUID'], 'bluetoothdPID': int(os.environ['VM27_CLASSIC_PID']),
              'timestampUnix': time.time(), 'attemptIndex': int(os.environ['VM27_CLASSIC_ATTEMPT'])}
    try:
        if os.geteuid() != 0 or sysctl('kern.osversion') != '25G83':
            raise RuntimeError('unsupported guest identity')
        boot = sysctl('kern.bootsessionuuid')
        pid = int(os.environ['VM27_CLASSIC_PID'])
        if boot != os.environ['VM27_CLASSIC_BOOT_UUID'] or pid <= 1:
            raise RuntimeError('guest boot identity changed')
        report.update(bootUUID=boot, bluetoothdPID=pid)
        path = subprocess.check_output(['/bin/ps', '-p', str(pid), '-o', 'comm='], text=True).strip()
        if path != '/usr/sbin/bluetoothd':
            raise RuntimeError('unexpected native daemon identity')
        if hashlib.sha256(secure_bytes(MODULE, 4 * 1024 * 1024)).hexdigest() != EXPECTED_MODULE_SHA256:
            raise RuntimeError('module hash differs from the reviewed build')
        debugger.SetAsync(False)
        for command in ['settings set symbols.enable-external-lookup false',
                        'settings set target.preload-symbols false',
                        'settings set target.auto-import-clang-modules false',
                        'settings set target.load-script-from-symbol-file false',
                        # A large read can cross a stack guard or the end of
                        # a small JIT allocation. LLDB then rejects an otherwise
                        # readable call stack before executing the load plan.
                        'settings set target.process.memory-cache-line-size 64']:
            debugger.HandleCommand(command)

        def attach():
            error = lldb.SBError()
            target = debugger.CreateTarget('/usr/sbin/bluetoothd', None, None, False, error)
            if not error.Success():
                raise RuntimeError('native target creation failed: ' + error.GetCString())
            proc = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
            if not error.Success() or not proc.IsValid() or proc.GetProcessID() != pid:
                if proc.IsValid():
                    proc.Detach()
                raise RuntimeError('native local attach failed: ' + str(error.GetCString()))
            report['nativeTargetTriple'] = target.GetTriple()
            report['nativeThreadCount'] = proc.GetNumThreads()
            thread = proc.GetSelectedThread()
            if not thread.IsValid() or thread.GetNumFrames() == 0:
                for candidate in proc:
                    if candidate.IsValid() and candidate.GetNumFrames() > 0:
                        thread = candidate
                        break
            report['nativeSelectedThreadValid'] = thread.IsValid()
            if not thread.IsValid() or thread.GetNumFrames() == 0:
                proc.Detach()
                raise RuntimeError('native attach has no stopped thread with a frame')
            proc.SetSelectedThread(thread)
            report['nativeSelectedThreadFrames'] = thread.GetNumFrames()
            return target, proc

        target, process = attach()

        def mapped():
            return any(module.GetFileSpec().GetFilename() == MODULE.name for module in target.modules)

        if not mapped():
            error = lldb.SBError()
            token = process.LoadImage(lldb.SBFileSpec(str(MODULE)), error)
            report['nativeLoadCallSucceeded'] = error.Success()
            if not error.Success():
                report['nativeLoadError'] = str(error.GetCString())[:800]
            report['nativeLoadTokenValid'] = token != lldb.LLDB_INVALID_IMAGE_TOKEN
            if not mapped():
                # Some arm64e LLDB calls complete dlopen but fail to read its
                # return buffer. Reattach once to refresh dyld's image list.
                detached = process.Detach()
                if not detached.Success():
                    raise RuntimeError('cannot refresh native image list safely')
                process = None
                target, process = attach()
            if not mapped():
                raise RuntimeError('reviewed module did not become visible')

        def symbol(name, kind):
            values = target.FindSymbols(name, kind)
            for index in range(values.GetSize()):
                context = values.GetContextAtIndex(index)
                if context.GetModule().GetFileSpec().GetFilename() == MODULE.name:
                    return context.GetSymbol().GetStartAddress().GetLoadAddress(target)
            raise RuntimeError('reviewed module symbol missing')

        address = symbol('VM27SharedBluetoothClassicInstallationStatusV1', lldb.eSymbolTypeData)

        def installation_status():
            error = lldb.SBError()
            value = process.ReadUnsignedFromMemory(address, 4, error)
            if not error.Success():
                raise RuntimeError('cannot read module installation receipt')
            return value

        if installation_status() != 0:
            options = lldb.SBExpressionOptions()
            options.SetLanguage(lldb.eLanguageTypeC)
            options.SetTimeoutInMicroSeconds(5000000)
            options.SetIgnoreBreakpoints(True)
            options.SetUnwindOnError(True)
            options.SetSuppressPersistentResult(True)
            expression = ('({ extern int VM27SharedBluetoothInstallClassicV1(const char *); '
                          '(void)VM27SharedBluetoothInstallClassicV1("' + boot + '"); })')
            process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression(expression, options)
        report['installerResult'] = installation_status()
        report['installed'] = report['installerResult'] == 0
    except Exception as error:
        report['error'] = str(error)[:800]
    finally:
        if process is not None and process.IsValid():
            report['debuggerDetached'] = process.Detach().Success()
        report['timestampUnix'] = time.time()
        atomic_receipt(report)
        print(json.dumps(report, sort_keys=True))


run(lldb.debugger)
