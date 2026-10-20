#!/usr/bin/env python3
"""Root-operated temporary VNC; current Device31 transport and exact cleanup."""
import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
CONTROL = N/'independent27-cpu-isa-amx-device-v31-attempt1/control.py'
CONTROL_SHA = '6df6a38f9295a6fbff64228174101266b0ed867717e649b7cf9706618a371a2c'
UDID = '00008112-001E48300207401E'
BOOT = 1792055689
BOOT_UUID = 'A3247B1A-473D-4786-8585-A99DB5B5BDA0'
SERVER = '/private/var/mobile/VirtualMacDebug/trollvncserver'


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    path = pathlib.Path(path)
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


SERVER_FUNCTIONS = r'''
export LC_ALL=C TZ=UTC
server=/private/var/mobile/VirtualMacDebug/trollvncserver
[ "$(realpath /var/mobile/VirtualMacDebug/trollvncserver)" = "$server" ]
[ -f "$server" ] && [ -x "$server" ] && [ ! -L "$server" ]
start_hash() { ps -p "$1" -o lstart= | sha256sum | cut -d ' ' -f1; }
check_own_server() {
 live=$(ps -p "$own_pid" -o pid=,ppid=,uid=,comm= || true)
 if [ -z "$live" ]; then
  if kill -0 "$own_pid" 2>/dev/null; then return 77; fi
  printf 'SERVER_ALREADY_EXITED\n'; return 2
 fi
 set -- $live
 [ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$3" = 0 ] || return 77
 if [ "$2" != "$own_ppid" ]; then
  [ "$2" = 1 ] || return 77
  [ -z "$(ps -p "$own_ppid" -o pid= || true)" ] || return 77
 fi
 [ "$(start_hash "$own_pid")" = "$own_start" ] || return 77
 state=$(ps -p "$own_pid" -o state=)
 case "$state" in *Z*)
  [ "$4" = "$server" ] || [ "$4" = '<defunct>' ] || return 77
  printf 'SERVER_ZOMBIE_SKIP\n'; return 3;; esac
 [ "$4" = "$server" ] && [ "$(realpath "$4")" = "$server" ] || return 77
 printf 'SERVER_ID_VERIFIED %s %s 0 %s %s\n' "$own_pid" "$2" "$own_start" "$server"
}
'''

LAUNCH = r'''
[ -z "$(ps -axo comm= | awk -v s="$server" '$0==s {print}')" ]
IFS= read -r TROLLVNC_PASSWORD
export TROLLVNC_PASSWORD
nohup "$server" -b 127.0.0.1 -p 5901 -s 0.5 -F 5 -O on -o 01 -U on -B off -C off -i off -I off >/dev/null 2>&1 </dev/null &
own_pid=$!; own_ppid=$$; own_start=none
unset TROLLVNC_PASSWORD
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 live=$(ps -p "$own_pid" -o pid=,ppid=,uid=,comm= || true)
 set -- $live
 if [ "$#" = 4 ] && [ "$1" = "$own_pid" ] && [ "$2" = "$own_ppid" ] && [ "$3" = 0 ] && [ "$4" = "$server" ]; then
  own_start=$(start_hash "$own_pid")
  check_own_server
  printf 'OWN_VNC_SERVER %s %s 0 %s %s\n' "$own_pid" "$own_ppid" "$own_start" "$server"
  exit 0
 fi
 sleep 0.1
done
exit 77
'''
CLEANUP = r'''
for signal in TERM KILL; do
 result=0
 check_own_server || result=$?
 case "$result" in 2|3) exit 0;; 0) ;; *) exit 77;; esac
 kill -"$signal" "$own_pid"
 printf 'SIGNALLED_OWN_VNC %s %s\n' "$signal" "$own_pid"
 sleep 1
done
result=0; check_own_server || result=$?
case "$result" in 2|3) exit 0;; *) exit 77;; esac
'''


def load_controller():
    need(pin(CONTROL)['sha256'] == CONTROL_SHA, 'Exact Device31 transport changed')
    spec = importlib.util.spec_from_file_location('vnc_exact_device31_transport', CONTROL)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    prefix = controller.prefix(0)
    need(str(BOOT) in prefix and BOOT_UUID in prefix and 'iPad14,6' in prefix,
         'Exact current boot, UUID and hardware guard required')
    return controller


def native_capture(output, name):
    target = output/(name+'.png')
    result = subprocess.run(['/opt/homebrew/bin/idevicescreenshot', '-u', UDID, str(target)],
                            capture_output=True, timeout=25)
    (output/(name+'.stdout')).write_bytes(result.stdout)
    (output/(name+'.stderr')).write_bytes(result.stderr)
    need(result.returncode == 0 and target.is_file() and
         target.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n', 'Fresh native USB PNG required')


def host_process(pid):
    env = dict(os.environ, LC_ALL='C', TZ='UTC')
    row = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'pid=,ppid=,uid=,comm='],
                         env=env, capture_output=True, text=True, timeout=5)
    fields = row.stdout.strip().split(None, 3)
    if len(fields) != 4:
        return None
    started = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart='],
                             env=env, capture_output=True, timeout=5)
    state = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'state='],
                           env=env, capture_output=True, text=True, timeout=5)
    need(row.returncode == started.returncode == state.returncode == 0 and started.stdout.strip(),
         'Actual proxy identity readable')
    return dict(pid=int(fields[0]), ppid=int(fields[1]), uid=int(fields[2]),
                canonicalPath=str(pathlib.Path(fields[3]).resolve()),
                startHash=hashlib.sha256(started.stdout).hexdigest(), zombie='Z' in state.stdout)


def stop_proxy(proxy, identity):
    for signal in ('TERM', 'KILL'):
        if proxy.poll() is not None:
            return 'already-exited'
        actual = host_process(proxy.pid)
        need(actual is not None and all(actual[k] == identity[k] for k in
             ('pid', 'ppid', 'uid', 'canonicalPath', 'startHash')), 'Refuse changed proxy PID identity')
        if actual['zombie']:
            proxy.wait(timeout=5)
            return 'zombie-reaped-without-signal'
        proxy.terminate() if signal == 'TERM' else proxy.kill()
        try:
            proxy.wait(timeout=2)
            return signal.lower()+'-own-proxy'
        except subprocess.TimeoutExpired:
            pass
    raise RuntimeError('Own proxy did not exit after exact verified cleanup')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('capture', 'calibrate', 'move', 'key', 'tap', 'drag'))
    parser.add_argument('label')
    parser.add_argument('values', nargs='*')
    parser.add_argument('--fresh-calibrated', action='store_true',
                        help='Root confirms this live landscape mapping was manually calibrated')
    parser.add_argument('--cursor-log', action='store_true', help='Optional current Independent27 cursor lines')
    args = parser.parse_args()
    need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', args.label), 'Fresh ordinary label required')
    need(args.action not in ('tap', 'drag') or args.fresh_calibrated,
         'Tap/drag require Root fresh manual landscape calibration flag')
    widths = dict(capture=0, calibrate=0, move=2, tap=2, drag=4)
    if args.action == 'key':
        need(1 <= len(args.values) <= 256 and all(0 < len(k) <= 80 for k in args.values), 'Bounded key list')
    else:
        need(len(args.values) == widths[args.action], 'Exact action coordinate count')
        args.values = [int(v) for v in args.values]
    output = N/('independent27-vnc-input-v2-'+args.label)
    need(not output.exists(), 'Fresh label refuses existing evidence directory')
    controller = load_controller()
    proxy_path = pathlib.Path(shutil.which('iproxy') or '').resolve()
    need(proxy_path.is_file(), 'Existing iproxy required')
    from vncdotool import api
    output.mkdir(mode=0o700)
    password = getpass.getpass('iPad password (memory only): ')
    vnc_password = secrets.token_hex(4)
    save(output/'request.json', dict(source=pin(pathlib.Path(__file__).resolve()),
         transport=pin(CONTROL), action=args.action, label=args.label,
         keyCount=len(args.values) if args.action == 'key' else 0,
         coordinates=args.values if args.action != 'key' else [],
         manualFreshCalibrationConfirmed=args.fresh_calibrated, actualUDID=UDID,
         bootSeconds=BOOT, bootSessionUUID=BOOT_UUID, AppOrVMRestart=False,
         serverArguments=['-b','127.0.0.1','-p','5901','-s','0.5','-F','5','-O','on',
                          '-o','01','-U','on','-B','off','-C','off','-i','off','-I','off']))
    ordinal = 0
    server_id = proxy = proxy_id = client = None
    cleanup = {}
    operation_error = None

    def remote(label, body, data=b''):
        nonlocal ordinal
        ordinal += 1
        status, stdout, stderr, error = controller.run_remote(
            controller.prefix(0)+SERVER_FUNCTIONS+body, data, True, password)
        stem = f'{ordinal:02d}-{label}'
        (output/(stem+'.stdout')).write_bytes(stdout)
        (output/(stem+'.stderr')).write_bytes(stderr)
        save(output/(stem+'.json'), dict(transportExit=status, error=error,
             stdout=pin(output/(stem+'.stdout')), stderr=pin(output/(stem+'.stderr'))))
        return status, stdout

    def identity_script():
        need(server_id is not None, 'No server signal without captured identity')
        return (f'own_pid={server_id["pid"]}\nown_ppid={server_id["ppid"]}\n'
                f'own_start={server_id["startHash"]}\n')

    try:
        with socket.socket() as check:
            check.bind(('127.0.0.1', 15901))
        status, raw = remote('launch-server', LAUNCH, (vnc_password+'\n').encode())
        for line in raw.decode(errors='replace').splitlines():
            words = line.split()
            if len(words) == 6 and words[0] == 'OWN_VNC_SERVER':
                need(words[1].isdigit() and int(words[1]) > 1 and words[2].isdigit() and int(words[2]) > 1 and
                     words[3] == '0' and re.fullmatch('[0-9a-f]{64}', words[4]) and words[5] == SERVER,
                     'Exact launched server identity')
                need(server_id is None, 'Unique launch identity')
                server_id = dict(pid=int(words[1]), ppid=int(words[2]), uid=0,
                                 startHash=words[4], canonicalPath=words[5])
                save(output/'server-identity.json', server_id)
        need(status == 0 and server_id is not None, 'Server launch must capture exact identity')
        proxy = subprocess.Popen([str(proxy_path), '-u', UDID, '-s', '127.0.0.1', '15901:5901'],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        proxy_id = host_process(proxy.pid)
        need(proxy_id and proxy_id['ppid'] == os.getpid() and proxy_id['uid'] == os.getuid() and
             proxy_id['canonicalPath'] == str(proxy_path) and not proxy_id['zombie'], 'Own actual proxy identity')
        save(output/'proxy-identity.json', proxy_id)
        status, _ = remote('verify-before-client', identity_script()+'check_own_server\n')
        need(status == 0, 'Same boot and exact live server required before input')
        client = api.connect('127.0.0.1::15901', password=vnc_password, timeout=8)
        client.refreshScreen()
        client.captureScreen(str(output/'vnc-before.png'))
        width, height = client.screen.size
        save(output/'framebuffer.json', dict(width=width, height=height))
        native_capture(output, 'native-before')

        def point(x, y):
            need(0 <= x < width and 0 <= y < height, 'Coordinate inside actual fresh RFB frame')
            return x, y

        if args.action == 'calibrate':
            for i, xy in enumerate(((300, 200), (900, 650), (650, 450))):
                client.mouseMove(*point(*xy))
                time.sleep(0.8)
                native_capture(output, f'calibration-point-{i}')
        elif args.action in ('move', 'tap'):
            client.mouseMove(*point(*args.values))
            if args.action == 'tap':
                client.mouseDown(1)
                try:
                    time.sleep(0.15)
                finally:
                    client.mouseUp(1)
        elif args.action == 'drag':
            x0, y0, x1, y1 = args.values
            point(x0, y0)
            point(x1, y1)
            client.mouseMove(x0, y0)
            client.mouseDown(1)
            try:
                for step in range(1, 21):
                    client.mouseMove(round(x0+(x1-x0)*step/20), round(y0+(y1-y0)*step/20))
                    time.sleep(0.035)
            finally:
                client.mouseUp(1)
        elif args.action == 'key':
            for key in args.values:
                client.keyPress(key)
                time.sleep(0.1)
        if args.cursor_log:
            status, _ = remote('current-cursor-log', identity_script()+'''check_own_server
if [ -f "$OWN_LOG" ]; then tail -120 "$OWN_LOG" | awk '/PVG cursor=|input pointer/ {print}'; fi
''')
            need(status == 0, 'Current boot/server cursor receipt')
        time.sleep(0.5)
        client.captureScreen(str(output/'vnc-after.png'))
        native_capture(output, 'native-after')
    except BaseException as error:
        operation_error = error
    finally:
        if client is not None:
            try:
                client.disconnect()
            except Exception as error:
                cleanup['clientError'] = type(error).__name__
        if server_id is not None:
            try:
                status, _ = remote('cleanup-own-server', identity_script()+CLEANUP)
                cleanup['serverExactCleanupExit'] = status
            except Exception as error:
                cleanup['serverError'] = type(error).__name__
        if proxy is not None:
            try:
                need(proxy_id is not None, 'Never signal an uncaptured proxy identity')
                cleanup['proxy'] = stop_proxy(proxy, proxy_id)
            except Exception as error:
                cleanup['proxyError'] = type(error).__name__
        try:
            api.shutdown()
        except Exception as error:
            cleanup['apiError'] = type(error).__name__
        password = vnc_password = None
        save(output/'receipt.json', dict(finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
             action=args.action, operationCompleted=operation_error is None,
             operationError=type(operation_error).__name__ if operation_error else None,
             cleanup=cleanup, deviceAppOrVMChanged=False,
             guestVerified=False, inputCalibrationVerified=False))
        save(output/'freeze.json', dict(files=[pin(p) for p in sorted(output.iterdir()) if p.is_file()]+
             [pin(pathlib.Path(__file__).resolve()), pin(CONTROL)]))
    print(json.dumps(pin(output/'receipt.json')), flush=True)
    if operation_error is not None:
        raise operation_error
    need(cleanup.get('serverExactCleanupExit') == 0 and
         not any(k.endswith('Error') for k in cleanup), 'Exact temporary VNC cleanup must complete')


if __name__ == '__main__':
    main()

