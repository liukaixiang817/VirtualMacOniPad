#!/usr/bin/env python3
"""Root serial dispatcher plus one bounded owned-log read after the ten-second diagnostic wake."""
import argparse, importlib.util, pathlib, sys, threading
sys.dont_write_bytecode = True
B = pathlib.Path(__file__).resolve().parent
def load(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('pair-source', 'normal-packet', 'ready', 'stack-output'):
        ap.add_argument('--'+name, required=True, type=pathlib.Path)
    a = ap.parse_args(); packet = a.normal_packet.resolve()
    assert a.pair_source.resolve().parent == B
    pair = load('root_exact_normal_serial_pair', a.pair_source.resolve())
    stack = load('root_exact_owned_stack_reader', B/'read-independent27-active-owned-log-v1.py')
    assert pair.PACKET.resolve() == packet
    assert stack.pin(packet/'candidate.json')['sha256'] == pair.CANDIDATE_SHA256
    done = threading.Event()
    def sample():
        request = packet/'device-receipts/start/request.json'
        while not done.wait(0.2):
            if request.is_file(): break
        if done.wait(20) or (packet/'device-receipts/start/receipt.json').exists(): return
        try:
            stack.main(['--normal-packet', str(packet), '--output', str(a.stack_output.resolve())])
        except SystemExit as e:
            print('ROOT_OWNED_LOG_READER_EXIT '+str(e.code), flush=True)
        except Exception as e:
            print('ROOT_OWNED_LOG_READER_NOT_COMPLETED '+type(e).__name__+': '+str(e), flush=True)
    watcher = threading.Thread(target=sample, name='root-one-active-owned-log', daemon=False)
    old_argv = sys.argv
    try:
        sys.argv = [str(a.pair_source), '--ready', str(a.ready.resolve()), '--confirm-handoff']
        watcher.start()
        # The original pair alone owns preflight/start/ACK/cleanup and keeps
        # its password in memory. Its in-memory prompt also serves the one
        # read-only sampler after the actual start request exists.
        pair.main()
    finally:
        done.set(); watcher.join(60); sys.argv = old_argv
        if watcher.is_alive(): raise RuntimeError('bounded stack reader has not returned')
if __name__ == '__main__': main()
