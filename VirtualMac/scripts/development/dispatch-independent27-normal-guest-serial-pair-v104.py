#!/usr/bin/env python3
"""Root-only optional normal V17 wall900 preflight/start pair with one memory prompt.

All ready, freshness, once, fsync lease and ACK logic remains in the unchanged
normal controller. HOST source preparation does not call this entry point.
"""
import argparse
import getpass
import importlib.util
import pathlib
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
PACKET=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/independent27-app105-normal-guest-lifecycle-v109-attempt1'
CANDIDATE_SHA256='bfdc6f0303828704f1af092983dba55872f76a8a5a2ac4ac3774270d720fe053'


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ready',type=pathlib.Path,required=True)
    ap.add_argument('--confirm-handoff',action='store_true',required=True)
    args=ap.parse_args()
    spec=importlib.util.spec_from_file_location('exact_normal_v17_pair_controller',PACKET/'control.py')
    controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
    common,candidate=controller.load_common(PACKET)
    common.need(common.pin(PACKET/'candidate.json')['sha256']==CANDIDATE_SHA256,
                'only concrete reviewed normal V17 wall900 packet')
    ready_path=args.ready.resolve()
    controller.gate(common,PACKET,candidate,ready_path)
    for action in ('preflight','start'):
        common.need(not (PACKET/(action+'-dispatched.json')).exists() and
                    not (PACKET/'device-receipts'/action).exists(), 'pair cannot repeat or resume either phase')
    common.need(not (PACKET/'normal-dispatch.lock').exists(), 'no concurrent normal dispatch')
    cached=[getpass.getpass('iPad password: ')]
    original_prompt=controller.getpass.getpass
    controller.getpass.getpass=lambda prompt:cached[0]
    current=None
    try:
        for action in ('preflight','start'):
            current=action
            print('ROOT_EXACT_NORMAL_SERIAL_PHASE '+action,flush=True)
            controller.dispatch(argparse.Namespace(packet=PACKET,ready=ready_path,action=action,
                sequence=1,lease=None,confirm_handoff=args.confirm_handoff))
    except BaseException:
        start=PACKET/'device-receipts/start'
        if current=='start' and (start/'receipt.json').is_file() and not (start/'handoff-ack.json').exists() and \
           not (PACKET/'post-dispatched.json').exists() and not (PACKET/'device-receipts/post').exists():
            print('ROOT_EXACT_NORMAL_FAILED_START_READONLY_OFF_FIRST_POST',flush=True)
            controller.dispatch(argparse.Namespace(packet=PACKET,ready=ready_path,action='post',
                sequence=1,lease=None,confirm_handoff=False))
        # Any attempted ACK keeps the original explicit Root owner. No copied
        # lease handling, stop logic, ACK or receipt synthesis exists here.
        raise
    finally:
        controller.getpass.getpass=original_prompt
        cached[0]=None


if __name__=='__main__':main()
