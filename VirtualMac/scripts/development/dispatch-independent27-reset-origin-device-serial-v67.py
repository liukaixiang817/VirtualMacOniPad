#!/usr/bin/env python3
"""Root-only Runtime68 App81 reset-origin diagnostic update and initialization serial dispatcher; HOST preparation does not execute it.

Each phase delegates to the frozen controller's full ready/prior/once/lock gate.
The sole password prompt is retained only in this Python process's memory.
"""
import argparse
import getpass
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
PACKET=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/independent27-reset-origin-device-v67-attempt1'
CANDIDATE_SHA256='1700257a68bf6630c7c300789222c75060ceae123e3c60e10976c0cf77626609'
ACTIONS=('close-current-own','preflight','stage','verify','trust','launch','post')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--ready',type=pathlib.Path,required=True)
    args=ap.parse_args()
    spec=importlib.util.spec_from_file_location('exact_range_transaction_controller',PACKET/'control.py')
    controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
    controller.need(controller.pin(PACKET/'candidate.json')['sha256']==CANDIDATE_SHA256 and
                    controller.ACTIONS==ACTIONS,'only concrete reviewed interval RAM packet and seven phases')
    ready_path=args.ready.resolve()
    controller.ready_gate(PACKET,ready_path)
    # Reject an earlier attempt before prompting or executing any device call.
    for action in ACTIONS:
        controller.need(not (PACKET/(action+'-dispatched.json')).exists() and
                        not (PACKET/'device-receipts'/action).exists(), 'serial dispatcher cannot resume or repeat phases')
    controller.need(not (PACKET/'dispatch.lock').exists(), 'no other controller action running')
    cached=[getpass.getpass('iPad password: ')]
    original_prompt=controller.getpass.getpass
    controller.getpass.getpass=lambda prompt:cached[0]
    current=None
    try:
        for action in ACTIONS:
            current=action
            print('ROOT_EXACT_RANGE_TRANSACTION_SERIAL_PHASE '+action,flush=True)
            controller.dispatch(argparse.Namespace(packet=PACKET,ready=ready_path,action=action))
    except BaseException:
        # A failed launch may own processes. Preserve its failure and delegate
        # exact cleanup through the same once-only post gate; earlier failures
        # have no launch receipt and cannot fabricate one for post admission.
        if current=='launch' and (PACKET/'device-receipts/launch/receipt.json').is_file() and \
           not (PACKET/'post-dispatched.json').exists() and not (PACKET/'device-receipts/post').exists():
            print('ROOT_EXACT_RANGE_TRANSACTION_FAILED_LAUNCH_POST_CLEANUP',flush=True)
            controller.dispatch(argparse.Namespace(packet=PACKET,ready=ready_path,action='post'))
        raise
    finally:
        controller.getpass.getpass=original_prompt
        cached[0]=None


if __name__=='__main__':main()
