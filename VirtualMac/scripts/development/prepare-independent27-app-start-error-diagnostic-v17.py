#!/usr/bin/env python3
"""Create one copied Main17 diagnostic hunk; never compile/sign/run an App."""
import copy
import difflib
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    prior = N / 'independent27-app-first-basic-boot-source-v13-attempt1/candidate.json'
    assert pin(prior)['sha256'] == 'de626a225a07a3fe9d9bd6a6b5695a7b0faa12ac3e43275b0e5e165d27b42677'
    c = json.loads(prior.read_bytes())
    sourcepath = pathlib.Path(c['source']['path'])
    assert pin(sourcepath) == c['source']
    old = sourcepath.read_text()
    marker = '    void (^completion)(NSError *) = ^(NSError *startError) {\n        if (startError) {\n'
    assert old.count(marker) == 1
    diagnostic = '''            if (VZIndependent27SourceRouteSelected()) {
                fprintf(stderr, "[Independent27] start-vm rejected: actual-start-error domain=%s code=%ld userInfo=%s debug=%s\\n",
                    startError.domain.UTF8String ?: "(nil)", (long)startError.code,
                    startError.userInfo.description.UTF8String ?: "(nil)",
                    startError.debugDescription.UTF8String ?: "(nil)");
                id actualUnderlyingError=[startError.userInfo objectForKey:NSUnderlyingErrorKey];
                if ([actualUnderlyingError isKindOfClass:[NSError class]]) {
                    NSError *actualUnderlying=(NSError *)actualUnderlyingError;
                    fprintf(stderr, "[Independent27] start-vm rejected: actual-start-error underlyingDomain=%s underlyingCode=%ld underlyingUserInfo=%s underlyingDebug=%s\\n",
                        actualUnderlying.domain.UTF8String ?: "(nil)", (long)actualUnderlying.code,
                        actualUnderlying.userInfo.description.UTF8String ?: "(nil)",
                        actualUnderlying.debugDescription.UTF8String ?: "(nil)");
                }
            }
'''
    new = old.replace(marker, marker + diagnostic)
    assert new.replace(diagnostic, '', 1) == old
    out = N / 'independent27-app-start-error-diagnostic-source-v17-attempt1'
    assert not out.exists()
    out.mkdir(mode=0o700)
    target = out / 'VirtualMacApp.independent27.start-error-diagnostic-source-v17.m'
    target.write_text(new)
    diff = out / 'main13-to-main17.diff'
    diff.write_text(''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=str(sourcepath), tofile=str(target))))
    result = copy.deepcopy(c)
    result.update(schema='Copied Main17 actual NSError start failure diagnostics only', source=pin(target),
        sourceDiff=pin(diff), preparer=pin(__file__), priorActualMain13Candidate=pin(prior),
        sourceChangesOnlySSHPolicyConstantRegistrationStartedAndPollGuards=False,
        sourceChangesOnlyActualStartErrorDiagnostics=True,
        actualStartErrorDomainCodeUserInfoDebugLogged=True,
        actualUnderlyingErrorDomainCodeUserInfoDebugLogged=True,
        diagnosticsOnlySelectedIndependent27Route=True,
        diagnosticBeforeOriginalSetStatus=True,
        originalStartErrorObjectJudgmentQueueAndCleanupWholeUnchanged=True,
        actualStartErrorFailureMarker='[Independent27] start-vm rejected: actual-start-error',
        actualErrorDetailsObserved=False)
    candidate = out / 'candidate.json'
    candidate.write_text(json.dumps(result, indent=2) + '\n')
    rows = [pin(candidate), pin(target), pin(diff), pin(prior), pin(prior.parent / 'freeze.json'), pin(sourcepath), pin(__file__)]
    (out / 'freeze.json').write_text(json.dumps(dict(files=rows, hostOnly=True, deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(candidate), freeze=pin(out / 'freeze.json'), source=pin(target))))


if __name__ == '__main__':
    main()
