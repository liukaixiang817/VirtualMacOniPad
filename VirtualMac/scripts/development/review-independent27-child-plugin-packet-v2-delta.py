#!/usr/bin/env python3
"""Join frozen product/controller peers with the exact metadata-only packet V2."""
import hashlib
import json
import pathlib
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path=pathlib.Path(path).resolve();raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def main():
    out=N/'independent27-child-plugin-composition-peer-v2-attempt1'
    assert not out.exists()
    pins,checks={},[]
    def exact(row):
        core={k:row[k] for k in ('path','bytes','sha256')}
        assert pin(row['path']) == core,row['path'];pins[row['path']]=core
        return pathlib.Path(row['path'])
    def check(value,label):
        assert value,label;checks.append(label)
    def load(name):
        path=N/name/'candidate.json';exact(pin(path));exact(pin(path.parent/'freeze.json'))
        return path,json.loads(path.read_bytes())
    old_path,old=load('independent27-child-plugin-device-v1-attempt1')
    path,new=load('independent27-child-plugin-device-v2-attempt1')
    check(pin(path)['sha256'] == 'c49429f7e9823a41a0bd5fe8ec363c3ce26b840e43822dd453b2dc5142ec5835','exact finite corrected packet V2')
    product_path=exact(pin(N/'independent27-child-plugin-composition-peer-v1-attempt1/product-review.json'))
    product=json.loads(product_path.read_bytes())
    check(pin(product_path)['sha256'] == '2cbf2f0af2f5bf8849ede61c1e5c496c446862b6aab37d7c9b2aa1c61f26f4eb' and product['finiteProductCompositionScopePassed'] and product['findings'] == [],'frozen four real signature/source/graph composition peer retained')
    exact(pin(product_path.parent/'freeze.json'))
    controller_path=exact(pin(N/'independent27-child-plugin-controller-peer-v1-attempt1/review.json'))
    controller=json.loads(controller_path.read_bytes())
    check(pin(controller_path)['sha256'] == '6b3f8448638352e6bb519011ba144ff6d243a557c010afb59ee92f35bad776ea' and len(controller['findings']) == 2,'frozen97 controller operations peer retains original two metadata findings')
    exact(pin(controller_path.parent/'freeze.json'))
    before=json.loads(exact(old['scope']).read_bytes());after=json.loads(exact(new['scope']).read_bytes())
    check(new['runtimeCandidate'] == old['runtimeCandidate'] == product['runtimeCandidate'] and new['appCandidate'] == old['appCandidate'] == product['appCandidate'],'no product/source/signature change in packet V2')
    check(exact(new['controller']).read_bytes() == exact(old['controller']).read_bytes(),'whole controller bytes unchanged, including ready/once/transport/process gates')
    check(exact(new['archive']).read_bytes() == exact(old['archive']).read_bytes() and new['archive']['bytes'] == 10403840,'whole exact seven-file canonical archive unchanged')
    check(new['scripts'].keys() == old['scripts'].keys() and len(new['scripts']) == 8,'same eight bounded actions')
    for action,row in new['scripts'].items():
        check(exact(row).read_bytes() == exact(old['scripts'][action]).read_bytes(),'whole guarded remote script unchanged '+action)
    check(after['trustCacheFixedBatchCounts'] == [4] and after['archive'] == new['archive'],'both identified metadata findings resolved by exact delta batch/archive fields')
    history=after['historicalOriginalBootstrapOnly']
    for key in ('archive','trustCacheFixedBatchCounts','appMoveMayCopyAcrossDataAndPrebootVolumes','appDirectoryInodePreservationRequired'):
        check(history[key] == before[key],'prior bootstrap metadata explicitly historical '+key)
    check(after['actualFullCodeInventoryForVerificationOnly'] is True and after['deltaReplacementsUseExactSameDirectoryTemporaryFiles'] is True,'full140 inventory distinguished from new4 registration; seven replacements remain same-parent')
    check(new['currentInstalledProductsReadonly'] == after['currentInstalledProductsReadonly'] == old['priorActualPost'],'current prerequisite accurately named real read-only receipt')
    current=json.loads(exact(after['currentInstalledProductsReadonly']).read_bytes())
    check(current['transportExit'] == 0,'actual latest full-product read-only receipt succeeded')
    historical=json.loads(exact(after['oldActualPost']).read_bytes())
    check(historical['transportExit'] == 0 and after['oldActualPost'] != after['currentInstalledProductsReadonly'],'inherited oldActualPost is an actual ancestral successful post; not forged latest post77')
    allowed={'schema','archive','trustCacheFixedBatchCounts','appMoveMayCopyAcrossDataAndPrebootVolumes','appDirectoryInodePreservationRequired','historicalOriginalBootstrapOnly','actualFullCodeInventoryForVerificationOnly','deltaReplacementsUseExactSameDirectoryTemporaryFiles','currentInstalledProductsReadonly','oldActualPost'}
    differences=sorted(k for k in before.keys()|after.keys() if before.get(k) != after.get(k))
    check(set(differences) <= allowed,'scope changes limited to explicitly named metadata corrections')
    for key in ('files','deltaFiles','newTrustCacheCDHashes','trustCacheCDHashes','deviceStage','deviceLog','actualFullCodeDirectoryHashes','trustCacheRegistrationCount','oldScope'):
        check(after[key] == before[key],'real permissions/files/destinations unchanged '+key)
    check(new['actualNewTrustEntries'] == 4 and new['actualChangedFiles'] == 7 and new['actualUnchangedFiles'] == 245 and new['actualUnchangedSignedImages'] == 136,'actual4/7/245/136 unchanged')
    check(new['maximumQuotedCommandBytes'] == old['maximumQuotedCommandBytes'] == 214676 and new['maximumQuotedCommandBytes']+10000 < 262144,'actual unchanged quoted command ARG_MAX margin')
    check(new['deviceOperations'] == new['trustCacheOperations'] == 0 and not new['readyForDeviceExecution'],'host packet still requires fresh exact human4 authorization and frozen ready')
    exact(new['preparer'])
    report=dict(schema='Finite corrected child plugin packet V2 and actual Runtime5/App5 independent composition peer',controllerPacketCandidate=pin(path),scope=new['scope'],finiteLocalScopePassed=True,findings=[],productCompositionReview=pin(product_path),controllerOperationsReview=pin(controller_path),supersededControllerPacket=pin(old_path),resolvedPriorMetadataFindings=controller['findings'],scopeMetadataDifferenceKeys=differences,checks=checks,actualNewCodeDirectories=after['newTrustCacheCDHashes'],actualNewSignatures=product['actualNewSignatures'],actualChangedFiles=7,actualUnchangedFiles=245,actualUnchangedSignedImages=136,deviceOperations=0,trustCacheOperations=0,actualGuestBoot=False,boundaries=['Only exact plugin=true child signature changes privileges; all native entitlement validation/audit/kernel CodeDirectory/CS_VALID/file identity gates remain unchanged.','The actual previous post77 stays preserved. The new prerequisite is a successful read-only product receipt with an App potentially present; guarded fresh close independently establishes own processes off.','The inherited scope oldActualPost refers to an ancestral real successful post and is unused by current controller identity/authorization gates; it is not claimed as the latest post.','Unchanged legacy ONE success labels are historical output text; actual seven-file/four-TC commands and scope are exact.','V1 metadata findings remain in the frozen original peer; this new packet resolves them explicitly.','This finite host composition performs no device actions or added trust entries; successful initialization and guest execution remain actual device requirements.'])
    out.mkdir(mode=0o700);(out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    exact(pin(out/'review.json'));exact(pin(__file__))
    (out/'freeze.json').write_text(json.dumps(dict(files=list(pins.values()),deviceOperations=0,trustCacheOperations=0,findings=[]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),checks=len(checks))))


if __name__ == '__main__':main()
