"""Derive six readonly runtime owner prefixes from the actual current inventory."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUTPUT=N/'ipad-current-runtime-six-owner-prefixes-plan-v1'
def pin(path):
    path=Path(path).resolve();data=path.read_bytes()
    return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def require(value,message):
    if not value:raise ValueError(message)
def main():
    inventory=N/'ipad-current-cache-hid-extra-inventory-v1/current-images.json'
    headers=N/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    require(pin(inventory)['sha256']=='9e7319c0c1f6feddb0e956c1ca0d2b3b5753155a3624b41f02f774ccdf487f8d','current inventory')
    require(pin(headers)['sha256']=='b78e135585642c92910f37c2cbf1e3575d7fa069532e6155f270857287e315f1','current17 headers')
    images=json.loads(inventory.read_text());head=json.loads(headers.read_text())
    require(head['deviceWrites']==0 and head['matchesArchivedMap'] is True,'actual current headers')
    rows=[];proofs=[]
    targets=[('cryptokit','/System/Library/Frameworks/CryptoKit.framework/CryptoKit'),
        ('apfs','/System/Library/PrivateFrameworks/APFS.framework/APFS'),
        ('bz2','/usr/lib/libbz2.1.0.dylib'),
        ('coreanalytics','/System/Library/PrivateFrameworks/CoreAnalytics.framework/CoreAnalytics'),
        ('compression','/usr/lib/libcompression.dylib'),
        ('cfnetwork','/System/Library/Frameworks/CFNetwork.framework/CFNetwork')]
    for name,path in targets:
        matching=[r for r in images if r['path']==path];require(len(matching)==1,'literal owner inventory '+name)
        image=matching[0];address=image['address'];hits=[]
        for header in head['headers']:
            for mapping in header['maps']:
                if mapping['address']<=address and address+4096<=mapping['address']+mapping['size']:
                    hits.append((header,mapping))
        require(len(hits)==1,'complete prefix map '+name);header,mapping=hits[0]
        offset=mapping['fileOffset']+address-mapping['address']
        require(offset>=4096,'prefix offset lower bound')
        rows.append({'name':name+'-command-prefix','cache':header['name'],'offset':offset,'length':4096})
        proofs.append({'name':name,'actualInventoryRow':image,'actualHeaderName':header['name'],
            'actualHeaderSHA256':header['sha256'],'actualMapping':mapping,'derivedFileOffset':offset})
    OUTPUT.mkdir(exist_ok=False)
    (OUTPUT/'request.json').write_text(json.dumps({'ranges':rows},indent=2)+'\n')
    (OUTPUT/'derivation.json').write_text(json.dumps({'schema':'Six current runtime owner readonly prefixes v1',
        'proofs':proofs,'totalBytes':sum(r['length'] for r in rows),'deviceWrites':0,
        'nativeCPUCalls':0,'frameworkLoads':0,'full27Backend':False},indent=2)+'\n')
    files=[Path(__file__),inventory,headers,
        ROOT/'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v10.py',
        ROOT/'DeviceDiagnostics/2026-10-02-ssh-steam-repair/remote.py',OUTPUT/'request.json',OUTPUT/'derivation.json']
    (OUTPUT/'freeze.json').write_text(json.dumps({'schema':'Finite current prefix plan pins v1',
        'files':[pin(p) for p in files]},indent=2)+'\n')
    print(json.dumps({'request':pin(OUTPUT/'request.json'),'bytes':24576,'owners':6}))
if __name__=='__main__':main()
