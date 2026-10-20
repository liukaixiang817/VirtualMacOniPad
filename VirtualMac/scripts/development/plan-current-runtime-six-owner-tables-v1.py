"""Current command tails and export tables; no archived export bytes."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
N=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUTPUT=N/'ipad-current-runtime-six-owner-tables-plan-v1'
def pin(path):
    path=Path(path).resolve();b=path.read_bytes()
    return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def need(value,why):
    if not value:raise ValueError(why)
def main():
    plan=N/'ipad-current-runtime-six-owner-prefixes-plan-v1'
    read=N/'ipad-current-runtime-six-owner-prefixes-readonly-v1'
    headers=N/'ipad-current-vz-stock-member-headers-readonly-v1/headers.json'
    need(pin(headers)['sha256']=='b78e135585642c92910f37c2cbf1e3575d7fa069532e6155f270857287e315f1','actual headers')
    actual=json.loads((read/'receipt.json').read_text());head=json.loads(headers.read_text())
    need(actual['transportExit']==0 and actual['allHeaderPinsMatchBeforeAndAfter'] is True and actual['deviceWrites']==0,'actual readonly receipt')
    derivation=json.loads((plan/'derivation.json').read_text());ranges=[];proofs=[]
    captures={r['name']:r for r in actual['ranges']}
    inputs=[Path(__file__),headers,read/'receipt.json',plan/'request.json',plan/'derivation.json']
    for proof in derivation['proofs']:
        name=proof['name'];capture=captures[name+'-command-prefix'];path=Path(capture['path']);data=path.read_bytes()
        need(pin(path)['sha256']==capture['sha256'] and len(data)==4096,'actual captured prefix');inputs.append(path)
        need(struct.unpack_from('<I',data)[0]==0xfeedfacf,'actual thin64 cached MachO')
        ncmds,cmdbytes=struct.unpack_from('<II',data,16);need(0<ncmds<100 and 0<cmdbytes<65536,'command bounds')
        end=32+cmdbytes;at=32;linkedit=None;exports=None;uuid=None;count=0
        while count<ncmds and at+8<=len(data):
            cmd,size=struct.unpack_from('<II',data,at);need(size>=8 and size%8==0 and at+size<=end,'bounded command')
            if at+size>len(data):break
            if cmd==27:uuid=data[at+8:at+24].hex()
            if cmd==0x19 and data[at+8:at+24].rstrip(b'\0')==b'__LINKEDIT':
                vmaddr,vmsize,fileoff,filesize=struct.unpack_from('<QQQQ',data,at+24)
                linkedit={'vmaddr':vmaddr,'vmsize':vmsize,'fileoff':fileoff,'filesize':filesize,'commandOffset':at}
            if cmd in (0x80000033,0x80000022):
                off,length=struct.unpack_from('<II',data,at+(8 if cmd==0x80000033 else 40))
                exports={'fileOffset':off,'bytes':length,'commandOffset':at,'command':cmd}
            at+=size;count+=1
        need(uuid==proof['actualInventoryRow']['UUID'] or (uuid is None and end>len(data)), 'captured owner UUID or pending command tail')
        if end>len(data):
            ranges.append({'name':name+'-command-tail','cache':capture['cache'],
                'offset':capture['offset']+len(data),'length':end-len(data)})
        else:need(at==end and count==ncmds,'complete actual commands')
        row={'name':name,'actualUUID':uuid,'expectedInventoryUUID':proof['actualInventoryRow']['UUID'],
            'uuidVerifiedFromCommands':uuid is not None,'actualPrefix':pin(path),'commandCount':ncmds,
            'commandBytes':cmdbytes,'commandsComplete':end<=len(data),'linkedit':linkedit,'exports':exports}
        if exports:
            need(linkedit and exports['bytes']>0 and exports['fileOffset']>=linkedit['fileoff'] and
                exports['fileOffset']+exports['bytes']<=linkedit['fileoff']+linkedit['filesize'],'actual linkedit export bounds')
            address=linkedit['vmaddr']+exports['fileOffset']-linkedit['fileoff'];hits=[]
            for header in head['headers']:
                for mapping in header['maps']:
                    if mapping['address']<=address and address+exports['bytes']<=mapping['address']+mapping['size']:
                        hits.append((header,mapping))
            need(len(hits)==1,'current export mapping');header,mapping=hits[0]
            request={'name':name+'-exports','cache':header['name'],
                'offset':mapping['fileOffset']+address-mapping['address'],'length':exports['bytes']}
            ranges.append(request);row['actualExportMapping']=mapping;row['actualExportHeaderSHA256']=header['sha256'];row['request']=request
        proofs.append(row)
    need(len(ranges)==7 and sum(r['length'] for r in ranges)==37760,'finite actual request shape')
    OUTPUT.mkdir(exist_ok=False)
    (OUTPUT/'request.json').write_text(json.dumps({'ranges':ranges},indent=2)+'\n')
    (OUTPUT/'derivation.json').write_text(json.dumps({'schema':'Current six owner command and export derivation v1',
        'proofs':proofs,'deviceWrites':0,'frameworkLoads':0,'nativeCPUCalls':0,'full27Backend':False},indent=2)+'\n')
    inputs += [OUTPUT/'request.json',OUTPUT/'derivation.json',ROOT/'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v10.py']
    (OUTPUT/'freeze.json').write_text(json.dumps({'files':[pin(p) for p in inputs]},indent=2)+'\n')
    print(json.dumps({'request':pin(OUTPUT/'request.json'),'ranges':len(ranges),'bytes':sum(r['length'] for r in ranges)}))
if __name__=='__main__':main()
