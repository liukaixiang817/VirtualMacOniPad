#!/usr/bin/env python3
"""Read the genuine modern VMM restore body, never execute its code.

The graph describes successful-return paths of this one function. It does not
establish that an opaque callee returns, or that a feature branch is feasible.
"""
from pathlib import Path
import collections, hashlib, json, re, runpy, struct, sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'modern27-cpu-restore-readonly-v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def edges(word, at):
    if word & 0xfc000000 == 0x14000000:
        return [at + 4 * signed(word & 0x3ffffff, 26)]
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
        return [at + 4, at + 4 * signed((word >> 5) & 0x7ffff, 19)]
    if word & 0x7e000000 == 0x36000000:
        return [at + 4, at + 4 * signed((word >> 5) & 0x3fff, 14)]
    if word in (0xd65f0fff, 0xd65f03c0) or word & 0xffe0001f == 0xd4200000:
        return []
    require(word & 0xfffffc1f not in (0xd61f0000, 0xd65f0000), 'unclosed indirect branch')
    return [at + 4]


def closure(first, graph):
    seen, todo = set(), [first]
    while todo:
        node = todo.pop()
        if node not in seen:
            seen.add(node)
            todo.extend(graph.get(node, []))
    return seen


def main():
    parser_path = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    parser_pin = pin(parser_path)
    old_contract = N / 'vmm-public-adapter-gap-design-v1/contract.json'
    parser = runpy.run_path(str(parser_path))
    image = parser['MachO'](parser['VM'].read_bytes())
    require(pin(parser['VM'])['sha256'] == 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422', 'genuine modern image')
    require(image.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'genuine modern UUID')
    begin, end = image.bounds(0x28a508)
    require((begin, end) == (0x28a508, 0x28cc24), 'complete LC26 extent')
    raw = image.raw(begin, end - begin)
    require(hashlib.sha256(raw).hexdigest() == '2bdd7f1d1ab04cd8eedfb0edc42da89b9ed6673e10580f71998410e686515d31', 'whole restore bytes')
    require((D / 'original-function.bin').read_bytes() == raw, 'saved whole body')
    rows = []
    for line in (D / 'original-function.asm').read_text().splitlines():
        match = re.match(r'^([0-9a-f]+): ([0-9a-f]{8})\s+(.+)$', line)
        if match:
            rows.append(dict(rva=int(match[1], 16) - image.base, word=int(match[2], 16), instruction=match[3]))
    require(len(rows) == len(raw) // 4, 'complete disassembly')
    require(b''.join(struct.pack('<I', row['word']) for row in rows) == raw, 'machine word disassembly join')
    stubs = {}
    section = next(section for section in image.sections if section['name'] == '__auth_stubs')
    for delta in range(0, section['bytes'], 16):
        at = section['va'] - image.base + delta
        slot, binding = parser['authenticated_stub'](image, image.raw(at, 16), at)
        stubs[at] = dict(stubRVA=at, slotRVA=slot, binding=binding)
    graph = {row['rva']: edges(row['word'], row['rva']) for row in rows}
    graph = {node: [target for target in targets if begin <= target < end] for node, targets in graph.items()}
    reverse = collections.defaultdict(list)
    for node, targets in graph.items():
        for target in targets:
            reverse[target].append(node)
    success = 0x28cb88
    require(image.raw(success, 4) == bytes.fromhex('ff0f5fd6'), 'sole ordinary success return')
    live = closure(begin, graph) & closure(success, reverse)
    require(success in live, 'ordinary return reachable')
    ordered = sorted(live)
    bits = {node: 1 << index for index, node in enumerate(ordered)}
    universe = (1 << len(ordered)) - 1
    dominators = {node: bits[node] if node == begin else universe for node in ordered}
    changed, iterations = True, 0
    while changed:
        changed = False
        iterations += 1
        require(iterations <= len(ordered), 'bounded graph convergence')
        for node in ordered:
            if node == begin:
                continue
            parents = [parent for parent in reverse[node] if parent in live]
            require(parents, 'successful subgraph predecessor')
            value = universe
            for parent in parents:
                value &= dominators[parent]
            value |= bits[node]
            if value != dominators[node]:
                dominators[node] = value
                changed = True
    calls = []
    for index, row in enumerate(rows):
        word, at = row['word'], row['rva']
        if word & 0xfc000000 != 0x94000000:
            continue
        target = at + 4 * signed(word & 0x3ffffff, 26)
        stub = stubs.get(target)
        call = dict(rva=at, word=word, targetRVA=target, reachableOnSuccessfulPath=at in live,
            structurallyRequiredOnEveryOrdinarySuccessPath=bool(at in live and dominators[success] & bits[at]),
            argumentsAreNotInitializationDefaults=True)
        if stub:
            call.update(stub)
            record = stub['binding']['importRecord']
            call['symbol'] = record['name']
            if record['library'] == '/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor':
                require(record['ordinal'] > 0 and not record['weak'] and record['addend'] == 0, 'actual positive strong Hypervisor import')
        else:
            call['symbol'] = None
        recent = rows[max(0, index - 6):index]
        argument = [item for item in recent if re.match(r'mov\s+w1, #0x[0-9a-f]+\s', item['instruction'])]
        if argument:
            item = argument[-1]
            call['literalArgument1'] = int(re.match(r'mov\s+w1, #0x([0-9a-f]+)', item['instruction'])[1], 16)
            call['argument1WordRVA'] = item['rva']
        frame_loads = [item for item in recent if re.match(r'ldr\s+(?:x2|q0), \[x19(?:, #0x[0-9a-f]+)?\]', item['instruction'])]
        if frame_loads:
            item = frame_loads[-1]
            match = re.match(r'ldr\s+(x2|q0), \[x19(?:, #0x([0-9a-f]+))?\]', item['instruction'])
            call['frameValue'] = dict(offset=int(match[2], 16) if match[2] else 0, bytes=16 if match[1] == 'q0' else 8,
                loadRVA=item['rva'], machineWord=item['word'])
        if at == 0x28a548:
            require(image.raw(0x28a540, 4) == struct.pack('<I', 0xf9400422), 'PC incoming frame+8')
            call['frameValue'] = dict(offset=8, bytes=8, loadRVA=0x28a540, machineWord=0xf9400422, base='incoming x1 retained in x19')
        if at == 0x28b2c4:
            require(image.raw(0x28b29c, 4) == struct.pack('<I', 0xf9431a62), '8012 frame+630 actual branch')
            call['frameValue'] = dict(offset=0x630, bytes=8, loadRVA=0x28b29c, machineWord=0xf9431a62,
                scope='the direct public SYS branch; the other branch uses original local helper28ce38')
        if at == 0x28ac48:
            require(image.raw(0x28ac3c, 4) == struct.pack('<I', 0xf94017e2), 'e08a original getter stack roundtrip')
            call['valueSource'] = dict(loadRVA=0x28ac3c, machineWord=0xf94017e2, stackOffset=0x28,
                source='same SYS id e08a getter at28ac34; stack output pointer prepared28ac2c; conditional feature byte78bit0')
        calls.append(call)
    scalar = [call for call in calls if call['symbol'] == '_hv_vcpu_set_reg']
    simd = [call for call in calls if call['symbol'] == '_hv_vcpu_set_simd_fp_reg']
    system = [call for call in calls if call['symbol'] == '_hv_vcpu_set_sys_reg']
    require(len(scalar) == 35 and len(simd) == 32, 'actual full scalar/SIMD enumeration')
    require(sorted(call['literalArgument1'] for call in scalar) == list(range(35)), 'all scalar IDs')
    require(sorted(call['literalArgument1'] for call in simd) == list(range(32)), 'all SIMD IDs')
    require(all(call.get('frameValue') or call.get('valueSource') for call in scalar + simd + system), 'all actual setter value sources accounted')
    fields_path = R / 'VirtualMac/vz/host/modern_cpu_kernel_system_fields.inc'
    supported = {int(match[1], 16) for match in re.finditer(r'\{0x([0-9a-f]+),', fields_path.read_text())}
    supported.update((0xc020, 0xc021, 0xc028, 0xc029, 0xc030, 0xc031, 0xc038, 0xc039, 0xc03a, 0xc000, 0xc005))
    for call in system:
        call['ownOldKernelLogicalRouteExists'] = call['literalArgument1'] in supported
    unknown = [call for call in system if not call['ownOldKernelLogicalRouteExists']]
    mandatory_unknown = [call for call in unknown if call['structurallyRequiredOnEveryOrdinarySuccessPath']]
    counts = dict(collections.Counter(call['symbol'] or 'local-function' for call in calls))
    branch_rows = [row for row in rows if len(edges(row['word'], row['rva'])) == 2 and not
        (row['instruction'].startswith('cbnz\tw0,') and edges(row['word'], row['rva'])[1] >= 0x28cb8c)]
    report = dict(schema='Actual original27 complete CPU restore caller contract v1',
        originalImage=pin(parser['VM']), originalUUID=image.uuid, parser=parser_pin,
        priorABIContract=pin(old_contract), functionStart=begin, functionEnd=end, functionBytes=len(raw),
        wholeMachineBytes=pin(D / 'original-function.bin'), wholeDisassembly=pin(D / 'original-function.asm'),
        ownLogicalFields=pin(fields_path), staticCalls=calls, importCallCounts=counts,
        graphDescription='Instruction control-flow restricted to paths reaching the actual ordinary retab; opaque callees are assumed returning for this structural analysis only.',
        successfulGraphInstructions=len(live), convergenceIterations=iterations,
        featureOrOtherConditionalBranches=branch_rows, actualScalarCalls=len(scalar), actualSIMDCalls=len(simd), actualSYSCalls=len(system),
        unknownSYSRoutes=unknown, structurallyMandatoryUnknownSYSRoutes=mandatory_unknown,
        actualCPUObjectIDSource='original296B CPU object+0xd8; incoming x0; x26 advanced by0xd8',
        frameSource='incoming x1 retained in x19; actual frame values except the conditional e08a getter roundtrip; never observed production defaults',
        actualConfigFeatureSource='CPU object+0x20 retained in x28; byte/bit tests preserved in the whole body',
        nativeCalls=0, deviceOperations=0, AppleCodeExecuted=False, guestInstructions=0,
        productionChanged=False, resetExecuted=False, full27Backend=False,
        nextWork='Route actual original VMM callers to one own public ABI registry; close or source-port specifically unsupported conditional host features using genuine feature inputs. Do not replay prior filtered run probes.')
    report['auditSource'] = pin(Path(__file__))
    destination = D / 'contract.json'
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    freezes = [pin(path) for path in sorted(D.iterdir()) if path.is_file() and path.name != 'freeze.json']
    with (D / 'freeze.json').open('x') as stream:
        json.dump(dict(files=freezes), stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(contract=pin(destination), freeze=pin(D / 'freeze.json'), calls=counts,
        unknownSYS=len(unknown), mandatoryUnknownSYS=len(mandatory_unknown), deviceOperations=0)))


if __name__ == '__main__':
    main()
