"""Definition-only resolution inside an explicitly declared flat private bundle.

No executable path, inherited rpath stack, arbitrary basename alias or missing
provider is guessed. Only an actual single LC_RPATH @loader_path is expanded.
"""
import posixpath


def resolved_path(primary, images, path, requester):
    key = primary.canonical_path(path)
    proof = None
    if path.startswith('@rpath/'):
        # This explicit subset has a declared flat placement. The requesting
        # provider's real LC_RPATH must itself be complete for this finite rule.
        suffix = path[len('@rpath/'):]
        if not requester or requester.get('rpaths') != ['@loader_path'] or '/' in suffix or suffix in ('', '.', '..'):
            return key, dict(status='uncapturedOwner', requestedPath=path,
                             rpathContextUnproved=True)
        owner = requester['path']
        if not requester.get('declaredFlatPrivateBundle') or not owner.startswith('@loader_path/'):
            return key, dict(status='uncapturedOwner', requestedPath=path,
                             requestingImagePlacementUnproved=True)
        expanded = posixpath.dirname(owner) + '/' + suffix
        key = primary.canonical_path(expanded)
        if key not in images or not images[key].get('declaredFlatPrivateBundle'):
            return key, dict(status='uncapturedOwner', requestedPath=path,
                             expandedFromActualRPath=expanded)
        proof = dict(requestedPath=path, requestingImage=owner,
                     requestingImagePin=requester['image'], actualLCRPaths=requester['rpaths'],
                     declaredPlacement=expanded, definitionEvidenceOnly=True,
                     nativeNamespaceBindingProven=False)
    return key, proof


def resolve(primary, images, path, symbol, requester=None, seen=()):
    key, pathproof = resolved_path(primary, images, path, requester)
    if pathproof and pathproof.get('status') == 'uncapturedOwner':
        return dict(pathproof, symbol=symbol)
    if (key, symbol) in seen or len(seen) > 12:
        raise AssertionError('reexport cycle')
    if key not in images:
        return dict(status='uncapturedOwner', requestedPath=path, symbol=symbol)
    image = images[key]
    entry = image['exports'].get(symbol)
    seen += ((key, symbol),)
    if entry and not entry['flags'] & 8:
        result = dict(status='actualDirectExport', owner=image['path'], UUID=image['UUID'], export=entry)
    elif entry:
        assert 1 <= entry['ordinal'] <= len(image['dependencies'])
        dep = image['dependencies'][entry['ordinal'] - 1]
        nested = resolve(primary, images, dep['path'], entry['importedName'] or symbol, image, seen)
        result = dict(status=nested['status'], namedReexport=entry, reexportDependency=dep, nested=nested)
    else:
        unknown = []
        result = None
        for dep in image['dependencies']:
            if dep['command'] != 0x8000001f:
                continue
            nested = resolve(primary, images, dep['path'], symbol, image, seen)
            if nested['status'] == 'actualDirectExport':
                result = dict(status='actualDirectExport', reexportDependency=dep, nested=nested)
                break
            if nested['status'] in ('uncapturedOwner', 'ownerHasNoDefinitionReexportsUnverified'):
                unknown.append(dep['path'])
        if result is None:
            result = dict(status='ownerHasNoDefinitionReexportsUnverified' if unknown else 'actualExportAbsent',
                          owner=image['path'], UUID=image['UUID'], symbol=symbol, unverifiedReexportPaths=unknown)
    if pathproof:
        result['actualFiniteRPathResolution'] = pathproof
    return result
