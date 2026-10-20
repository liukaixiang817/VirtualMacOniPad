"""Generate genuine batched metadata/SHA checks for the exact frozen products."""
import pathlib
import shlex


def product_path(scope, archive_path, staged):
    if staged:
        return scope['deviceStage'] + '/' + archive_path
    if archive_path == 'runtime' or archive_path.startswith('runtime/'):
        return scope['deviceRuntime'] + archive_path[len('runtime'):]
    prefix = 'VirtualMacIndependent27.app'
    assert archive_path == prefix or archive_path.startswith(prefix + '/')
    return scope['deviceApp'] + archive_path[len(prefix):]


def batch_check(scope, staged=False):
    directories = []
    directory_metadata = []
    files = []
    file_metadata = []
    hashes = []
    for archive_path, mode in sorted(scope['directories'].items()):
        path = product_path(scope, archive_path, staged)
        directories.append(path)
        directory_metadata.append(f'{path}:501:501:{mode:o}:directory')
    for row in scope['files']:
        path = product_path(scope, row['archivePath'], staged)
        assert staged or path == row['devicePath']
        assert pathlib.PurePosixPath(path).is_absolute()
        assert '\n' not in path and ':' not in path and ' ' not in path
        files.append(path)
        size = row['local']['bytes']
        kind = 'regular empty file' if size == 0 else 'regular file'
        file_metadata.append(f'{path}:501:501:{row["mode"]:o}:1:{size}:{kind}')
        hashes.append(row['local']['sha256'] + '  ' + path)
    quoted_directories = ' '.join(shlex.quote(path) for path in directories)
    quoted_files = ' '.join(shlex.quote(path) for path in files)
    lines = ['export LC_ALL=C\n']
    lines.append("own_directory_metadata=$(stat -c '%n:%u:%g:%a:%F' -- " + quoted_directories + ')\n')
    lines.append('[ "$own_directory_metadata" = ' + shlex.quote('\n'.join(directory_metadata)) + ' ]\n')
    lines.append('own_canonical_directories=$(realpath -- ' + quoted_directories + ')\n')
    lines.append('[ "$own_canonical_directories" = ' + shlex.quote('\n'.join(directories)) + ' ]\n')
    lines.append("own_file_metadata=$(stat -c '%n:%u:%g:%a:%h:%s:%F' -- " + quoted_files + ')\n')
    lines.append('[ "$own_file_metadata" = ' + shlex.quote('\n'.join(file_metadata)) + ' ]\n')
    lines.append('sha256sum --check --status - <<\'VM27_EXACT_SHA256_ROWS\'\n'
                 + '\n'.join(hashes) + '\nVM27_EXACT_SHA256_ROWS\n')
    for top in ('runtime', 'VirtualMacIndependent27.app'):
        count = sum(name != top and name.startswith(top + '/') for name in scope['directories'])
        count += sum(row['archivePath'].startswith(top + '/') for row in scope['files'])
        path = product_path(scope, top, staged)
        lines.append('[ "$(find ' + shlex.quote(path)
                     + " -mindepth 1 | wc -l | tr -d ' ')\" = " + str(count) + ' ]\n')
    lines.append("printf 'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT\\n'\n")
    return ''.join(lines)


def cd_check(scope, cd_hashes, staged=False):
    lines = ["verify_cd() {\n own_cd=$(ldid -h \"$1\" 2>&1)\n"
             " printf 'OWN_CD_READ %s\\n' \"$1\"\n"
             " printf '%s\\n' \"$own_cd\"\n"
             " [ \"$(printf '%s\\n' \"$own_cd\" | sed -n 's/^CDHash=//p')\" = \"$2\" ]\n}\n"]
    for cd_hash in cd_hashes:
        rows = [row for row in scope['files'] if row.get('cdhash') == cd_hash]
        assert len(rows) == 1
        path = product_path(scope, rows[0]['archivePath'], staged)
        lines.append('verify_cd ' + shlex.quote(path) + ' ' + cd_hash + '\n')
    return ''.join(lines)
