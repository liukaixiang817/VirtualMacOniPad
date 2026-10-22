#!/usr/bin/env python3
"""Exercise actual V6/V7 FD guards against a growing owned log on macOS.

Only the fixture path and host uid/gid are adapted; production remains 501:501.
No iPad process, system file, native VM or external service is involved.
"""
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCES = ROOT / 'VirtualMac/vz/host'


def actual_guard(version, log_path):
    source = (SOURCES / f'modern_xpc_large_private_consumer_v{version}.c').read_text()
    start = source.index(f'static int OwnedLogDescriptorsV{version}')
    end = source.index('\nint VM27LargePrivateServiceConsumerV2Spawn', start)
    return (source[start:end]
        .replace(f'OwnedLogDescriptorsV{version}', f'check{version}')
        .replace('"/tmp/VirtualMacIndependent27.log"', json.dumps(str(log_path)))
        .replace('pathStat.st_uid!=501', 'pathStat.st_uid!=geteuid()')
        .replace('st.st_uid!=501', 'st.st_uid!=geteuid()')
        .replace('pathStat.st_gid!=501', 'pathStat.st_gid!=getegid()')
        .replace('st.st_gid!=501', 'st.st_gid!=getegid()'))


def main():
    with tempfile.TemporaryDirectory(prefix='vm27-log-growth-test-', dir='/private/tmp') as folder:
        folder = pathlib.Path(folder)
        log_path = folder / 'owned.log'
        code = '''#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#define CHECK(x) do {if(!(x)){dprintf(report,"FAIL line=%d\\n",__LINE__);return 1;}}while(0)
'''
        code += actual_guard(6, log_path) + actual_guard(7, log_path)
        code += f'''
int main(void) {{
    int report=dup(2),out=dup(1);CHECK(report>=0&&out>=0);
    const char *path={json.dumps(str(log_path))};
    const char *alias={json.dumps(str(folder / 'alias.log'))};
    int fd=open(path,O_CREAT|O_EXCL|O_RDWR|O_APPEND,0600);CHECK(fd>=0);
    CHECK(!fchown(fd,(uid_t)-1,getegid()));
    CHECK(!ftruncate(fd,2097153));CHECK(dup2(fd,1)==1&&dup2(fd,2)==2);
    CHECK(check6(false)==EACCES);CHECK(check7(false)==0);
    CHECK(!fchmod(fd,0644));CHECK(check7(false)==EACCES);CHECK(!fchmod(fd,0600));
    int plain=open(path,O_WRONLY);CHECK(plain>=0&&dup2(plain,2)==2);
    CHECK(check7(false)==EACCES);CHECK(dup2(fd,2)==2);close(plain);
    CHECK(!link(path,alias));CHECK(check7(false)==EACCES);CHECK(!unlink(alias));
    CHECK(!ftruncate(fd,16777216));CHECK(check7(false)==0);
    CHECK(dup2(out,1)==1&&dup2(report,2)==2);close(fd);close(out);close(report);
    puts("PASS: log growth no longer rejects spawn; mode, append and hardlink guards remain");
    return 0;
}}
'''
        test_source = folder / 'test.c'
        test_source.write_text(code)
        executable = folder / 'test'
        subprocess.run(['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(test_source), '-o', str(executable)], check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == '__main__':
    main()
