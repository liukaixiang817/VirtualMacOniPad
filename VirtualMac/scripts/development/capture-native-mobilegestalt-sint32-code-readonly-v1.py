import getpass,os,pathlib,runpy,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';reader=R/'VirtualMac/scripts/development/read-ipad-current-cache-ranges-readonly-v11.py'
os.environ['VIRTUALMAC_SSH_PASSWORD']=getpass.getpass('iPad password: ')
try:
 os.environ.update(SSH_ASKPASS='/private/tmp/virtualmac-ipad-tools/ssh-askpass',SSH_ASKPASS_REQUIRE='force',DISPLAY='virtualmac-debug')
 sys.argv=[str(reader),'--manifest',str(N/'ipad-native-mobilegestalt-sint32-code-readonly-plan-v1-attempt1/manifest.json'),'--headers',str(N/'ipad-current-mediakit-member31-header-readonly-v1/headers.json'),'--output',str(N/'ipad-native-mobilegestalt-sint32-code-readonly-v1-attempt1')]
 runpy.run_path(reader,run_name='__main__')
finally:os.environ.pop('VIRTUALMAC_SSH_PASSWORD',None)
