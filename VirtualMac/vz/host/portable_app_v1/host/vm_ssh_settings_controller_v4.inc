#include <arpa/inet.h>
static NSString *VM27SSHAddressesV4(VM27SSHSettingsV3 value) {
 NSMutableArray *addresses=[NSMutableArray array];
 if(value.scope==VM27SSHLocalV3) {
  if(value.families&VM27SSHIPv4V3)[addresses addObject:[NSString stringWithFormat:@"127.0.0.1:%u",value.port]];
  if(value.families&VM27SSHIPv6V3)[addresses addObject:[NSString stringWithFormat:@"[::1]:%u",value.port]];
 } else {
  struct ifaddrs *rows=NULL;
  if(!getifaddrs(&rows)) {
   for(struct ifaddrs *r=rows;r;r=r->ifa_next) {
    if(!r->ifa_addr||!(r->ifa_flags&IFF_UP)||(r->ifa_flags&IFF_LOOPBACK))continue;
    int af=r->ifa_addr->sa_family;char address[INET6_ADDRSTRLEN]={0};const void *bytes=NULL;
    if(af==AF_INET&&(value.families&VM27SSHIPv4V3))bytes=&((struct sockaddr_in*)r->ifa_addr)->sin_addr;
    else if(af==AF_INET6&&(value.families&VM27SSHIPv6V3))bytes=&((struct sockaddr_in6*)r->ifa_addr)->sin6_addr;
    if(!bytes||!inet_ntop(af,bytes,address,sizeof(address)))continue;
    NSString *row=af==AF_INET?[NSString stringWithFormat:@"%s: %s:%u",r->ifa_name,address,value.port]:
     [NSString stringWithFormat:@"%s: [%s]:%u",r->ifa_name,address,value.port];
    if(![addresses containsObject:row])[addresses addObject:row];
   }
   freeifaddrs(rows);
  }
 }
 return [addresses componentsJoinedByString:@"\n"];
}
@interface VM27SSHSettingsControllerV3 : UITableViewController
@property(nonatomic,retain) NSMutableDictionary *options;
@property(nonatomic,copy) NSString *bundlePath;
@property(nonatomic,assign) BOOL running;
@property(nonatomic,retain) NSTimer *statusTimer;
@property(nonatomic,assign) BOOL applying;
@end
@implementation VM27SSHSettingsControllerV3
- (void)viewDidLoad {
 [super viewDidLoad];self.title=VZL(@"SSH");self.tableView.rowHeight=UITableViewAutomaticDimension;
 self.tableView.estimatedRowHeight=48;
}
- (void)viewWillAppear:(BOOL)animated {
 [super viewWillAppear:animated];
 self.statusTimer=[NSTimer scheduledTimerWithTimeInterval:2 target:self selector:@selector(refreshStatus:) userInfo:nil repeats:YES];
}
- (void)viewWillDisappear:(BOOL)animated {[super viewWillDisappear:animated];[self.statusTimer invalidate];self.statusTimer=nil;}
- (void)refreshStatus:(id)sender {(void)sender;[self.tableView reloadData];}
- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {(void)tableView;(void)section;return 5;}
- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section {
 (void)tableView;(void)section;
 NSString *help=VZL(@"The guest SSH service starts automatically. Apply Now changes forwarding for the running Virtual Mac and disconnects existing SSH sessions. Save the Virtual Mac settings to use them at its next boot. Local uses loopback only. LAN accepts private, link-local and attached-subnet clients. Internet allows other clients, subject to your router, public IP address and firewall; this does not configure port forwarding on your router. Use the guest's existing SSH account.");
 VM27SSHSettingsV3 selected;NSString *addresses=VM27SSHSettingsReadV3(self.options,&selected)?VM27SSHAddressesV4(selected):@"";
 return [NSString stringWithFormat:@"%@\n\n%@\n%@\n\n%@",self.bundlePath?VZVMSSHStatusV3(self.bundlePath):VZL(@"Settings apply at the first Virtual Mac start."),VZL(@"Addresses for the selected settings:"),addresses,help];
}
- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)path {
 UITableViewCell *cell=[[[UITableViewCell alloc]initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:nil]autorelease];
 VM27SSHSettingsV3 value;if(!VM27SSHSettingsReadV3(self.options,&value))value=(VM27SSHSettingsV3){YES,22222,0,1};
 cell.accessoryType=UITableViewCellAccessoryDisclosureIndicator;
 if(path.row==0) {
  cell.textLabel.text=VZL(@"Enable SSH Forwarding");UISwitch *toggle=[[[UISwitch alloc]init]autorelease];toggle.on=value.enabled;
  [toggle addTarget:self action:@selector(enabledChanged:) forControlEvents:UIControlEventValueChanged];cell.accessoryView=toggle;cell.selectionStyle=UITableViewCellSelectionStyleNone;
 } else if(path.row==1) {
  cell.textLabel.text=VZL(@"Access");cell.detailTextLabel.text=@[VZL(@"This iPad Only"),VZL(@"Local Network"),VZL(@"Allow Internet Access")][value.scope];
 } else if(path.row==2) {
  cell.textLabel.text=VZL(@"IP Version");cell.detailTextLabel.text=@[@"IPv4",@"IPv6",@"IPv4 + IPv6"][value.families-1];
 } else if(path.row==3) {
  cell.textLabel.text=VZL(@"iPad Listening Port");cell.detailTextLabel.text=[NSString stringWithFormat:@"%u",value.port];
 } else {
  cell.textLabel.text=VZL(self.applying?@"Applying SSH settings…":@"Apply Now");cell.textLabel.textColor=self.view.tintColor;cell.accessoryType=UITableViewCellAccessoryNone;
  cell.userInteractionEnabled=self.running&&!self.applying;
  if(!cell.userInteractionEnabled)cell.textLabel.textColor=UIColor.secondaryLabelColor;
 }
 return cell;
}
- (void)enabledChanged:(UISwitch *)sender {self.options[VM27_SSH_ENABLED]=@(sender.on);}
- (void)showSSHError:(NSString *)message {
 UIAlertController *alert=[UIAlertController alertControllerWithTitle:VZL(@"SSH") message:message preferredStyle:UIAlertControllerStyleAlert];
 [alert addAction:[UIAlertAction actionWithTitle:VZL(@"OK") style:UIAlertActionStyleCancel handler:nil]];[self presentViewController:alert animated:YES completion:nil];
}
- (void)applyNow {
 if(self.applying||!self.running)return;
 VM27SSHSettingsV3 value;if(!VM27SSHSettingsReadV3(self.options,&value)){[self showSSHError:VZL(@"Enter a port from 1 to 65535.")];return;}
 NSDictionary *settings=VM27SSHSettingsDictionaryV3(value);self.applying=YES;[self.tableView reloadData];
 VZVMApplySSHSettingsV3(self.bundlePath,settings,^(NSError *error) {
  self.applying=NO;
  if(!error) {
   NSMutableDictionary *saved=[NSMutableDictionary dictionaryWithDictionary:VZVMOptionsForBundle(self.bundlePath)];[saved addEntriesFromDictionary:settings];
   if(!VZWriteVMOptions(saved,self.bundlePath,&error))error=[NSError errorWithDomain:@"VirtualMac.SSH" code:EIO userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"%@\n%@",VZL(@"SSH applied, but the settings could not be saved."),error.localizedDescription?:@""]}];
  }
  [self.tableView reloadData];if(error)[self showSSHError:error.localizedDescription];
 });
}
- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)path {
 [tableView deselectRowAtIndexPath:path animated:YES];
 if(path.row==4){[self applyNow];return;}
 if(path.row==1||path.row==2) {
  BOOL access=path.row==1;NSArray *titles=access?@[VZL(@"This iPad Only"),VZL(@"Local Network"),VZL(@"Allow Internet Access")]:@[@"IPv4",@"IPv6",@"IPv4 + IPv6"];
  UIAlertController *sheet=[UIAlertController alertControllerWithTitle:VZL(access?@"Access":@"IP Version") message:nil preferredStyle:UIAlertControllerStyleActionSheet];
  for(NSUInteger i=0;i<titles.count;i++)[sheet addAction:[UIAlertAction actionWithTitle:titles[i] style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){(void)action;self.options[access?VM27_SSH_SCOPE:VM27_SSH_FAMILIES]=@(access?i:i+1);[self.tableView reloadData];}]];
  [sheet addAction:[UIAlertAction actionWithTitle:VZL(@"Cancel") style:UIAlertActionStyleCancel handler:nil]];
  sheet.popoverPresentationController.sourceView=[tableView cellForRowAtIndexPath:path];sheet.popoverPresentationController.sourceRect=[tableView cellForRowAtIndexPath:path].bounds;
  [self presentViewController:sheet animated:YES completion:nil];return;
 }
 if(path.row==3) {
  VM27SSHSettingsV3 current;if(!VM27SSHSettingsReadV3(self.options,&current))return;
  UIAlertController *alert=[UIAlertController alertControllerWithTitle:VZL(@"iPad Listening Port") message:VZL(@"Enter a port from 1 to 65535.") preferredStyle:UIAlertControllerStyleAlert];
  [alert addTextFieldWithConfigurationHandler:^(UITextField *field){field.keyboardType=UIKeyboardTypeNumberPad;field.text=[NSString stringWithFormat:@"%u",current.port];}];
  [alert addAction:[UIAlertAction actionWithTitle:VZL(@"Cancel") style:UIAlertActionStyleCancel handler:nil]];
  [alert addAction:[UIAlertAction actionWithTitle:VZL(@"OK") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action){
   (void)action;NSString *text=alert.textFields.firstObject.text;
   if(!text.length||text.length>5||[text rangeOfCharacterFromSet:NSCharacterSet.decimalDigitCharacterSet.invertedSet].location!=NSNotFound||text.integerValue<1||text.integerValue>65535){[self showSSHError:VZL(@"Enter a port from 1 to 65535.")];return;}
   self.options[VM27_SSH_PORT]=@(text.integerValue);[self.tableView reloadData];
  }]];[self presentViewController:alert animated:YES completion:nil];
 }
}
- (void)dealloc {[self.statusTimer invalidate];[_statusTimer release];[_bundlePath release];[_options release];[super dealloc];}
@end
