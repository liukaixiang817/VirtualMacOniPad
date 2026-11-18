// Keep genuinely observed BSSs through a partial native scan. Each BSSID has
// its own monotonic age; another scan must never rejuvenate an absent row.
static NSMutableDictionary *BrokerObservedScanRows;
enum { BrokerObservedScanLimit = 256, BrokerObservedScanLifetimeMS = 60000 };
static NSString *brokerObservedScanKey(NSDictionary *row){
 uint8_t address[6]={0};
 if(!brokerAddress(row[@"BSSID"],address))return nil;
 return [NSString stringWithFormat:@"%02x%02x%02x%02x%02x%02x",address[0],address[1],address[2],address[3],address[4],address[5]];
}
static unsigned brokerObservedScanAgeMS(NSDictionary *row,double now){
 NSString *key=brokerObservedScanKey(row);NSDictionary *entry=key?BrokerObservedScanRows[key]:nil;
 double seen=[entry[@"seen"]doubleValue],age=(now-seen)*1000;
 if(!entry||!isfinite(age)||age<0||age>UINT32_MAX)return UINT32_MAX;
 return (unsigned)age;
}
static NSArray *brokerMergeObservedScanRows(NSArray *fresh,double now){
 NSMutableDictionary *next=[NSMutableDictionary dictionary];
 NSMutableArray *rows=[NSMutableArray array];
 for(NSDictionary *row in fresh){
  NSString *key=brokerObservedScanKey(row);if(!key||next[key]||rows.count>=BrokerObservedScanLimit)continue;
  next[key]=@{@"row":row,@"seen":@(now)};[rows addObject:row];
 }
 unsigned retained=0;
 for(NSDictionary *row in BrokerScanRows){
  NSString *key=brokerObservedScanKey(row);if(!key||next[key]||rows.count>=BrokerObservedScanLimit)continue;
  NSDictionary *entry=BrokerObservedScanRows[key];
  if(!entry||brokerObservedScanAgeMS(row,now)>=BrokerObservedScanLifetimeMS)continue;
  next[key]=entry;[rows addObject:entry[@"row"]];retained++;
 }
 BrokerObservedScanRows=next;
 Report[@"nativeScanFreshBSSCount"]=@(fresh.count);
 Report[@"nativeScanRecentBSSRetainedCount"]=@(retained);
 Report[@"nativeScanRecentBSSLifetimeMS"]=@(BrokerObservedScanLifetimeMS);
 return rows;
}
