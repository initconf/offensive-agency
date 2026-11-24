# @TEST-DOC: Tunables set through a Config framework file (not redef) change what is watched and noticed.
#
# Config: min_level=probable (45.33.1.22 becomes watched), include_cdn_ips=T
# (45.33.1.20 becomes watched), ignore_hosts silences 10.1.1.5, port 443 inbound
# is log-only, and the HexStrike User-Agent signature is disabled.
#
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut kind indicator direction local_host remote_host note < offensive_agency.log > hits.txt
# @TEST-EXEC: btest-diff hits.txt
# @TEST-EXEC: zeek-cut note msg < notice.log > notices.txt
# @TEST-EXEC: btest-diff notices.txt
# Probable host is now noticed; ignored host and disabled signature are not.
# @TEST-EXEC: grep -q '45.33.1.22.*Outbound_To_Agent_Host' hits.txt
# @TEST-EXEC: grep -q '45.33.1.20.*Outbound_To_Agent_Host' hits.txt
# @TEST-EXEC: ! grep -q '10.1.1.5	' hits.txt
# @TEST-EXEC: ! grep -q 'hexstrike-ua' hits.txt
# @TEST-EXEC: grep -q '45.33.1.11.*inbound.*-$' hits.txt

@TEST-START-FILE oa.cfg
OffensiveAgency::min_level	probable
OffensiveAgency::include_cdn_ips	T
OffensiveAgency::ignore_hosts	10.1.1.5/32
OffensiveAgency::inbound_ignore_ports	443/tcp
OffensiveAgency::disabled_signatures	hexstrike-ua
@TEST-END-FILE

redef Config::config_files += { "oa.cfg" };
redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";

event zeek_init() &priority=100
	{
	suspend_processing();
	}

# Resume only once the feed has been applied with the config file's values.
event OffensiveAgency::feed_updated(n_ips: count, n_domains: count)
	{
	if ( OffensiveAgency::min_level == "probable" && OffensiveAgency::include_cdn_ips )
		continue_processing();
	}
