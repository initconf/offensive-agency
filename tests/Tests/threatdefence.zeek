# @TEST-DOC: ThreatDefence source (td_file) and the CyberStrikeAI implant check-in pairing: true positives fire once, every precision filter holds.
#
# @TEST-EXEC: zeek -C -r $TRACES/extra.pcap $PACKAGE/__load__.zeek %INPUT
# @TEST-EXEC: zeek-cut kind indicator direction local_host remote_host agents note source < offensive_agency.log > hits.txt
# @TEST-EXEC: btest-diff hits.txt
# @TEST-EXEC: zeek-cut note msg sub < notice.log > notices.txt
# @TEST-EXEC: btest-diff notices.txt
# Filters: low confidence, expired, VPN exit, range, ignored service, signature-covered domain.
# @TEST-EXEC: ! grep -E '91\.92\.1\.(12|13|14|70)|webhook\.site|domain	update\.pentagi' hits.txt
# Pairing: both implant requests are strong, no weak finding for them, the GET stays weak.
# @TEST-EXEC: test "$(grep -c 'cyberstrikeai-implant-checkin.*Agent_Implant_Or_Webshell' hits.txt)" = "2"
# @TEST-EXEC: ! grep -q 'truncated-chrome-ua.*10\.2\.1\.6	' hits.txt
# @TEST-EXEC: grep -q 'truncated-chrome-ua.*10\.2\.1\.11.*Agent_Low_Confidence' hits.txt
# @TEST-EXEC: ! grep -q '10\.2\.1\.12' hits.txt
# Intel source tag:
# @TEST-EXEC: grep -q 'threatdefence' intel.log

redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";
redef OffensiveAgency::td_file = getenv("TEST_FILES") + "/threatdefence.tsv";

global oa_ready = F;
global td_ready = F;

event zeek_init() &priority=100
	{
	suspend_processing();
	}

event OffensiveAgency::feed_updated(n_ips: count, n_domains: count)
	{
	oa_ready = T;
	if ( td_ready )
		continue_processing();
	}

event OffensiveAgency::td_updated(n_ips: count, n_domains: count)
	{
	td_ready = T;
	if ( oa_ready )
		continue_processing();
	}
