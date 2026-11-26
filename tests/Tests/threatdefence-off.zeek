# @TEST-DOC: Clearing td_file at runtime (Config framework) withdraws every ThreatDefence indicator from the Intel store.
#
# @TEST-EXEC: btest-bg-run zeek "zeek $PACKAGE/__load__.zeek ../test.zeek"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: btest-diff zeek/.stdout

@TEST-START-FILE test.zeek
redef exit_only_after_terminate = T;

module Intel;
export { global oa_count: function(src: string): count; }
# How many addresses/domains of a source are in the Intel store.
function oa_count(src: string): count
	{
	local n = 0;
	for ( a, m in data_store$host_data )
		if ( src in m )
			++n;
	for ( [d, t], m2 in data_store$string_data )
		if ( src in m2 )
			++n;
	return n;
	}
module GLOBAL;

redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";
redef OffensiveAgency::td_file = getenv("TEST_FILES") + "/threatdefence.tsv";

event check()
	{
	print fmt("after off: td_hosts=%d td_domains=%d intel threatdefence=%d offensive.agency=%d",
	          |OffensiveAgency::td_hosts|, |OffensiveAgency::td_domains|,
	          Intel::oa_count("threatdefence"), Intel::oa_count("offensive.agency"));
	terminate();
	}

event OffensiveAgency::td_updated(n_ips: count, n_domains: count)
	{
	print fmt("loaded: ips=%d domains=%d intel threatdefence=%d offensive.agency=%d", n_ips, n_domains,
	          Intel::oa_count("threatdefence"), Intel::oa_count("offensive.agency"));
	Config::set_value("OffensiveAgency::td_file", "");
	schedule 1 sec { check() };
	}
@TEST-END-FILE
