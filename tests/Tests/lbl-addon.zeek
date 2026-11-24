# @TEST-DOC: LBL add-on: lbl.cfg is applied through the Config framework, every finding is alarmed, the right ones are emailed, and ACTION_DROP is added only when enabled and only for external inbound sources.
#
# Default lbl.cfg: no drops.
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $PACKAGE/lbl $TEST_FILES/feed-ready.zeek %INPUT
# @TEST-EXEC: zeek-cut note src actions < notice.log > actions-default.txt
# @TEST-EXEC: btest-diff actions-default.txt
# @TEST-EXEC: ! grep -q ACTION_DROP actions-default.txt
#
# Drop switched on from a second config file, no code change:
# @TEST-EXEC: rm -f *.log && echo "OffensiveAgency::lbl_drop_inbound T" > drop.cfg
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $PACKAGE/lbl %INPUT ./drop-on.zeek
# @TEST-EXEC: zeek-cut note src actions < notice.log > actions-drop.txt
# @TEST-EXEC: btest-diff actions-drop.txt
# @TEST-EXEC: test "$(grep -c ACTION_DROP actions-drop.txt)" = "3"
# @TEST-EXEC: ! grep ACTION_DROP actions-drop.txt | grep -q '	10\.'

redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";

@TEST-START-FILE drop-on.zeek
redef Config::config_files += { "drop.cfg" };

event zeek_init() &priority=100
	{
	suspend_processing();
	}

# Resume once the feed is applied AND drop.cfg has been read.
global fed = F;
global cfg_read = F;
function maybe_go()
	{
	if ( fed && cfg_read && OffensiveAgency::lbl_drop_inbound )
		continue_processing();
	}
event OffensiveAgency::feed_updated(n_ips: count, n_domains: count)
	{
	fed = T;
	maybe_go();
	}
event Input::end_of_data(name: string, source: string)
	{
	if ( /drop\.cfg/ in source )
		{
		cfg_read = T;
		maybe_go();
		}
	}
@TEST-END-FILE
