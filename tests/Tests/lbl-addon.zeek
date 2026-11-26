# @TEST-DOC: LBL add-on: a site config file (here the shipped lbl.cfg.example, drops switched on) is applied through the Config framework, every finding goes to notice.log (no alarm), the right ones are emailed, ACTION_DROP only for external inbound sources, and lbl_drop_inbound F turns drops off without a code change.
#
# The shipped example with drops switched on.
# @TEST-EXEC: sed 's/^\(OffensiveAgency::lbl_drop_inbound\).*/\1	T/' $PACKAGE/lbl/lbl.cfg.example > lbl-test.cfg
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $PACKAGE/lbl $TEST_FILES/feed-ready.zeek %INPUT
# @TEST-EXEC: zeek-cut note src actions < notice.log > actions-drop.txt
# @TEST-EXEC: btest-diff actions-drop.txt
# @TEST-EXEC: test "$(grep -c ACTION_DROP actions-drop.txt)" = "3"
# @TEST-EXEC: ! grep ACTION_DROP actions-drop.txt | grep -q '	10\.'
# @TEST-EXEC: ! grep -q ACTION_ALARM actions-drop.txt
#
# Same config with drops switched off.
# @TEST-EXEC: rm -f *.log && sed 's/^\(OffensiveAgency::lbl_drop_inbound\).*/\1	F/' lbl-test.cfg > tmp.cfg && mv tmp.cfg lbl-test.cfg
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $PACKAGE/lbl $TEST_FILES/feed-ready.zeek %INPUT
# @TEST-EXEC: zeek-cut note src actions < notice.log > actions-default.txt
# @TEST-EXEC: btest-diff actions-default.txt
# @TEST-EXEC: ! grep -q ACTION_DROP actions-default.txt

# Replace (not add to) the config file list: only the test copy of the site config.
# The package defers feed loading until every config file has been read, so
# lbl_drop_inbound is in effect before the first packet.
redef Config::config_files = { "lbl-test.cfg" };
redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";
