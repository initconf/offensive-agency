# @TEST-DOC: Standalone with JSON logs: one JSON object per finding with the expected keys.
#
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $TEST_FILES/feed-ready.zeek %INPUT
# @TEST-EXEC: test $(wc -l < offensive_agency.log) -eq 13
# @TEST-EXEC: grep -q '"note":"OffensiveAgency::Outbound_To_Agent_Host"' offensive_agency.log
# @TEST-EXEC: grep -q '"agents":"artex:confirmed"' offensive_agency.log
# @TEST-EXEC: btest-diff offensive_agency.log

@load policy/tuning/json-logs
redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";
