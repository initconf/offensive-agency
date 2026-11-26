# @TEST-DOC: Standalone: every scenario in the trace yields exactly the expected hits and notices (TSV).
#
# @TEST-EXEC: zeek -C -r $TRACES/offensive-agency.pcap $PACKAGE/__load__.zeek $TEST_FILES/feed-ready.zeek %INPUT
# @TEST-EXEC: test "$(grep -vc '^#' offensive_agency.log)" = "13"
# @TEST-EXEC: test "$(grep -vc '^#' notice.log)" = "13"
# @TEST-EXEC: zeek-cut kind indicator direction local_host remote_host agents note < offensive_agency.log > hits.txt
# @TEST-EXEC: btest-diff hits.txt
# @TEST-EXEC: zeek-cut note msg src dst < notice.log > notices.txt
# @TEST-EXEC: btest-diff notices.txt
# @TEST-EXEC: btest-diff offensive_agency.log

redef OffensiveAgency::feed_file = getenv("TEST_FILES") + "/feed.ndjson";
