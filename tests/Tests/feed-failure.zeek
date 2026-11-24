# @TEST-DOC: A feed that cannot be fetched raises Feed_Problem (after failures_before_notice attempts).
#
# @TEST-EXEC: btest-bg-run zeek "zeek $PACKAGE/__load__.zeek ../test.zeek"
# @TEST-EXEC: btest-bg-wait 30
# @TEST-EXEC: zeek-cut note < zeek/notice.log > notes.txt
# @TEST-EXEC: btest-diff notes.txt
# @TEST-EXEC: grep -q 'consecutive failures fetching file:///nonexistent' zeek/notice.log

@TEST-START-FILE test.zeek
redef exit_only_after_terminate = T;
redef OffensiveAgency::feed_url = "file:///nonexistent/hosts.ndjson";
redef OffensiveAgency::failures_before_notice = 1;

event OffensiveAgency::log_offensive_agency(rec: OffensiveAgency::Hit)
	{
	if ( rec$kind == "feed" )
		terminate();
	}
@TEST-END-FILE
