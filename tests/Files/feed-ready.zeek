# Test helper: hold packet processing until the feed has been applied, so
# the trace is matched against a populated Intel store.
@load base/frameworks/intel

event zeek_init() &priority=100
	{
	suspend_processing();
	}

event OffensiveAgency::feed_updated(n_ips: count, n_domains: count)
	{
	continue_processing();
	}
