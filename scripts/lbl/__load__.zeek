##! offensive-agency: LBL site add-on.
##!
##! NOT loaded by the package's default __load__. LBL loads it explicitly,
##! after the package:
##!
##!     @load offensive-agency
##!     @load offensive-agency/lbl
##!
##! It does two things and nothing else:
##!   1. Defines the options a site config file sets (scanner allowlist,
##!      never-drop nets). The package does NOT register any config file:
##!      it ships only lbl.cfg.example (placeholder values). The real site
##!      file lives outside the repo and is registered in local.zeek with
##!          redef Config::config_files += { "/path/to/lbl.cfg" };
##!      Site-local overrides (e.g. turning on drops) go in a SEPARATE
##!      config file, such as /YURT/feeds/zeek-config/offensive-agency.cfg,
##!      added to Config::config_files in local.zeek. Never set the same
##!      option in both files: there is no ordering guarantee between them.
##!   2. Adds LBL notice actions: alarm for every finding, email for the
##!      findings that need a human today, and (opt-in, via the
##!      lbl_drop_inbound option) ACTION_DROP for inbound agent hosts,
##!      executed by LBL's existing lbl.drop-action.zeek machinery.

@load policy/frameworks/notice/actions/drop
@load ../main

module OffensiveAgency;

export {
	## Add ACTION_DROP to inbound findings from external agent hosts.
	## Off by default; enable it from a site override config file.
	option lbl_drop_inbound = F;

	## Never drop these, even when lbl_drop_inbound is on.
	option lbl_never_drop_nets: set[subnet] = {};

	## Notice types that are emailed (in addition to being alarmed).
	option lbl_email_types: set[Notice::Type] = {
		OffensiveAgency::Agent_Implant_Or_Webshell,
		OffensiveAgency::Local_Host_Listed,
		OffensiveAgency::Agent_Running_Locally,
		OffensiveAgency::Outbound_To_Agent_Host,
		OffensiveAgency::Agent_Domain_Contact,
		OffensiveAgency::OAST_Callback_Lookup,
		OffensiveAgency::Feed_Problem,
	};
}

const package_notes: set[Notice::Type] = {
	Outbound_To_Agent_Host, Inbound_From_Agent_Host, Agent_Domain_Contact,
	Agent_Activity_Inbound, Agent_Running_Locally, Agent_Implant_Or_Webshell,
	OAST_Callback_Lookup, Local_Host_Listed, Feed_Problem,
};

function never_drop(a: addr): bool
	{
	if ( Site::is_local_addr(a) )
		return T;
	for ( sn in lbl_never_drop_nets )
		if ( a in sn )
			return T;
	return F;
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note !in package_notes )
		return;

	add n$actions[Notice::ACTION_ALARM];

	if ( n$note in lbl_email_types )
		add n$actions[Notice::ACTION_EMAIL];

	if ( lbl_drop_inbound && n?$src && ! never_drop(n$src) &&
	     (n$note == Inbound_From_Agent_Host || n$note == Agent_Activity_Inbound ||
	      (n$note == Agent_Implant_Or_Webshell && ! Site::is_local_addr(n$src))) )
		add n$actions[Notice::ACTION_DROP];
	}
