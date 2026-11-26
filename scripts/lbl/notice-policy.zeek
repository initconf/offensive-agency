##! offensive-agency LBL notice policy: notice.log for every finding, email
##! for lbl_email_types, ACTION_DROP for external inbound agent hosts only
##! when lbl_drop_inbound is T (set in the site config file). Drops are
##! executed by the site's drop machinery (e.g. NetControl), not here.

module OffensiveAgency;

const package_notes: set[Notice::Type] = {
	Outbound_To_Agent_Host, Inbound_From_Agent_Host, Agent_Domain_Contact,
	Agent_Activity_Inbound, Agent_Running_Locally, Agent_Implant_Or_Webshell,
	OAST_Callback_Lookup, Local_Host_Listed, Feed_Problem,
	Agent_Low_Confidence,   # notice.log only: never emailed or dropped
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
	# Runs for every notice at the site; some site scripts build
	# Notice::Info records without $note, so don't assume it is set.
	if ( ! n?$note || n$note !in package_notes )
		return;

	add n$actions[Notice::ACTION_LOG];

	if ( n$note in lbl_email_types )
		add n$actions[Notice::ACTION_EMAIL];

	if ( lbl_drop_inbound && n?$src && ! never_drop(n$src) &&
	     (n$note == Inbound_From_Agent_Host || n$note == Agent_Activity_Inbound ||
	      (n$note == Agent_Implant_Or_Webshell && ! Site::is_local_addr(n$src))) )
		add n$actions[Notice::ACTION_DROP];
	}
