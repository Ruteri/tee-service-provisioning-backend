1. Persistency
	-> KMS-encrypted persistent disk should do it. Comes for free with dstack.
2. Censorship Resistance
	-> Important for secrets, deregistration, upgrades. KMS CR is actually a bigger problem than config CR (possible leaks only in KMS).
3. Secrets
	-> Local KMS
	-> Remote KMS
	-> How to address/reference secrets in configuration?
4. Discovery
	-> Public DNS list on chain (decentralized)
	-> Public centralized discovery endpoint (centralized)

Adjusting dstack's KMS:
* Use metadata instead of manifest (metadata can be a manifest, but doesn't have to be)
	Measurements (derived, base+extensions), instance and owner identity (pubkeys+signatures)
	Currently only measurement is used (app id derived from measurement). The manifest is ignored.
	Extending measurements is not as simple, since we need to derive at different granularities (same app different instance/operator).
	Maybe parse the extensions? The extensions are just a string. We can encode identity there just fine. Would this work in Azure as well? TPM? AppID is there already so that could work.
		See tdxctl/src/fde_setup.rs "system-preparing"
		If we extend the events in this way it would work almost out of the box. For us the app id would be governance rather than manifest.
		How to generalize from manifest boot to any binary/vm boot? Can we modularize that? Would be cool to use this for the boot sequence.
* How can we reuse KMS's CA?
	ectd supports that by default. CA would have to be per app/app-version? — it kind of is already.

dstack vs native application
Pros:
	-> disk encryption handled by dstack
	-> out of the box governance
	-> addressing could work
Cons:
	-> unnecessary complexity
		consider modularizing disk encryption or kms client
	-> baremetal only (and not simple to adjust that)
	-> no CR yet, but we could add it (to KMS or as a module)
