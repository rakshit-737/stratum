# STRATUM Zero-Trust controls as OPA/Rego (Rego v1).
#
# Input: a STRATUM Dataset as JSON (`stratum export --format json`) plus an
# optional `deny_bases` array. Output: `data.stratum.findings`, a set of
# {control_id, subject} objects. This file mirrors stratum/policy.py rule for
# rule; `stratum opa-check` evaluates both and diffs the results.
package stratum

import rego.v1

baseline_checks := {
	"hostnamespaces", "privileged", "capabilities_baseline", "hostpathvolumes", "hostports",
	"apparmorprofile", "selinuxoptions", "procmount", "seccompprofile_baseline", "sysctls",
	"windowshostprocess", "hostprobesandhostlifecycle",
}

real_data if count(input.image_reports) > 0

real_data if {
	some w in input.workloads
	w.pss_level != ""
}

wid(w) := sprintf("workload:%s/%s", [w.namespace, w.name])

sa_of(w) := sa if {
	some sa in input.service_accounts
	sa.namespace == w.namespace
	sa.name == w.service_account
}

report_of(ref) := r if {
	some r in input.image_reports
	r.ref == ref
}

image_refs(w) := w.images if count(w.images) > 0

image_refs(w) := [w.image_digest] if count(w.images) == 0

# ---------------------------------------------------------------- network
has_egress_policy(ns) if {
	some np in input.network_policies
	np.namespace == ns
	"Egress" in np.policy_types
}

findings contains {"control_id": "ZT-NET-01", "subject": sprintf("ns:%s", [ns.name])} if {
	some ns in input.namespaces
	some w in input.workloads
	w.namespace == ns.name
	not has_egress_policy(ns.name)
}

# --------------------------------------------------------------- workload
baseline_violation(w) if w.privileged
baseline_violation(w) if w.run_as_root
baseline_violation(w) if w.host_network
baseline_violation(w) if {
	some k, _ in w.pss_violations
	k in baseline_checks
}

findings contains {"control_id": "ZT-WL-01", "subject": wid(w)} if {
	some w in input.workloads
	baseline_violation(w)
}

findings contains {"control_id": "ZT-WL-02", "subject": wid(w)} if {
	some w in input.workloads
	not baseline_violation(w)
	w.pss_level == "baseline"
}

# --------------------------------------------------------------- identity
findings contains {"control_id": "ZT-ID-01", "subject": wid(w)} if {
	some w in input.workloads
	w.service_account == "default"
}

findings contains {"control_id": "ZT-ID-02", "subject": wid(w)} if {
	some w in input.workloads
	w.automount_token == true
	count(sa_of(w).rbac_risks) > 0
}

findings contains {"control_id": "ZT-ID-03", "subject": wid(w)} if {
	some w in input.workloads
	sa_of(w).cluster_admin == true
}

risky(r) if startswith(r, "secrets read cluster")
risky(r) if startswith(r, "RBAC escalate")
risky(r) if startswith(r, "wildcard")

findings contains {"control_id": "ZT-ID-04", "subject": wid(w)} if {
	some w in input.workloads
	sa := sa_of(w)
	sa.cluster_admin == false
	some r in sa.rbac_risks
	risky(r)
}

# ----------------------------------------------------------- supply chain
findings contains {"control_id": "ZT-PROV-03", "subject": wid(w)} if {
	real_data
	some w in input.workloads
	some ref in image_refs(w)
	not contains(ref, "@sha256:")
}

trusted_image(w) if {
	some img in input.images
	img.digest == w.image_digest
	img.build_id != null
	some b in input.builds
	b.id == img.build_id
}

findings contains {"control_id": "ZT-PROV-01", "subject": wid(w)} if {
	some w in input.workloads
	not trusted_image(w)
	not real_data
}

findings contains {"control_id": "ZT-PROV-01", "subject": wid(w)} if {
	some w in input.workloads
	not trusted_image(w)
	real_data
	report_of(w.image_digest)
}

findings contains {"control_id": "ZT-PROV-02", "subject": wid(w)} if {
	some w in input.workloads
	some img in input.images
	img.digest == w.image_digest
	some b in input.builds
	b.id == img.build_id
	b.signed == false
}

findings contains {"control_id": "ZT-IMG-01", "subject": wid(w)} if {
	some w in input.workloads
	trusted_image(w)
	some img in input.images
	img.digest == w.image_digest
	img.base_image in object.get(input, "deny_bases", [])
}

findings contains {"control_id": "ZT-IMG-01", "subject": wid(w)} if {
	some w in input.workloads
	some ref in image_refs(w)
	count(report_of(ref).critical) > 0
}

findings contains {"control_id": "ZT-IMG-03", "subject": wid(w)} if {
	some w in input.workloads
	some ref in image_refs(w)
	count(report_of(ref).kev) > 0
}

findings contains {"control_id": "ZT-IMG-02", "subject": wid(w)} if {
	some w in input.workloads
	count(report_of(w.image_digest).shells) > 0
}
