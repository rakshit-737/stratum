# Pod Security Standards checks in Rego (subset of stratum/pss.py, same check ids).
# Input: a Gatekeeper admission review (input.review.object) or a bare object (input).
# Accepts Pods and pod-template workloads (Deployment, StatefulSet, DaemonSet, Job, ReplicaSet, CronJob).
# Exported as a Gatekeeper ConstraintTemplate by `stratum gatekeeper`.
package stratum.pss

import rego.v1

obj := input.review.object if input.review.object
obj := input if not input.review

spec := obj.spec if obj.kind == "Pod"
spec := obj.spec.jobTemplate.spec.template.spec if obj.kind == "CronJob"
spec := obj.spec.template.spec if not obj.kind in {"Pod", "CronJob"}

baseline_caps := {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
	"NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}

containers contains c if some c in spec.initContainers
containers contains c if some c in spec.containers
containers contains c if some c in spec.ephemeralContainers

windows if lower(object.get(spec, ["os", "name"], "")) == "windows"

userns if spec.hostUsers == false

# ---- baseline
violations contains ["hostnamespaces", sprintf("%s=true", [k])] if {
	some k in ["hostNetwork", "hostPID", "hostIPC"]
	spec[k] == true
}

violations contains ["privileged", sprintf("container %s privileged", [c.name])] if {
	some c in containers
	c.securityContext.privileged == true
}

violations contains ["capabilities_baseline", sprintf("container %s adds %s", [c.name, cap])] if {
	some c in containers
	some cap in object.get(c, ["securityContext", "capabilities", "add"], [])
	not cap in baseline_caps
}

violations contains ["hostpathvolumes", sprintf("volume %s is hostPath", [v.name])] if {
	some v in spec.volumes
	v.hostPath
}

violations contains ["hostports", sprintf("container %s hostPort %v", [c.name, p.hostPort])] if {
	some c in containers
	some p in c.ports
	p.hostPort
	p.hostPort != 0
}

# ---- restricted
violations contains ["allowprivilegeescalation", sprintf("container %s allowPrivilegeEscalation!=false", [c.name])] if {
	not windows
	some c in containers
	object.get(c, ["securityContext", "allowPrivilegeEscalation"], null) != false
}

violations contains ["runasuser", "pod runAsUser=0"] if {
	not userns
	spec.securityContext.runAsUser == 0
}

violations contains ["runasuser", sprintf("container %s runAsUser=0", [c.name])] if {
	not userns
	some c in containers
	c.securityContext.runAsUser == 0
}

pod_nonroot := object.get(spec, ["securityContext", "runAsNonRoot"], null)

violations contains ["runasnonroot", "pod runAsNonRoot=false"] if {
	not userns
	pod_nonroot == false
}

violations contains ["runasnonroot", sprintf("container %s runAsNonRoot=false", [c.name])] if {
	not userns
	some c in containers
	object.get(c, ["securityContext", "runAsNonRoot"], null) == false
}

violations contains ["runasnonroot", sprintf("container %s runAsNonRoot unset", [c.name])] if {
	not userns
	some c in containers
	object.get(c, ["securityContext", "runAsNonRoot"], null) == null
	pod_nonroot != true
}

baseline_checks := {"hostnamespaces", "privileged", "capabilities_baseline", "hostpathvolumes", "hostports"}

level := object.get(object.get(input, "parameters", {}), "level", "restricted")

# Gatekeeper entry point
violation contains {"msg": sprintf("PSS %s/%s: %s", [level, v[0], v[1]]), "details": {"check": v[0]}} if {
	some v in violations
	level_applies(v[0])
}

level_applies(c) if c in baseline_checks
level_applies(_) if level == "restricted"
