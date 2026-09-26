# Threat Model

## Scope
STRATUM consumes CI provenance, Kubernetes state and runtime events, and produces findings and incidents. The MVP runs offline on synthetic data.

## Threats STRATUM helps defend against (in the modelled cluster)
| Threat | Signal | Control |
| --- | --- | --- |
| Shell / RCE in a container | `exec` of a shell | ZT-IMG-02 |
| C2 / exfiltration egress | `connect` to a non-RFC1918 address | ZT-NET-01 |
| Credential theft (SA token) | `open` of the serviceaccount token | ZT-ID-02, ZT-ID-03 |
| Untrusted image (supply chain / drift) | image has no build provenance | ZT-PROV-01/02 |
| Vulnerable shared base image | base image on the deny-list | ZT-IMG-01 (plus blast radius) |
| Over-privileged workload | privileged / root / cluster-admin | ZT-WL-01, ZT-ID-03 |

## Threats to STRATUM itself
| Threat | Impact | Mitigation (current / planned) |
| --- | --- | --- |
| Forged provenance or events fed in | False trace, missed alert | Planned: verify signed attestations (in-toto/Sigstore) and authenticated collectors |
| Attacker evades rules (renamed shell, internal pivot) | Missed detection | Novelty model as a second layer; documented as a known gap |
| Baseline poisoning (attack inside the training window) | Novelty model learns the attack as normal | Planned: a baseline from trusted time windows only, with drift checks |
| Tampered JSON input | Parser misuse | Plain `json` plus dataclasses. No `eval`, no pickle, no YAML loading |
| Sensitive data in reports | Leakage | Reports hold only IDs and metadata, never secret values |

## Assumptions and limitations
- The graph is only as good as the collectors. Today every collector is synthetic.
- Egress enforcement is simulated and covers IP/CIDR only. It does not model ports, DNS or L7.
- Perfect scores on the seeded scenario are not evidence of real-world performance.
