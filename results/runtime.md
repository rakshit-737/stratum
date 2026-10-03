### Runtime rules on real Tetragon events (30 security-relevant events, 20 labelled attack)

In-sample: the rules were written with these events in view. Brackets: Wilson 95% CIs.

| rule set | TP | FP | FN | precision | recall |
|---|---:|---:|---:|---:|---:|
| STRATUM v0.2 (9 rules) | 16 | 2 | 4 | 0.89 [0.67, 0.97] | 0.80 [0.58, 0.92] |
| v0.1 rules (shell / SA token / egress) | 8 | 2 | 12 | 0.80 [0.49, 0.94] | 0.40 [0.22, 0.61] |

Detections traced to the exact running image digest: 9/18.

| event file | pod | process | label | STRATUM rule -> control | v0.1 |
|---|---|---|---|---|---|
| events.json | default/tiefighter | netserver | benign | - | - |
| process_kprobe.json | tenant-jobs/elasticsearch-56f8fc6988-sh8rm | vi | attack | R-SYS-WRITE -> ZT-WL-02 | - |
| privileged-pod-init.json | default/privileged-pod | docker-entrypoint.sh | benign | - | - |
| nginx-execution.json | default/privileged-pod | nginx | benign | - | - |
| nginx-listen.json | default/privileged-pod | nginx | benign | - | - |
| privileged-pod-bash.json | default/privileged-pod | bash | attack | R-SHELL -> ZT-IMG-02 | R-SHELL |
| privileged-pod-nsenter.json | default/privileged-pod | nsenter | attack | R-ESCAPE -> ZT-WL-01 | - |
| host-namespace-bash.json | default/privileged-pod | bash | attack | R-SHELL -> ZT-IMG-02 | R-SHELL |
| merlin-agent-insert-pod-spec.json | default/privileged-pod | cat | attack | - | - |
| merlin-agent-container-start-containerd-shim.json | ctr:host | containerd-shim | attack | - | - |
| merlin-agent-container-start-runc.json | ctr:host | runc | attack | - | - |
| merlin-agent-go-start.json | ctr:a51959123c3b | main | attack | R-UNMANAGED -> ZT-PROV-01 | - |
| merlin-agent-go-connect.json | ctr:a51959123c3b | main | attack | R-EGRESS -> ZT-NET-01 | R-EGRESS |
| merlin-agent-job-connect.json | ctr:a51959123c3b | main | attack | R-EGRESS -> ZT-NET-01 | R-EGRESS |
| merlin-agent-sh.json | ctr:a51959123c3b | sh | attack | R-UNMANAGED -> ZT-PROV-01 | R-SHELL |
| merlin-agent-7z.json | ctr:a51959123c3b | 7z | attack | R-UNMANAGED -> ZT-PROV-01 | - |
| merlin-agent-scp-sh.json | ctr:80976c957594 | sh | attack | R-UNMANAGED -> ZT-PROV-01 | R-SHELL |
| merlin-agent-scp-ssh.json | ctr:80976c957594 | ssh | attack | R-UNMANAGED -> ZT-PROV-01 | - |
| merlin-agent-scp.json | ctr:80976c957594 | scp | attack | R-UNMANAGED -> ZT-PROV-01 | - |
| merlin-agent-ssh-tunnel-connect.json | ctr:80976c957594 | ssh | attack | R-EGRESS -> ZT-NET-01 | R-EGRESS |
| process_listen.json | tenant-jobs/coreapi-79568ff848-ljh8n | python | benign | - | - |
| process_exec.json | tenant-jobs/elasticsearch-56f8fc6988-pb8c7 | curl | benign | - | - |
| process_connect.json | tenant-jobs/elasticsearch-56f8fc6988-pb8c7 | curl | benign | R-EGRESS -> ZT-NET-01 | R-EGRESS |
| lifecycle_sh_process_exec.json | tenant-jobs/elasticsearch-56f8fc6988-65smb | sh | benign | R-SHELL -> ZT-IMG-02 | R-SHELL |
| cat_process_exec.json | tenant-jobs/elasticsearch-56f8fc6988-65smb | cat | attack | - | - |
| cat_process_kprobe.json | tenant-jobs/elasticsearch-56f8fc6988-65smb | cat | attack | R-CRED-READ -> ZT-ID-04 | - |
| nc_process_exec.json | tenant-jobs/elasticsearch-56f8fc6988-65smb | nc | attack | R-NETTOOL -> ZT-IMG-02 | - |
| nc_process_connect.json | tenant-jobs/elasticsearch-56f8fc6988-65smb | nc | attack | R-EGRESS -> ZT-NET-01 | R-EGRESS |
| events.json | default/deathstar-6f87496b94-qdlh8 | starwars-docker | benign | - | - |
| events.json | default/deathstar-6f87496b94-gjf74 | starwars-docker | benign | - | - |
