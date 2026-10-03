### Performance (real corpus: 470 nodes / 504 edges, 95 workloads, 30 runtime events)

Milliseconds, median (min-max): corpus load over 3 loads (the first from a cold file cache), the rest over 20 repeats. Machine: Windows-11-10.0.26200-SP0, Python 3.14.3, 16 logical CPUs, shared with other jobs while measured.

| load corpus | build graph | evaluate policy | trace one pod to commit | full analyze |
|---:|---:|---:|---:|---:|
| 4800.896 (4688.153-5354.721) | 8.978 (4.126-33.933) | 5.529 (1.529-12.69) | 0.052 (0.014-0.124) | 20.855 (11.969-81.657) |
