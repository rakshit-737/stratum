### Reproduction: Kim et al. 2016 (LSTM system-call language model ensemble) on ADFA-LD

Test split as in the paper: 4372 validation normals vs 746 attacks. Training: of the 833 training normals, 750 are used to fit and 83 are held out for early stopping (the paper does not say how it stopped). Max 200 epochs, batch 32, CPU. Seeds [0, 1, 2]; mean ± sd (min-max) over seeds; per-seed bootstrap CIs in kim_lstm.json.

| method | paper AUC | our reproduction AUC |
|---|---:|---:|
| proposed leaky-ReLU ensemble (3 LSTMs) | 0.928 | 0.812 ± 0.005 (0.808-0.818) |
| averaging ensemble | 0.890 | 0.811 ± 0.006 (0.806-0.818) |
| voting ensemble | 0.859 | not reproduced (procedure not specified) |
| single LSTM 1x200 | (figure only) | 0.796 ± 0.013 |
| single LSTM 1x400 | (figure only) | 0.809 ± 0.012 |
| single LSTM 2x400 | (figure only) | 0.821 ± 0.006 |

Early stopping reached the epoch cap (best held-out epoch = max) for 1x200 in 2 of 3 seeds, so those models were still improving when training stopped.

Source: https://github.com/rakshit-737/stratum/actions/runs/37007358324 (commit `0c3983f`).
