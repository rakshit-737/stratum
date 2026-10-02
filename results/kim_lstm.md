### Reproduction: Kim et al. 2016 (LSTM system-call language model ensemble) on ADFA-LD

Test split as in the paper: 4372 validation normals vs 746 attacks. Training: of the 833 training normals, 750 are used to fit and 83 are held out for early stopping (the paper does not say how it stopped). Max 12 epochs, batch 32, CPU. Seeds [0, 1, 2]; mean ± sd (min-max) over seeds; per-seed bootstrap CIs in kim_lstm.json.

| method | paper AUC | our reproduction AUC |
|---|---:|---:|
| proposed leaky-ReLU ensemble (3 LSTMs) | 0.928 | 0.709 ± 0.003 (0.706-0.712) |
| averaging ensemble | 0.890 | 0.634 ± 0.010 (0.627-0.645) |
| voting ensemble | 0.859 | not reproduced (procedure not specified) |
| single LSTM 1x200 | (figure only) | 0.731 ± 0.018 |
| single LSTM 1x400 | (figure only) | 0.623 ± 0.003 |
| single LSTM 2x400 | (figure only) | 0.584 ± 0.003 |
