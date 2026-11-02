# Experimental scenarios

Not part of the tests. `echo-downlink.yaml` and `traffic-dl-ambr.yaml` need the echo mode of the load generator (`echo: true`, backlog B-02: loss, round trip and jitter of
downlink traffic through the UPF, and the downlink AMBR). The generator side is written, but the packets did not come back to the gNB's N3 socket in the first live run and the cause is not found yet:
they are kept here so the work is not lost, and they fail until that is fixed.
