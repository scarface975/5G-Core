# Training lab

Thirteen exercises that walk through the core from the first registration to key rotation. Each one has a goal, the commands to run by hand, what you should see and why.
`tools/cli/g5c-lab` lists them, shows them and checks them: `check` runs the exercise on a private cluster (a network namespace, no root) and judges the result with the same scenario engine the tests use, so an exercise that stops working is found in the release, not by a student.

```
tools/cli/g5c-lab list
tools/cli/g5c-lab show 7
tools/cli/g5c-lab check 7        # or: check all
```

| # | Exercise |
|---|----------|
| 01 | [Start a core and register UEs](01-first-registration.md) |
| 02 | [Make the AMF refuse registrations on purpose](02-refuse-on-purpose.md) |
| 03 | [Ask the core why a subscriber failed](03-why-did-it-fail.md) |
| 04 | [Kill the SMF in the middle of a wave](04-lose-the-smf.md) |
| 05 | [Slow down the link to the UPF](05-slow-link.md) |
| 06 | [Hold a session to its rate](06-limit-a-session.md) |
| 07 | [Survive a signalling storm](07-signalling-storm.md) |
| 08 | [Change a limit without a restart](08-hot-reload.md) |
| 09 | [Replay a customer's capture against the core](09-replay-a-capture.md) |
| 10 | [Throw hostile input at the functions](10-hostile-input.md) |
| 11 | [Read N2 and N4 as a ladder](11-read-a-capture.md) |
| 12 | [Break a certificate and watch the core refuse](12-break-a-certificate.md) |
| 13 | [Rotate the master key of the subscriber database](13-rotate-a-key.md) |

Needs a built tree (`bash scripts/c_install.sh` or the build tree the tests use), Linux with user namespaces, `python3`; exercises 9 and 11 also need `tshark`.
