# Phase 5 tooling eval — VR agent blind briefs

Hand the VR agent **only the one brief** for the target it is working, and **only the compiled binary** (never the source, never `EVAL_PLAN.md`, never this file's other entries). Each brief states a realistic objective the way a real engagement would; it deliberately does **not** name the bug, the file's internals, or which HexGraph tool to use. The target's construction is what forces the right tool — discovering that is part of what's being evaluated.

These targets are fictional. Any vendor/product/version names are invented and identifying strings are scrubbed, so nothing is solvable by recognizing a public CVE — only by reading the binary.

---

## Brief A — `mitis_relayd`

You pulled the `relayd` daemon off a **Mitis EdgeRelay** appliance (a small x86-64 Linux box that proxies field-bus traffic to a cloud endpoint). The vendor claims the build is "hardened."

**Objective.** Assess `relayd`'s exploitability as shipped. Specifically: what runtime memory protections does this binary actually carry, and is there a realistic path from attacker-controlled input to **command or code execution**? Record what you find in the graph — the binary's security posture, any dangerous capability it links against, and a grounded hypothesis about exploitability.

You have only the binary.

---

## Brief B — `stringcrypt.exe`

`stringcrypt.exe` is a small Windows (PE32+) agent recovered from a **compromised analyst workstation**. It looks like a benign "relay agent," but IR believes it beacons out.

**Objective.** Recover this sample's **indicators of compromise**: any command-and-control endpoints (URLs/hosts), API keys, or credentials it carries, and the routine that produces them. A surface-level string dump looks innocuous — the interesting material does not sit in the binary as plain text. Record the recovered IOCs and the routine that builds them in the graph.

You have only the binary.

---

## Brief C — `vantage_iot_fw.bin`

`vantage_iot_fw.bin` is a firmware image from a **Vantage IoT gateway**. You're doing a fast supply-chain / hygiene triage of the whole image before a deeper review.

**Objective.** Triage the **entire filesystem** for "shipped-with-known-weak-defaults": baked-in or default credentials, deprecated/broken cryptography, and outdated bundled service versions with a track record of vulnerabilities. The signal is spread across more than one executable in the image, so make sure your assessment covers the whole corpus, not a single file. Promote what you confirm into the graph as leads, grounded in why each is a concern.

You have only the firmware image.

---

## Brief D — `licensegate`  *(run after angr support lands)*

`licensegate` is a small x86-64 binary that gates a **privileged action** behind a serial/license check. The action only fires for a "valid" serial; an invalid one is rejected.

**Objective.** Determine whether the check is **satisfiable** at all, and if so, **recover a serial that passes it** and reaches the privileged action. The valid serial is not printed, logged, or stored anywhere in plain form — it's defined by what the check computes. Record the recovered input and the code path it unlocks in the graph.

You have only the binary.
