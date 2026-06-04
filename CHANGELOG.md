# Changelog

All notable changes to HexGraph are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project will adopt
[semantic versioning](https://semver.org/) properly once it reaches 1.0. Until then,
expect breaking changes between minor versions.

## [0.3.0](https://github.com/branover/hexgraph/compare/hexgraph-v0.2.0...hexgraph-v0.3.0) (2026-06-04)


### Features

* add check_decompiler health verb and surface decompiler health in get_schemas ([2ab6d85](https://github.com/branover/hexgraph/commit/2ab6d856f7a249311543ed272cf6a2756be50689))


### Bug Fixes

* build Ghidra against JDK 21 and add a CI gate that decompiles a fixture ([e4fa3fa](https://github.com/branover/hexgraph/commit/e4fa3fa4d43122096d76c93b5e3175411ed9d139))
* **ci:** drop unreachable stdout re-capture in the ghidra gate ([aaabeb3](https://github.com/branover/hexgraph/commit/aaabeb3d3fed3ecb66bdd07ec89cbb530c233767))
* make Ghidra 12 decompile under full sandbox hardening ([532694d](https://github.com/branover/hexgraph/commit/532694dce90f47c3bc03f39090d28fc7203233c0))
* radare2 health also confirms the sandbox image is built ([60bf5ad](https://github.com/branover/hexgraph/commit/60bf5adbca08b61a7dffd951c39080418f00fd04))
* surface decompiler probe errors instead of a bare exit code ([e860f0a](https://github.com/branover/hexgraph/commit/e860f0afe1c4e4edc83602c5d9656fd350d3c2a1))


### Documentation

* reverse-engineering tooling design ([#126](https://github.com/branover/hexgraph/issues/126)) ([eee464e](https://github.com/branover/hexgraph/commit/eee464e6843b183415578de0f2ea63a4c1b546eb))

## [0.2.0](https://github.com/branover/hexgraph/compare/hexgraph-v0.1.0...hexgraph-v0.2.0) (2026-06-04)


### Features

* add create_project MCP tool ([#113](https://github.com/branover/hexgraph/issues/113)) ([89f74c0](https://github.com/branover/hexgraph/commit/89f74c00ec48ad663a85a6c7fe13a58d72900c2d))
* add DoS liveness/unavailable verification oracle (Phase 2) ([018343b](https://github.com/branover/hexgraph/commit/018343bfd88a28e8b70e2f681e497c965271cbc2))
* adopt release-please versioning and expose build identity (/health, banner, --version) ([#124](https://github.com/branover/hexgraph/issues/124)) ([84e12c1](https://github.com/branover/hexgraph/commit/84e12c1f6e2d3dcc896ed4dce6d0ee470b2be42b))
* allow editing scratch trees without features.source.edit (scoped source-edit) ([#123](https://github.com/branover/hexgraph/issues/123)) ([d75d436](https://github.com/branover/hexgraph/commit/d75d43655b242d954544421c30856f65fba7c0e2))
* battle-test PR-1 — fuzz UX, campaign-status, egress audit, MCP schema ([07eb9e6](https://github.com/branover/hexgraph/commit/07eb9e679627043313cd6a88d98e7b9731c24097))
* binary-only (AFL++ qemu/frida) + network (boofuzz/desock) fuzzing — Phase 5 ([d102817](https://github.com/branover/hexgraph/commit/d1028175a5cba39415ac02f2492598b2992a7af2))
* binary-only (AFL++ qemu/frida) + network (boofuzz/desock) fuzzing — Phase 5 ([dcf6fe1](https://github.com/branover/hexgraph/commit/dcf6fe1b9baf9aab02b00fb56af38176e8d5f2c6))
* Builder seam + build-as-API (fuzzing+source Phase 2) ([29ba331](https://github.com/branover/hexgraph/commit/29ba331f766c497f1690c4cee200fffc83ece16d))
* centralize bounded-egress allowlist enforcement (review [#7](https://github.com/branover/hexgraph/issues/7)) ([362f888](https://github.com/branover/hexgraph/commit/362f8887cec8705c9afc3f3785c6f2a59eb2b5dd))
* coverage-guided fuzzing + crash dedup/minimize/exploitability (Phase 0) ([4387fcd](https://github.com/branover/hexgraph/commit/4387fcd84093cc363573626032fc3f503b49f0ad))
* coverage-guided fuzzing + crash dedup/minimize/exploitability (Phase 0) ([8883083](https://github.com/branover/hexgraph/commit/88830836597df287cbb80d0c8e540c79d93c07c5))
* coverage-guided fuzzing campaigns (AFL++ + libFuzzer), detached lifecycle, ResourceSpec ([a90b68a](https://github.com/branover/hexgraph/commit/a90b68ae9fcbddd4b021afed6419ed619d5c2ef5))
* deeper staged showcase fuzz target so coverage visibly climbs ([6a28cd5](https://github.com/branover/hexgraph/commit/6a28cd5285d5788d919c54847eaadc1a452f471e))
* deeper, staged showcase fuzz target so coverage visibly climbs ([5f1a4e4](https://github.com/branover/hexgraph/commit/5f1a4e423158095d2bd9e0327cd88c11cd38e4ca))
* DoS liveness/unavailable verification oracle (Phase 2) ([49abc90](https://github.com/branover/hexgraph/commit/49abc904fb7021dcf9aca54386de53bb2293227d))
* expressive Run menu + reconciled fuzz path + human task errors ([79685cd](https://github.com/branover/hexgraph/commit/79685cd05f0c7ecfec05918a2e3140b9c82a7dc6))
* filesystem-hierarchical targets pane (curatable targets phase 1) ([f943eb6](https://github.com/branover/hexgraph/commit/f943eb69eb8db7e12af6c4ba907f466a401d12c3))
* filesystem-hierarchical targets pane (curatable targets, phase 1) ([0d12608](https://github.com/branover/hexgraph/commit/0d12608dc4abf3295c98216f699e5eacffe94128))
* **firmae:** vendor-brand inference + clearer no-network error (DVRF VR follow-up) ([c774728](https://github.com/branover/hexgraph/commit/c774728cc27c143a8b3e3c897f52345148373cf0))
* first-class raw-TCP/socket live target (register_socket) ([3cfc4a3](https://github.com/branover/hexgraph/commit/3cfc4a3485f4ec2f9a9930f85ef745fb69006238))
* first-class raw-TCP/socket live target (register_socket) ([9e264f8](https://github.com/branover/hexgraph/commit/9e264f8621569c135213b4bf0b4deebec593d052))
* full web-app authoring (no CLI required) with enforced invariants ([6ba0d2c](https://github.com/branover/hexgraph/commit/6ba0d2c54e3266b41a5ccfcc1b50b8969b2e3a9e))
* fuzz phase 4 — Source/IDE tab UX + Campaigns/Artifacts triage ([f6e7bac](https://github.com/branover/hexgraph/commit/f6e7bac268da2a810d1f20061ece374ff4d1dc19))
* fuzz phase 4 — Source/IDE tab UX + Campaigns/Artifacts triage ([0df80ab](https://github.com/branover/hexgraph/commit/0df80ab2869f9864bbf2db5f5efe520cc89dba4e))
* fuzzing+source Phase 7 — supply-chain, cross-compile, editable IDE, coverage diff ([7819bd8](https://github.com/branover/hexgraph/commit/7819bd8144a224fa432a85184c90fe98d00dccd0))
* graph collapse/filter + selective graph context in task bundles ([4684588](https://github.com/branover/hexgraph/commit/46845885884d6c0648d03ce98f12e1261f2cedd5))
* graph presentation phase 1 — visual legibility ([f7d48e8](https://github.com/branover/hexgraph/commit/f7d48e8fe5326b540e8519003865bbae70fadbc0))
* graph presentation phase 1 — visual legibility ([5b224cd](https://github.com/branover/hexgraph/commit/5b224cdf9d17cb10b12374620aca47346752d0fa))
* graph presentation phase 2 — focus / hide / navigation ([a2ee17d](https://github.com/branover/hexgraph/commit/a2ee17d7d9c215e7885a6faa52d2a3dd38234f4e))
* graph presentation Phase 3 — compound islands + grouping + expand/collapse ([bff4448](https://github.com/branover/hexgraph/commit/bff4448ebdc3e1b52b562d233e3d037fccf80ba7))
* graph presentation Phase 4 — layout-by-context + semantic zoom ([4458f8b](https://github.com/branover/hexgraph/commit/4458f8b75532c93af78cc04e9aefd06cb9456956))
* graph presentation Phase 4 — layout-by-context + semantic zoom ([7c1b5ea](https://github.com/branover/hexgraph/commit/7c1b5ea5fa3d3fbf316856582e820c3f7ba01a62))
* graph presentation Phase 5 — layer panel, filter rail, complementary views ([c3fa748](https://github.com/branover/hexgraph/commit/c3fa748853d8277202165da594be3c516b25398f))
* graph presentation Phase 5 — layer panel, filter rail, complementary views ([fb16f73](https://github.com/branover/hexgraph/commit/fb16f736922756afa2eacc9a2ff96635a55739c1))
* hard-delete a finding (distinct from dismiss) ([6efcef0](https://github.com/branover/hexgraph/commit/6efcef0a20ebd838a336331e88b163771b4b6351))
* hard-delete a finding (distinct from dismiss) ([ba6c009](https://github.com/branover/hexgraph/commit/ba6c00953c20c56b0eec9520011db3c30db3dd3c))
* interactive `hexgraph setup` wizard with security-implication panels ([185bda6](https://github.com/branover/hexgraph/commit/185bda6462d6163445af0ef4ea70490e07625145))
* interactive `hexgraph setup` wizard with security-implication panels ([314774e](https://github.com/branover/hexgraph/commit/314774ede9221b95ed66ac58c2b42da925534f6a))
* launch-and-join for local-service network fuzzing (§5.8b) ([160214c](https://github.com/branover/hexgraph/commit/160214c710a231abadeceed7af3a64b805b954b6))
* launch-and-join for local-service network fuzzing (§5.8b) ([126f4f6](https://github.com/branover/hexgraph/commit/126f4f65aec96c0a2b92b3a6f142eabb3737af30))
* make verified PoC findings presentable and actionable ([83d6310](https://github.com/branover/hexgraph/commit/83d6310d9edde5d857c654d7a7a29a1bff783411))
* modernize `just demo` to the current headline loop ([1ef2db9](https://github.com/branover/hexgraph/commit/1ef2db9be334583aa73fe6e4d5f0da4a54e9623b))
* modernize `just demo` to the current headline loop ([d9d7cf5](https://github.com/branover/hexgraph/commit/d9d7cf548b2811b2fafa21cdcbf7298d95221a31))
* modernize source viewer, center toolbar, and fuzz modal (UI polish) ([5e3d216](https://github.com/branover/hexgraph/commit/5e3d21677ddbba0eb7b6ec7de9f9c17b29ef0d5c))
* modernize the Build-from-source modal to match the Fuzz modal ([9d20e15](https://github.com/branover/hexgraph/commit/9d20e15d47cd4f768321fe95f396603ae2c4ccf6))
* modernize the Build-from-source modal to match the Fuzz modal ([50e65ae](https://github.com/branover/hexgraph/commit/50e65aece8eb7920183fc7e14a496a28b64c1214))
* modernize the source viewer, center toolbar, and fuzz modal (UI polish) ([ae74216](https://github.com/branover/hexgraph/commit/ae7421645799caf3ebccd369e85a408b7117e8f8))
* **oracles:** Standard B static — source→sink reachability argument (Phase 4) ([0c6eef8](https://github.com/branover/hexgraph/commit/0c6eef889e2f5c81313b2477bc41e41db23f7dda))
* **oracles:** Standard B static — source→sink reachability argument (Phase 4) ([a6d5877](https://github.com/branover/hexgraph/commit/a6d587791f7cf5b5fd942bfd33bc12c5b9e8cc25))
* Phase 1 dynamic-surfaces backbone — web_app surface + surface_recon + routes_to ([014dac0](https://github.com/branover/hexgraph/commit/014dac018206786f6f487623f32d53743a2f51f2))
* Phase 1 dynamic-surfaces backbone (web_app surface + surface_recon + routes_to) ([d71e3e0](https://github.com/branover/hexgraph/commit/d71e3e04b06d248ef1ac965abf6bbbc38b02b8f8))
* Phase 2 bounded network egress — local-network tier + audit + web_recon ([6bc2bb9](https://github.com/branover/hexgraph/commit/6bc2bb919bfbaa19716e7503ccf08cc3fca3b537))
* Phase 2 bounded network egress (local-network tier + audit + web_recon) ([3b3cf61](https://github.com/branover/hexgraph/commit/3b3cf61a05b08dd176f0c8344072a9e9ada8ea4c))
* **rehost:** auto-register booted device as a remote target + detect service ports ([dca30c4](https://github.com/branover/hexgraph/commit/dca30c46ab67f5f127feba450f7085871b05784f))
* **rehost:** auto-register the booted device as a remote target + detect service ports ([ac10e92](https://github.com/branover/hexgraph/commit/ac10e9224c512a3b42c4e629b651cdefb9e636e2))
* **rehost:** qemu+KVM disk-image rehoster + auto-select by image type ([55cb9a5](https://github.com/branover/hexgraph/commit/55cb9a517aa13a34b26102101d9cfe2ab076bce7))
* **rehost:** qemu+KVM disk-image rehoster + auto-select by image type ([b8b79b6](https://github.com/branover/hexgraph/commit/b8b79b685c44b270f2c4a4ff67f3377f0cf922ac))
* remote fuzz environments (Phase 6) — RemoteDockerExecutor + fuzz-environment concept ([bf6c618](https://github.com/branover/hexgraph/commit/bf6c6183c1fa0dc270a41a1470d67e2215f7e358))
* remote fuzz environments (Phase 6) — RemoteDockerExecutor + fuzz-environment concept ([98897d8](https://github.com/branover/hexgraph/commit/98897d8e2e1fc2f8323c7a109a54836b1ec15c0d))
* **remote:** live remote-device targets over SSH/telnet (live-remote tier) ([cccfb1b](https://github.com/branover/hexgraph/commit/cccfb1b649ba674e1230f3aaf3becd8ef4bbc9c2))
* **remote:** live remote-device targets over SSH/telnet (live-remote tier) ([34f46d8](https://github.com/branover/hexgraph/commit/34f46d83253c332b80897876074508d43c843125))
* resizable + collapsible workspace panels ([3fe687a](https://github.com/branover/hexgraph/commit/3fe687aea5bc23154b0e630c195c03b156c93b58))
* resizable + collapsible workspace panels ([49bfd18](https://github.com/branover/hexgraph/commit/49bfd18d8e5bfb40e5828c46f53e5d4ee5a36aba))
* setup wizard registers MCP server + installs VR skill; fix: just --list truncation ([aec1735](https://github.com/branover/hexgraph/commit/aec17352731cb2581dcca91a58354141dea66d70))
* setup wizard registers MCP server + installs VR skill; fix: just --list truncation ([2f458ba](https://github.com/branover/hexgraph/commit/2f458ba618150f99a74f3aa381fcbc22f4eacffa))
* skeleton-first graph loading for real firmware scale ([056eca8](https://github.com/branover/hexgraph/commit/056eca81636b581d5600932cc1b6c5760b15e9a7))
* source-tree foundation + read-only Source/IDE tab (fuzzing+source Phase 1) ([b11e000](https://github.com/branover/hexgraph/commit/b11e000c695e25b705becd9f9bd5ed7112caa309))
* source-tree foundation + read-only Source/IDE tab (fuzzing+source Phase 1) ([401b147](https://github.com/branover/hexgraph/commit/401b1471fdd0f33f8dc7fa587116d9bb76a852c7))
* strengthen network fuzzer for binary protocols (size/checksum/hex fields); honest docstring ([#115](https://github.com/branover/hexgraph/issues/115)) ([5ccf043](https://github.com/branover/hexgraph/commit/5ccf043c9fc14431540b6a2020c08a9c1a35e9ae))
* surface missing VR-agent capabilities (build_log, add_file_as_target, resume_fuzz_campaign) + skill docs ([a6ba6dc](https://github.com/branover/hexgraph/commit/a6ba6dc8dabc1e023ce53bb22a7a6ba81cce79b5))
* surface missing VR-agent capabilities + close skill docs gaps ([f0d4dc9](https://github.com/branover/hexgraph/commit/f0d4dc9abf2997ab80264cc724c2a5db3c57b0e6))
* **tcp:** raw-TCP live testing + non-HTTP verify_poc + bounded service-launch ([1e97c21](https://github.com/branover/hexgraph/commit/1e97c21dabec6dc8d5e93d790e1aa8c97a2e4913))
* **tcp:** raw-TCP live testing + non-HTTP verify_poc + bounded service-launch ([443a502](https://github.com/branover/hexgraph/commit/443a502f770a23f5ab28e244174064c9dd1c9b83))
* **ui:** deliberate launch + node inspector + task mgmt + provenance polish ([d14aedd](https://github.com/branover/hexgraph/commit/d14aedd6ea183c902b299507532e7391d04e7cd7))
* **ui:** UX refresh — surface the new typed graph + network tier; modernise controls ([0b35a6a](https://github.com/branover/hexgraph/commit/0b35a6a8a5b87e51e453fbab69ccaf1671097d35))
* **ui:** UX refresh — surface the typed graph + network tier; modernise controls ([9794935](https://github.com/branover/hexgraph/commit/97949352e15477ddfb3992130dfb4a0d5cf85770))
* **unpack:** extract rootfs from partitioned full-OS disk images (gap [#1](https://github.com/branover/hexgraph/issues/1)) ([5198355](https://github.com/branover/hexgraph/commit/519835563bba61d057afbced29daf4bce83841c3))
* **unpack:** extract the rootfs from partitioned full-OS disk images (gap [#1](https://github.com/branover/hexgraph/issues/1)) ([b893341](https://github.com/branover/hexgraph/commit/b893341159147f31f1bfeec5e214e4b67e23e5cb))
* **verify:** assurance triple in the engine — the two standards of "verified" (Phase 0) ([2776430](https://github.com/branover/hexgraph/commit/27764307e1c9903eb8effe78d9bb5965d6538452))
* **verify:** compute the assurance triple in the engine (two standards of verified, Phase 0) ([a7aeaf7](https://github.com/branover/hexgraph/commit/a7aeaf7b4751737ced3b4467d0af521c2157708b))
* **verify:** lab-confirmed vs reachable + assurance floor + aim-strictest guidance ([f3a69e8](https://github.com/branover/hexgraph/commit/f3a69e85199134d792cfc71be485701b07c112f2))
* **verify:** lab-confirmed vs reachable, the assurance floor, and aim-strictest guidance ([d4bfefc](https://github.com/branover/hexgraph/commit/d4bfefc30f07478cfabf2807331d0bbcc67e01a4))
* **verify:** unforgeable oracles beyond reflected cmdi — callback, canary_read, oob_write ([b9a0fb3](https://github.com/branover/hexgraph/commit/b9a0fb3b931a3ed54581f6924dfd4f0afa1f8407))
* **verify:** unforgeable oracles beyond reflected cmdi — callback, canary_read, oob_write ([d9f7154](https://github.com/branover/hexgraph/commit/d9f71543489e92c50d0a5ca6430f89c083bbdef2))
* **web:** live route/content discovery — web_discover task (gap [#2](https://github.com/branover/hexgraph/issues/2)) ([e61f78a](https://github.com/branover/hexgraph/commit/e61f78a780dca22beac8ccacc72bdc0ab87a2104))
* **web:** live route/content discovery (web_discover task) (gap [#2](https://github.com/branover/hexgraph/issues/2)) ([8b000cd](https://github.com/branover/hexgraph/commit/8b000cd7b498f23415e4417afa43f5b0fc882012))


### Bug Fixes

* address PR [#64](https://github.com/branover/hexgraph/issues/64) review — ghidra rebuild, core-build exit, dead var ([8a9ae4e](https://github.com/branover/hexgraph/commit/8a9ae4e34fbfbce59d103957f33fc1c2535f1431))
* address PR review — byte-exact network reproducer replay + UDP egress backstop ([6617d0e](https://github.com/branover/hexgraph/commit/6617d0e796897aef9dcc8ef3d2e72f464895989a))
* address PR review — scope makeImage watchdog, heal wrong-group/missing partition node safely, widen port probe ([4f0dcf1](https://github.com/branover/hexgraph/commit/4f0dcf1e2e764e0c5a3bb787c5d3f14d89b89872))
* address PR review — shell-quote remote argv, stream-back ordering, resume env ([cf1072a](https://github.com/branover/hexgraph/commit/cf1072a83a44807f6b75c898017b362c3be41409))
* address review nits — strengthen test + guard multi-instance + comment fixes ([efd58ba](https://github.com/branover/hexgraph/commit/efd58bac41bba72e3f20100a47e0228d2ea6a242))
* address self-review — fetch tier gating, OSS-Fuzz $OUT capture, dead code ([ac316d3](https://github.com/branover/hexgraph/commit/ac316d397a419f9b1cc698baeb1c18e6c1368b35))
* AFL++ source fuzzing on high-ASLR-entropy kernels (ASan/ASLR + persistent-mode) ([8fca78c](https://github.com/branover/hexgraph/commit/8fca78c5bb45952309718583aca5bef88fae650a))
* AFL++ source fuzzing on high-ASLR-entropy kernels (ASan/ASLR shadow collision + persistent-mode hang) ([6d2ef39](https://github.com/branover/hexgraph/commit/6d2ef39928cd492ac55fb3c38d854cfff8458986))
* AFL++ source-fuzz forkserver handshake in the hardened sandbox ([f0dc80c](https://github.com/branover/hexgraph/commit/f0dc80c4aa6056a44782e29533017802732e5873))
* AFL++ source-fuzz forkserver handshake in the hardened sandbox ([898ec8e](https://github.com/branover/hexgraph/commit/898ec8e4697c8a67b537303041cb08c583615684))
* audit rehost boot dest as host:port (urlparse, not rsplit) ([ba4bbb2](https://github.com/branover/hexgraph/commit/ba4bbb2e1140809844c84081533f6b781e1e0ef6))
* author custom build phases as `sh -c <cmd>`, not a shell script path ([17261ae](https://github.com/branover/hexgraph/commit/17261aeb127b633d1efa080b684a06a0aca12128))
* battle-test PR-2 — assurance never-downgrade, PoC-target resolution, agent visibility ([e9a3e9d](https://github.com/branover/hexgraph/commit/e9a3e9d33a0b03a1e39ee75ec2de17fb5cae6048))
* battle-test PR-2 — assurance never-downgrade, PoC-target resolution, agent visibility ([0753521](https://github.com/branover/hexgraph/commit/0753521da3fb539c5158b585af4813f136be6dd7))
* battle-test PR-3 — build→fuzz handoff + coverage/symbolization + verify_fuzz_artifact ([ec487b7](https://github.com/branover/hexgraph/commit/ec487b723b83c628a651adadf4357787c347dab6))
* battle-test PR-3 — build→fuzz handoff + coverage/symbolization + verify_fuzz_artifact ([6ddef89](https://github.com/branover/hexgraph/commit/6ddef89d49d609dabf9e198c03a0035eaf6eed81))
* bound fuzz triage time so minimization can't blow the sandbox timeout ([dac70c9](https://github.com/branover/hexgraph/commit/dac70c9854a0bd7c016c1acdfa048db6424404b4))
* bounded startup grace for launch-and-join fuzzing (PR [#68](https://github.com/branover/hexgraph/issues/68) review [#1](https://github.com/branover/hexgraph/issues/1)) ([8cd66d1](https://github.com/branover/hexgraph/commit/8cd66d1f6ed3200b375cc70d5e503a0264f75625))
* byte recon never runs on a path-less surface target ([7511d15](https://github.com/branover/hexgraph/commit/7511d1514f92b48ff326e8529da0acaf2f7e5c8b))
* byte recon never runs on a path-less surface target ([2a3cc76](https://github.com/branover/hexgraph/commit/2a3cc769726d7b9fb13e88326e9b130de1e9066c))
* **ci:** install into .venv on the docker lane ([47d9fb3](https://github.com/branover/hexgraph/commit/47d9fb33ba8bd7931085a7ae022a9469eec48d59))
* **ci:** pin pip cache-dependency-path to pyproject.toml ([f53c044](https://github.com/branover/hexgraph/commit/f53c0445a008053fe2f8999bb17f050a15a5a5aa))
* clamp liveness reprobes/delay to a bounded range ([570f331](https://github.com/branover/hexgraph/commit/570f33128b4a708a2386920e17adba2543ab338e))
* contain build artifact paths (PR [#51](https://github.com/branover/hexgraph/issues/51) review) ([6806cf7](https://github.com/branover/hexgraph/commit/6806cf7f06ca045daa7a26716a3c073568af064e))
* correct about-edge direction in finding grouping + placement ([2068619](https://github.com/branover/hexgraph/commit/20686199a544953d3d955cab2ce0f0a9a8baecb6))
* correct IoTGoat download URL + robust make iotgoat ([8245edf](https://github.com/branover/hexgraph/commit/8245edf7526dca1259f1d3271661dce1d55af758))
* correct IoTGoat download URL + robust make iotgoat recipe ([5c048b1](https://github.com/branover/hexgraph/commit/5c048b1a05913f8bed7d14c2f795876e458dae07))
* correct setup.sh prereq message to Python 3.11+ ([6e8a920](https://github.com/branover/hexgraph/commit/6e8a92077a082f6863cf7dccb1a64dd3fa258b63))
* **db:** migrate legacy/create_all'd DBs forward instead of stamping head ([2b32877](https://github.com/branover/hexgraph/commit/2b32877fee5a53097fb530993fe872e5210a2cda))
* deflake desock/AFL e2e — retry preeny forkserver race + seed the planted overflow ([a1cb65e](https://github.com/branover/hexgraph/commit/a1cb65e3a6acfaebaf1fadf5309e2b8b1933f780))
* deflake desock/AFL e2e — retry preeny forkserver-startup race + seed the planted overflow ([dfe1565](https://github.com/branover/hexgraph/commit/dfe1565cc2c52e87cfd4311b961ce0baa477f1b2))
* demo must not leak HEXGRAPH_BUILDER/_FUZZER into the caller (PR [#72](https://github.com/branover/hexgraph/issues/72) review) ([21455e7](https://github.com/branover/hexgraph/commit/21455e7e4fc9cdb56b8422293193384373990375))
* detach FuzzArtifact.finding_id on delete_finding (review [#99](https://github.com/branover/hexgraph/issues/99)) ([cbf9636](https://github.com/branover/hexgraph/commit/cbf963628c377a537a1b3de433f508c5ff0f260d))
* don't write host onto the shared socket node (review [#61](https://github.com/branover/hexgraph/issues/61) discussion_r3341331986) ([daba4a7](https://github.com/branover/hexgraph/commit/daba4a78f5bdc44658fe0dff0f8bfe280f337b2f))
* drop the stale cytoscape-expand-collapse ambient type declaration ([143ad71](https://github.com/branover/hexgraph/commit/143ad7126298af039b8d1b96b606d8054f63f108))
* **egress:** expand hostname allowlist entries to resolved IPs (review blocker) ([f3c6600](https://github.com/branover/hexgraph/commit/f3c6600c57d480b5f27778d9744871d268b59ced))
* **firmae:** build sasquatch into the FirmAE image + bump rehost timeout (validated on DVRF) ([12dcf4b](https://github.com/branover/hexgraph/commit/12dcf4bcbedaff72ab782af57192a151edae7c65))
* **firmae:** sasquatch + timeout + brand inference — FirmAE branch validated on real DVRF ([d6ae0e1](https://github.com/branover/hexgraph/commit/d6ae0e1ee30ee3ed4a1dbe05a5c4575de67d37a3))
* from-source build links for both engines + legible build-result UI ([048b496](https://github.com/branover/hexgraph/commit/048b496b459eef6098acdc1d305d5ba531041f3b))
* from-source build links for both engines + legible build-result UI ([fbc3cd7](https://github.com/branover/hexgraph/commit/fbc3cd74fa0df9942a12a1324c92306ccc70872a))
* gate source-tree writes on the editable flag, not origin ([33b544a](https://github.com/branover/hexgraph/commit/33b544a6150c9cc389c7b7e82d36201b219683f1))
* graph-canvas interaction & layout bugs on the merged redesign ([4407ff9](https://github.com/branover/hexgraph/commit/4407ff9ef41520cd7fb3403604d4ee0ac18eb07c))
* graph-canvas interaction & layout bugs on the merged redesign ([5ee1689](https://github.com/branover/hexgraph/commit/5ee1689627ad2c5b5a31ac64ded97a9f56c21dec))
* graph-canvas UX round 2 — zoom feel, native menu, expand animation, source-file layer, room label ([1b35e8b](https://github.com/branover/hexgraph/commit/1b35e8b35fb1bedb3c90b755eeb4d9a73a9a9d59))
* graph-canvas UX round 2 (zoom feel · native menu · expand animation · source-file layer · room label) ([c69a0d7](https://github.com/branover/hexgraph/commit/c69a0d708cf8d340f839735335ecd0ce976c2377))
* **graph:** guard dangling edges + rework the bottom control cluster ([dd9c485](https://github.com/branover/hexgraph/commit/dd9c485eb3c71f5fcc4af6a3eb53ae153340503d))
* handle None artifact in SandboxTimeout message for channel probes ([d6b068f](https://github.com/branover/hexgraph/commit/d6b068f54866530cc7758598edbfc64106ddd326))
* harden FirmAE rehost boot against the makeImage silent hang ([8622af6](https://github.com/branover/hexgraph/commit/8622af62a28d54d20fa2c3f3d7c1f9cc0e0344a0))
* harden FirmAE rehost boot against the makeImage silent hang ([e80206a](https://github.com/branover/hexgraph/commit/e80206a344ea47e6bbd0aea6eee09e98604f0af1))
* harden operator-machine trust boundary (Host/CSRF guard + creds off docker argv) ([c0fe6fa](https://github.com/branover/hexgraph/commit/c0fe6fa144deca598652b55ed715b962016aebcc))
* harden operator-machine trust boundary (Host/CSRF guard + creds off docker argv) ([b0f995e](https://github.com/branover/hexgraph/commit/b0f995e809abd59949912d6ad23fce9037dd2406))
* legend isolate click-to-clear must clear while still hovering ([e766313](https://github.com/branover/hexgraph/commit/e7663134a209473065eb610e86cb15aa58c109d6))
* let serve respect ambient HEXGRAPH_HOST/PORT (review #discussion_r3335047069) ([e8c7fe1](https://github.com/branover/hexgraph/commit/e8c7fe1d15fb3485e483d639da0b5433c62cfbdb))
* let the worker re-symbolize already-ingested crash reps that lack frames ([#121](https://github.com/branover/hexgraph/issues/121)) ([1643042](https://github.com/branover/hexgraph/commit/16430422af8b028cecf39c7361db4a8fb7d55229))
* make FirmAE rehost boot budget configurable for slow MIPS images ([3be4c8d](https://github.com/branover/hexgraph/commit/3be4c8def12b022adc4b8bdc457af16d81970774))
* make FirmAE rehost boot budget configurable for slow MIPS images ([ff4074e](https://github.com/branover/hexgraph/commit/ff4074ec7dfdff0d104c6933c7eb898f29ff01ba))
* make launch_command robust and harden ASan service launch ([#114](https://github.com/branover/hexgraph/issues/114)) ([4c413b7](https://github.com/branover/hexgraph/commit/4c413b7469a3e2d0a42b81c176846abe88792e88))
* make Promote→PoC verify (or guide), not silently seed ([c92dcc8](https://github.com/branover/hexgraph/commit/c92dcc8c252a699383550ac5d932a99dcaf76953))
* make Promote→PoC verify (or guide), not silently seed ([63e65aa](https://github.com/branover/hexgraph/commit/63e65aa679913128869aa348af333ca3a6b416df))
* make the code block the horizontal scroller (review [#62](https://github.com/branover/hexgraph/issues/62)) ([fa7ac87](https://github.com/branover/hexgraph/commit/fa7ac87644024fd3f273187c1af12f2b9e4c2e0e))
* make the sandbox /out bind-mount writable for any host uid ([8bfd5b0](https://github.com/branover/hexgraph/commit/8bfd5b044a28850add2cb71f913980d618b0bccf))
* make the sandbox /out bind-mount writable for any host uid ([d14bdb3](https://github.com/branover/hexgraph/commit/d14bdb386f30dcfd9775cee0fb11e3d06d3aad3a))
* Map card territory + skeleton severity heat (VIEW-02, GRAPH-01) ([c94d6b9](https://github.com/branover/hexgraph/commit/c94d6b9a19a3859818c5fcad504811c4d1da7a6f))
* Map collapses to a card territory + skeleton severity heat pops (VIEW-02, GRAPH-01) ([239a4bd](https://github.com/branover/hexgraph/commit/239a4bd97cdf35b15e643419bf5c5db4e3a85b44))
* namespace ingested artifacts by target id (basename collision → graph corruption) ([f98dd63](https://github.com/branover/hexgraph/commit/f98dd63d3c97065480a8d1ff5ad83a56ad71dde0))
* namespace ingested artifacts by target id to prevent basename collision ([084567d](https://github.com/branover/hexgraph/commit/084567de6e5b5f7ef88d50aa9f94e579cfc43d72))
* normalize sanitizer label and symbolize crash representatives ([#112](https://github.com/branover/hexgraph/issues/112)) ([86f8a56](https://github.com/branover/hexgraph/commit/86f8a562ff60d259aaf62aeafb6016d00267b5f9))
* **oracles:** close the reflection-forgery holes the review found ([5e2bcd7](https://github.com/branover/hexgraph/commit/5e2bcd7af3d19be4358df819bd39edfd965c50ce))
* **oracles:** min-length guard so reflection-strip never over-strips a legit secret ([5cd05d3](https://github.com/branover/hexgraph/commit/5cd05d3a5cfaa3c90dfd647b567998b6d8b2c4da))
* **oracles:** strip method + request keys; known ground-truth via file channel only ([be1364e](https://github.com/branover/hexgraph/commit/be1364e8c6f59a8ce9d1689cd52ac7ff2dc23f30))
* **oracles:** strip the WHOLE request (headers/json/nested) + the known read-back ([2be3b99](https://github.com/branover/hexgraph/commit/2be3b99dc25fcebf19b6abb55038a2f46c029ead))
* populate fuzz campaign edges_covered + stream live progress ([6c43300](https://github.com/branover/hexgraph/commit/6c43300966bea17f35316a83cafe84ebbbe06943))
* populate fuzz campaign edges_covered + stream live progress ([f912a29](https://github.com/branover/hexgraph/commit/f912a293a3cd28878785b8491716a600c9268305))
* preserve original PoC spec on re-verify; harden http_probe dest check ([a5bcf5f](https://github.com/branover/hexgraph/commit/a5bcf5f7ada7774708f8b6b511bde219096026ad))
* **rehost:** build FirmAE correctly (binwalk 2.3.4 from source, in-container postgres) ([45fa9d6](https://github.com/branover/hexgraph/commit/45fa9d6cb81712eb53741c74651aee3ca70e0dbf))
* **rehost:** carry scheme through qemu marker so HTTPS-only guests register as https:// ([c5419d5](https://github.com/branover/hexgraph/commit/c5419d57f43ffd1c28aebab20a20424e2edf81e2))
* **rehost:** working FirmAE image + loop self-heal + graceful teardown ([b021a72](https://github.com/branover/hexgraph/commit/b021a72b3afcd94e487baf1a07a31ba6146f554d))
* **rehost:** working FirmAE image + loop self-heal + graceful teardown; document OpenWrt limit ([8713368](https://github.com/branover/hexgraph/commit/871336839c3f766d373a6291f8b104a286abfbec))
* relaunch launch-and-join service when verifying a network crash (F6) ([#116](https://github.com/branover/hexgraph/issues/116)) ([468c945](https://github.com/branover/hexgraph/commit/468c945b9479bb3c8456afbeee79ea96dd4990c6))
* render binary PoC env via the env utility so a hostile env key can't inject ([c057d4f](https://github.com/branover/hexgraph/commit/c057d4fdb15a80f29ec56134cfdae089a7de0c54))
* render the collapse-all rail button glyph (chip, not the empty firmware_image) ([af81a4a](https://github.com/branover/hexgraph/commit/af81a4a68d48db42851f7046c09a536bafe78100))
* resume_campaign must not leak a dangling fuzzed_by edge / orphan task ([6fe3e30](https://github.com/branover/hexgraph/commit/6fe3e3039fe4318709a261a2c119a21a2b24ee06))
* review — replay coverage corpus per-file so one crashing input can't suppress the whole map ([b60c1ec](https://github.com/branover/hexgraph/commit/b60c1ecd7a771afa4bc56f3552e58722e08835b6))
* review — stop ArtifactsViewLoader polling after finalize; keep 0.0 coverage % ([2be0001](https://github.com/branover/hexgraph/commit/2be00016344092121fd50b6b6d35b5a27edc7983))
* **review:** derive __version__ from package metadata (single source) ([c87b06b](https://github.com/branover/hexgraph/commit/c87b06beb7bdcc00addad89bb5527ba0af34fa44))
* **review:** grant /out via --group-add + 0o770, not world-writable ([4d53f3d](https://github.com/branover/hexgraph/commit/4d53f3d0771d1526e1c75c09e7486d6a7dac7f74))
* Run menu advertises kind-valid tasks for surface targets ([e4d6e8f](https://github.com/branover/hexgraph/commit/e4d6e8fb7156f5b6cc2e2675858e4fdca43664cb))
* Run menu advertises kind-valid tasks for surface targets ([7516eef](https://github.com/branover/hexgraph/commit/7516eef21d65b692f120ee2876ad98a9955c7661))
* **security:** address review — IPv6-loopback Host, same-site CSRF, Executor seam ([797c9e3](https://github.com/branover/hexgraph/commit/797c9e35ed8e5427193bcb8bcf3fc8f6abc5055c))
* setarch personality fallback + stale-engine ASLR diagnostic (N3, N1-compat) ([#120](https://github.com/branover/hexgraph/issues/120)) ([bb92777](https://github.com/branover/hexgraph/commit/bb9277795b188f874733a9402e26ed5bf5920062))
* showcase fuzz target links cleanly and finds a real crash ([3a0c117](https://github.com/branover/hexgraph/commit/3a0c117ccd37f3a370df138caf12277bd610ddab))
* showcase fuzz target links cleanly and finds a real crash ([b5470e2](https://github.com/branover/hexgraph/commit/b5470e295dd6adde0b002bb708137f70253aea31))
* survive a broken XDG_RUNTIME_DIR; add a no-just setup.sh ([078b997](https://github.com/branover/hexgraph/commit/078b997e7fe24733874fe1b1715c4e1c7a645017))
* survive a broken XDG_RUNTIME_DIR; add a no-just setup.sh ([e7d10e4](https://github.com/branover/hexgraph/commit/e7d10e4cd718ba7dbe31101d096558b99820f2e2))
* **test:** gate two verify-path tests on SANDBOX_READY ([daae4ad](https://github.com/branover/hexgraph/commit/daae4ad79e666db241f8472fe4c6f5b796cc606e))
* treat launch-and-join container exit as the verified-DOWN oracle on network re-verify ([#122](https://github.com/branover/hexgraph/issues/122)) ([f000f19](https://github.com/branover/hexgraph/commit/f000f19f0132421b63815d9ad9121914e1171c45))
* warn on the container-bind bypass (audit F1) + onboarding doc fixes ([d237f5a](https://github.com/branover/hexgraph/commit/d237f5a2ab890574a4518fc03b40a79a593ec92e))
* warn on the container-bind bypass + onboarding doc fixes ([33243c3](https://github.com/branover/hexgraph/commit/33243c345104aa96c490a29f6f4ba0632c75423b))
* **web-poc:** reject reflected payloads in body_contains oracle (forged-PoC bug) ([8c0a7d8](https://github.com/branover/hexgraph/commit/8c0a7d878be3a3469ffcb527c4ce3162b4e8757e))
* **web-poc:** reject reflected payloads in the body_contains oracle (forged-PoC bug) ([8a59640](https://github.com/branover/hexgraph/commit/8a59640602a9fa4e311d653be8972c73843f71c7))
* **web:** http_probe accepts self-signed TLS; qemu rehoster registers the real UI ([9e28595](https://github.com/branover/hexgraph/commit/9e28595eb2c947b19997325fa720f1a9f20febfa))
* **web:** http_probe accepts self-signed TLS; qemu rehoster registers the real UI not a redirect ([19ed273](https://github.com/branover/hexgraph/commit/19ed273fdb1b99d6db2fe7d48cf3c785b5af2245))


### Documentation

* accuracy + streamlining pass (README/CLAUDE/PROGRESS) ([38688b3](https://github.com/branover/hexgraph/commit/38688b3744253d4e3c2f6b154af3b25b61ca4078))
* add DISCLAIMER and THIRD_PARTY_NOTICES ([db77be3](https://github.com/branover/hexgraph/commit/db77be3e487b232349955c3f27020a90590ccebe))
* add DISCLAIMER and THIRD_PARTY_NOTICES ([d435eed](https://github.com/branover/hexgraph/commit/d435eed623e419174e11bb3e5cac43dd2b1d9cd2))
* add first-class fuzzing + source/build management design (council synthesis) ([928f358](https://github.com/branover/hexgraph/commit/928f358c258deddf0a1852b97daa2d52270813fc))
* add git-worktree + PR + concurrency workflow to CLAUDE.md ([e755e7d](https://github.com/branover/hexgraph/commit/e755e7dafc4e2b86133feb5fce28b8458fe691ed))
* add harness-authoring guidance and network-engine/source-edit notes to fuzzing.md ([#111](https://github.com/branover/hexgraph/issues/111)) ([c7dbd0a](https://github.com/branover/hexgraph/commit/c7dbd0a3d8c0bcaa20bd93a63287c961001b668d))
* add HexGraph design vision (v2 target shape) ([2cc3101](https://github.com/branover/hexgraph/commit/2cc31011fa4ec68aea4e7b50a3be942b9271bede))
* add living UX behavior contract + two-role agent-driven assessment skill ([2f87803](https://github.com/branover/hexgraph/commit/2f8780304f096f66d4d72aa8896a78f9192e11ae))
* add resource governance knobs + remote fuzz environments (§5.8) ([c8cd18c](https://github.com/branover/hexgraph/commit/c8cd18c74080c6f0589118586d45e1fd0a95cc0d))
* add the two standards of 'verified' (code-present vs input-reachable) ([c30584c](https://github.com/branover/hexgraph/commit/c30584c2a73535dd5d61ae61fdb79e537351558c))
* add user-facing README (full structure; unbuilt features flagged) ([a0f1cd6](https://github.com/branover/hexgraph/commit/a0f1cd64315555a1a4542e51689d09705d85fd8e))
* add v2 implementation plan (P0–P8) from the design vision ([a3e07c6](https://github.com/branover/hexgraph/commit/a3e07c6d80003ba645fad7bacbb0312562314e81))
* align setup.sh serve hint with the README (.venv/bin/hexgraph serve) ([473d8fb](https://github.com/branover/hexgraph/commit/473d8fb36b0ec55f7a92ae9df568cc729d517b8b))
* bring CLAUDE.md and PROGRESS.md up to date (MVP complete) ([728a988](https://github.com/branover/hexgraph/commit/728a988619b4480e65924ab3b220fe9d9f318e51))
* capture UI improvement backlog from visual review ([c0cb1f7](https://github.com/branover/hexgraph/commit/c0cb1f7a9735e9d125903a343bf9c1516405ad69))
* clarify the merge gate — the initiator launches the PR-review subagent ([ee9bdb5](https://github.com/branover/hexgraph/commit/ee9bdb573ed0c2a267e44f6bb05d88c6a7c7ffff))
* **CLAUDE.md:** capture Playwright workflow for visual UI assessment ([db17056](https://github.com/branover/hexgraph/commit/db17056d47810fb8ebd88c36bb2308d146bb45bb))
* condense CLAUDE.md to rules+orientation; record session in PROGRESS ([1f14ea5](https://github.com/branover/hexgraph/commit/1f14ea5e9d1b06eebb315dfc67225df8edf810c1))
* correct stale verify_poc assurance comment to reflect scope-aware standard ([e8d9ecc](https://github.com/branover/hexgraph/commit/e8d9ecc68faaa35cabdf976e6899e8aa847c64cf))
* design for dynamic & networked attack surfaces (web/live/rehost) ([227dbbc](https://github.com/branover/hexgraph/commit/227dbbc02270afb290f10e92a1659ce63db1fe10))
* design for dynamic & networked attack surfaces (web/live/rehost) ([92546c4](https://github.com/branover/hexgraph/commit/92546c470ba0f1f3d3e7c9f7262bad5781db6ee8))
* design for verification oracles beyond command-injection ([38c041c](https://github.com/branover/hexgraph/commit/38c041c4d1cb40037301a2e9363761a5afbe0754))
* evaluate UI as a human would + single docs/images screenshot convention ([7f23eb6](https://github.com/branover/hexgraph/commit/7f23eb697e8558a5f8ea655455cc39fa62d6892b))
* evaluate UI as a human would + the single docs/images screenshot convention ([31bfbb3](https://github.com/branover/hexgraph/commit/31bfbb32ffd23645ded6f5bbdabe9fc220b75f4c))
* first-class fuzzing + source/build management design (council synthesis) ([a8305b5](https://github.com/branover/hexgraph/commit/a8305b567bb8f202501507041345bbd56fe8ede6))
* fix two markdown staleness issues (test count, dangling link) ([c273b86](https://github.com/branover/hexgraph/commit/c273b86b1dbcba2df5054f8195bc1b82e5d64bf5))
* fix two staleness issues found in a markdown audit ([84b52b6](https://github.com/branover/hexgraph/commit/84b52b6b13fbffcb187f88ae0d0d4eaad63cc701))
* git-worktree + PR + concurrency workflow in CLAUDE.md ([34f08a9](https://github.com/branover/hexgraph/commit/34f08a928e09751a9a8fe0ea6130c13561717e7b))
* graph-presentation redesign (council synthesis) — held reference for phased impl ([af09a66](https://github.com/branover/hexgraph/commit/af09a66d46cd2882661aaa1d5a604586ceb35e96))
* graph-presentation redesign design (council synthesis) ([66f5ec5](https://github.com/branover/hexgraph/commit/66f5ec55e1153ceadadfa48fb8c62150702b6fa9))
* living UX behavior contract + two-role agent-driven assessment skill ([ccf030f](https://github.com/branover/hexgraph/commit/ccf030f4e82c7ae47c627eb0f36f2814e3185a22))
* log the live-device + rehosting-engagement track (gaps [#1](https://github.com/branover/hexgraph/issues/1)/[#2](https://github.com/branover/hexgraph/issues/2), remote tier, FirmAE/DVRF) ([21750ca](https://github.com/branover/hexgraph/commit/21750cade56187ee8cf8d78b67df6a2b67fb8a1b))
* log the live-device + rehosting-engagement track in PROGRESS.md ([0f0ae92](https://github.com/branover/hexgraph/commit/0f0ae92bcdd244c4f28d5a46f2add036d6b8c378))
* log the recon-surface fix in PROGRESS (merge-gate completeness) ([1529e25](https://github.com/branover/hexgraph/commit/1529e25904c1735b3b159efeb0fed2dd49f86c0c))
* merge gate — the initiator launches the PR-review subagent ([6accfe5](https://github.com/branover/hexgraph/commit/6accfe58385b060471e671d0cfd82787b90f40f0))
* move the internal ui-backlog ledger to docs/dev/ ([e36b8fa](https://github.com/branover/hexgraph/commit/e36b8fa69fe7c644f932fa7772c395ba5d3ebfcf))
* move the internal ui-backlog ledger to docs/dev/ ([8c8a06b](https://github.com/branover/hexgraph/commit/8c8a06bbd583cf325693b0d31af43db28512a6d4))
* note grep is aliased to ripgrep on this system ([585188d](https://github.com/branover/hexgraph/commit/585188d545fb7171abdd20a6d2d34ca5078dbf92))
* note that grep is aliased to ripgrep on this system ([dfe1db0](https://github.com/branover/hexgraph/commit/dfe1db0e737bbaedec70563a828e4d2f67646b63))
* note the demo env-leak fix in PROGRESS ([e484b2d](https://github.com/branover/hexgraph/commit/e484b2d53a18adedacf425976d07da16e4860fc8))
* post-merge cleanup deletes branches locally AND remotely ([ef236e0](https://github.com/branover/hexgraph/commit/ef236e09a9de7e8dce78b4d0d5b536585baf670d))
* post-merge cleanup must delete branches locally AND remotely ([db1901d](https://github.com/branover/hexgraph/commit/db1901dddb16ad96e3b97fbbb8a4d859abd259b8))
* PROGRESS.md — get_finding, bypasses edge, auth-bypass round ([7dc821b](https://github.com/branover/hexgraph/commit/7dc821ba3ed1d8b43b2a60f9cad53df540b29625))
* PROGRESS.md — n-day tools, vantage challenge, build.sh/answer-key, 229 tests ([da35f2f](https://github.com/branover/hexgraph/commit/da35f2f775f7fc52e9a1dde2caa8097fee1a07ec))
* record autonomous-session work; fix stale probe-rebuild discipline ([b551f45](https://github.com/branover/hexgraph/commit/b551f45c8eb0be093bab508b87ef3e71ca5e23f9))
* record code-review [#44](https://github.com/branover/hexgraph/issues/44) IoTGoat live-web-RCE engagement outcome ([3226ea4](https://github.com/branover/hexgraph/commit/3226ea423256a181ebadd390befbf2facda538e4))
* record code-review [#44](https://github.com/branover/hexgraph/issues/44) IoTGoat live-web-RCE engagement outcome ([d95e8cb](https://github.com/branover/hexgraph/commit/d95e8cbc483544b8da58daf571e05c44fb5e4e65))
* record coding-agent (MCP) integration + VR-eval UX pass in CLAUDE/PROGRESS ([7650d8a](https://github.com/branover/hexgraph/commit/7650d8a67b2e54cbdf6b754cb4ffdd9da46c2189))
* record fuzzing / target-removal / firmware-FS in CLAUDE.md + PROGRESS.md ([a320cef](https://github.com/branover/hexgraph/commit/a320cef96ee90717771776dd7d2e4c1bbc765f0b))
* record LLM tool-use / agent loop in CLAUDE.md + PROGRESS.md ([86b082b](https://github.com/branover/hexgraph/commit/86b082b5bbbc6ac18de977878f862eb246b7ec0d))
* reframe static-only as enforced-default + PR-review comment logging ([d41c031](https://github.com/branover/hexgraph/commit/d41c031980c6a79a887ac8429695a2e64b066f5e))
* reframe static-only as enforced-default + require PR-review comment logging ([dfbc26c](https://github.com/branover/hexgraph/commit/dfbc26c215154f194a8537afcd271d3edffbaa7b))
* refresh screenshots at 1440p with the critical finding in the hero ([f444930](https://github.com/branover/hexgraph/commit/f444930b3f201f5acfeada8e3eae6562d0c75c08))
* regenerate showcase screenshots for the current UI ([429ee0a](https://github.com/branover/hexgraph/commit/429ee0aa1caaa8b89d452733462f158eb76127d8))
* regenerate showcase screenshots for the current UI ([f1b8216](https://github.com/branover/hexgraph/commit/f1b82167a334c7fc4d4bcbe0c367a033364a8c7b))
* remove PROGRESS.md and the engagement answer key ([86dd7cf](https://github.com/branover/hexgraph/commit/86dd7cf13553a4674775a414fe16b45add65568c))
* remove PROGRESS.md and the engagement answer key ([d595e6c](https://github.com/branover/hexgraph/commit/d595e6cccbb698116b4a1d3e49376935726ea08f))
* repoint live RESUME-HERE links to docs/design/ after the move ([8f0c020](https://github.com/branover/hexgraph/commit/8f0c020e3e7a9c7a6cbea219073d7f6ee22c9821))
* restructure docs/, humanize the user-facing set, codify the voice ([9b10379](https://github.com/branover/hexgraph/commit/9b10379a29f111e2b6b806487d208520c8acf92c))
* restructure, humanize the user-facing set, codify the voice ([1daf764](https://github.com/branover/hexgraph/commit/1daf764ab9f3eeb4215c9f9bddb7cdbfa944b3c4))
* **runner:** note the shared-primary-group caveat for the 0o770 out-dir ([1bf810a](https://github.com/branover/hexgraph/commit/1bf810a845652a5f7db0e63cb78014ce6833f8fc))
* scrub the last PROGRESS reference in the merge-gate checklist ([9c9becd](https://github.com/branover/hexgraph/commit/9c9becd4c9fcb832068d088664387cfe22d68d9f))
* select the critical finding in the README hero screenshot ([c2249cf](https://github.com/branover/hexgraph/commit/c2249cf7c0bc83f3cf6e2c7c1d2bb3ae68fbc014))
* slim README + per-feature docs, single-folder screenshots, fix hero-3 ([1fe355d](https://github.com/branover/hexgraph/commit/1fe355d7b457a733ee2744ca02abf6ab3ec2b0ad))
* slim README + per-feature docs, single-folder screenshots, fix hero-3 ([3acfd78](https://github.com/branover/hexgraph/commit/3acfd78889f116ab89391733aefaf83bd4f246ea))
* spawn review subagents with the review skills declared ([#117](https://github.com/branover/hexgraph/issues/117)) ([d0c6927](https://github.com/branover/hexgraph/commit/d0c692737933dfcae3a856d1feb2c50971ca7e86))
* sync CLAUDE.md/README.md/PROGRESS.md + complete MCP tool surface ([3d3cb75](https://github.com/branover/hexgraph/commit/3d3cb75de3b4c3330b082185fb54ad8b988887b1))
* sync CLAUDE.md/README.md/PROGRESS.md with new features; complete MCP tool surface ([a1723b6](https://github.com/branover/hexgraph/commit/a1723b62a03010b73cc3edcf6c76858f26934d30))
* use precise features.*.enabled keys in the tier table (review nit) ([dd7aed5](https://github.com/branover/hexgraph/commit/dd7aed5aebdf98feb56b22d81c490e3304d9ffb7))
* **ux-contract:** reflect the reworked graph controls; tidy a css comment ([d3ac2e1](https://github.com/branover/hexgraph/commit/d3ac2e1da3745b64e79d193e3e01d84f9aba599e))
* verification-oracles design (prove vuln classes beyond cmdi) ([a13dc92](https://github.com/branover/hexgraph/commit/a13dc92003cb7c9defb521a3b81756455fa87073))

## [Unreleased]

### Added
- **`setup.sh`** — a no-`just` bootstrap, now the single source of truth for the setup
  sequence (venv + deps + web-UI build, then the interactive setup wizard). `just setup` is a
  thin wrapper that calls it, so the two paths can't drift. For people who would rather not
  install the `just` task runner. Arguments pass through to the wizard, so `./setup.sh --yes`
  takes the static-only defaults without prompting.

### Changed
- `just setup` now forwards flags straight through to the wizard, so the non-interactive
  invocation is **`just setup --yes`** (or `--non-interactive` / `--defaults` / `--rebuild`).
  The old `just setup yes=1` form never actually bound the parameter — `just` parsed `yes=1`
  as a positional value, so it only reached the baseline via the no-TTY fallback; use `--yes`
  instead.

### Fixed
- `just setup` (and any other shebang recipe) no longer fails with `error: I/O error in
  runtime dir` in environments where `$XDG_RUNTIME_DIR` points at a directory that doesn't
  exist and can't be created — minimal containers, `cron`, `su` without a login session, or
  a WSL shell with no systemd user session. The justfile now pins `just`'s temp dir to a
  writable location (`set tempdir := "/tmp"`).

## [0.1.0] — 2026-06-03

The first tagged, public pre-release. HexGraph is a self-hosted, local-only workbench for
AI-assisted vulnerability research: you point it at a binary or a firmware image, and it
ingests the target, pulls firmware apart into its component binaries, runs AI-driven
analysis tasks using your own model access, and records every result as a structured
**finding** in a typed, SQLite-backed graph. A loopback web UI browses the graph, launches
tasks, and triages findings; the same primitives are available to a coding agent over MCP.

Everything below has been built and exercised end to end, but this is pre-1.0 software and
the rough edges are real.

### The core loop
- Ingest a target, run recon, drive AI analysis, emit a structured finding against the
  frozen `finding.schema.json`, write it into the graph, and spawn the next task it
  suggests. `just demo` runs the whole loop offline, for $0, and exits 0.

### What's in it
- **Local-only and self-hosted.** The API and UI bind `127.0.0.1` and refuse otherwise; no
  telemetry, no auto-update pings, nothing calls a HexGraph-operated server.
- **Bring your own key, or nothing.** A mock backend (the default) runs the full loop with
  no key and no network; an Anthropic BYOK backend and a local Claude Code backend are the
  paid paths. Secrets are read on demand and never logged, stored, or returned.
- **Every target is treated as hostile.** All handling of target bytes happens inside a
  disposable Docker sandbox (`--network none`, read-only root, dropped capabilities,
  resource caps, a hard timeout). The model only ever sees tool output, never raw bytes.
- **A typed, attributed knowledge graph** of targets, functions, sockets, endpoints,
  hypotheses, and findings, with node dedup and a network map of shared sockets.
- **Graduated, opt-in capability.** Static-only is the enforced default; execution
  (PoC/fuzzing), bounded network egress, source builds, audited dependency fetch, firmware
  rehosting, remote live devices, and remote fuzz compute are each a separate opt-in that
  relaxes the single policy seam and nothing else.
- **Verification and an assurance ladder.** Findings carry an assurance level, and opt-in
  PoC verification executes the target against an unforgeable nonce oracle, foreign-arch
  included, under qemu-user.
- **Coverage-guided, surface-aware fuzzing** (AFL++, libFuzzer, qemu-mode, boofuzz, desock)
  with detached, crash-safe campaigns, dedup, minimization, and one-click re-verification —
  optionally on a remote compute host you own.
- **Build from source** into instrumented, reproducible artifacts through a recorded
  recipe, with an in-browser Source/IDE tab and coverage shading.
- **Dynamic surfaces, rehosting, and remote**: model a running web service or a raw-TCP
  daemon as a first-class surface, boot a whole firmware image under full-system emulation,
  or assess a physical device over SSH/telnet, all with bounded, audited egress.
- **Real vendor-firmware extraction** (sasquatch, jefferson, ubi_reader, sleuthkit, binwalk)
  and **MCP integration** in both driver and delegate modes.

### Project / release engineering
- Continuous integration (offline test matrix, frontend build, dependency audit, and a
  live-Docker lane that actually exercises the sandboxed egress/exec/rehost paths).
- Open-source onboarding: `SECURITY.md`, `CONTRIBUTING.md`, a code of conduct, and issue /
  PR templates.

### Known limitations
- Pre-1.0: interfaces and the data model may change between minor versions (the project DB
  migrates forward and is never silently reset).
- Single-user, local, self-hosted by design. It is not hardened for multi-tenant or
  internet-facing use; do not expose an instance to untrusted users or networks.
- The heavier dynamic features (rehosting, KVM disk-image boot, remote devices) need extra
  host capabilities (privileged containers, `/dev/kvm`) and are the most operationally
  involved to run.

[0.1.0]: https://github.com/branover/hexgraph/releases/tag/v0.1.0
