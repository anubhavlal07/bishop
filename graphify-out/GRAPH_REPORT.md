# Graph Report - Bishop  (2026-09-05)

## Corpus Check
- 207 files · ~152,860 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 2307 nodes · 5448 edges · 115 communities (95 shown, 10 thin omitted)
- Extraction: 90% EXTRACTED · 10% INFERRED · 0% AMBIGUOUS · INFERRED: 547 edges (avg confidence: 0.71)
- Token cost: 255,737 input · 0 output

## Community Hubs (Navigation)
- CLI and Run Orchestration
- Human Approval Gate Demo
- Quarantine Trust Boundary
- Injection Signal Scoring
- Graph State and Alert Schema
- Detector Contract and Maths
- FastAPI Endpoint Surface
- Corpus and Holdout Builders
- Trusted-Block Confusion Attacks
- Deployment Configuration Guards
- Fence Rendering and Field Budget
- Audit Actions and Ingest Node
- Endpoint Detectors
- Identity Detectors
- Bring-Your-Own-Key Providers
- Graph Assembly and Response Planning
- Model Provider Interface
- Credential Validation and SSRF Guard
- Endpoint Detector Tests and Catalogues
- Incident Store Schema
- Console Dependencies
- Injection Test Fixtures
- Mitigating Context Detectors
- TypeScript Build Config
- Environment Policy Loading
- Prompt Assembly and Grounding
- Investigator Documentation
- API Security Middleware Tests
- Synthesis and Adversarial Critic
- Alert Normalisation
- Human Gate Decision Parsing
- API Integration Tests
- Console Evidence Panel
- Pipeline Test Harness
- Auth, Rate Limit and Headers
- Injection Corpus Recall
- Ingest Normaliser Tests
- Console Pages and Primitives
- Production Config Enforcement
- Deterministic Mock Model
- Mocked Response Execution
- Deployment and Console Docs
- Architecture Decisions
- Incident Persistence Round-Trip
- Console Triage and Detector Pages
- Coverage Reporting
- Run Manager and SSE Stream
- Audit Chain Append Tests
- Console Layout and Model Gate
- Quarantine Laundering Paths
- Audit Chain Operations
- MITRE ATLAS Mapping
- ATT&CK Catalogue Validation
- Threat Intel Cache
- DNS Exfiltration Detection
- Outbound Volume and Beaconing
- Catalogue Loading
- Audit Chain Verification
- Fence Integrity Attacks
- Untrusted Input Trust Boundary
- Test Pipeline
- Test Byok
- Test Purity
- Test Gate
- Threat Model
- Coverage
- Adr 002 Deterministic Detectors
- Test Validation
- Test Pipeline
- Topology
- Logging Setup
- Test Endpoint
- Test Third Party And Gate
- Deployment
- Architecture
- Catalogue
- Test Endpoint
- Test Ingest
- Test Security
- Test Denial Of Analysis
- Chain
- Test Ingest
- Chain
- Test Byok
- Test Ingest
- Test Ingest
- Ci
- Render Terminal Svg
- Test Identity
- Test Store
- Build Attck Catalogue
- Test Validation
- Normalise
- Test Store
- Test Escalation Is Ioc
- Types
- Normalise
- Test Chain
- Fetch Datasets
- Next Config
- Next Env D
- Record Demo
- Normalise
- Init
- Pyproject

## God Nodes (most connected - your core abstractions)
1. `alert()` - 114 edges
2. `Alert` - 79 edges
3. `DetectorResult` - 59 edges
4. `DeploymentSettings` - 50 edges
5. `Process` - 50 edges
6. `BishopModel` - 45 edges
7. `quarantine_alert()` - 43 edges
8. `proc()` - 39 edges
9. `credential_theft_alert()` - 35 edges
10. `build_graph()` - 34 edges

## Surprising Connections (you probably didn't know these)
- `Three-Direction Grounding Rule` --semantically_similar_to--> `Symmetric Detector Grounding`  [INFERRED] [semantically similar]
  README.md → docs/THREAT-MODEL.md
- `What This Doesn't Do` --semantically_similar_to--> `Residual Risk`  [INFERRED] [semantically similar]
  README.md → docs/THREAT-MODEL.md
- `graph()` --calls--> `build_graph()`  [INFERRED]
  tests/graph/conftest.py → src/bishop/graph/build.py
- `The LLM Reasons; Unit-Tested Python Decides` --conceptually_related_to--> `ADR-002: Deterministic Detectors Beneath the Model`  [INFERRED]
  README.md → docs/decisions/ADR-002-deterministic-detectors.md
- `The Agent Is an Attack Surface` --semantically_similar_to--> `Bishop Is Itself an Attack Surface`  [INFERRED] [semantically similar]
  README.md → docs/THREAT-MODEL.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **The Bishop Triage Pipeline** — docs_architecture_ingest, docs_architecture_triage_supervisor, docs_architecture_synthesis, docs_architecture_adversarial_critic, docs_architecture_response_planner, docs_architecture_response_gate, docs_architecture_response_execute, docs_architecture_report [EXTRACTED 1.00]
- **The Five-Layer Quarantine and Render-Boundary Defence** — docs_threat_model_typed_marker, docs_threat_model_fail_closed_assertion, docs_threat_model_unpredictable_fence, docs_threat_model_escalate_not_strip, docs_threat_model_structural_invariant, docs_threat_model_scan_text [EXTRACTED 1.00]
- **Mitigating Context Detectors and Symmetric Grounding** — docs_detectors_authorised_activity, docs_detectors_routine_software, docs_detectors_policy_json, docs_detectors_explains_contract, docs_threat_model_symmetric_grounding [INFERRED 0.85]
- **Demo Flow: Ingestion Transparency, Verdict, Human Gate** — docs_demo_triage_what_bishop_read_panel, docs_demo_triage_applicable_detectors, docs_demo_verdict_deterministic_detector_fusion, docs_demo_verdict_true_positive_verdict, docs_demo_verdict_attck_mapping, docs_demo_gate_human_approval_required [INFERRED 0.85]
- **Gate Decision Surface: Irreversibility, Blast Radius, Choice Set** — docs_demo_gate_irreversible_marking, docs_demo_gate_blast_radius_description, docs_demo_gate_approval_choices, docs_demo_gate_reversible_only_subset, docs_demo_gate_default_reject [EXTRACTED 1.00]

## Communities (115 total, 10 thin omitted)

### Community 0 - "CLI and Run Orchestration"
Cohesion: 0.05
Nodes (98): ArgumentParser, Namespace, Run orchestration behind the API.  The graph is synchronous and one run can susp, _ask_for_decision(), bold(), build_parser(), _c(), cmd_alerts() (+90 more)

### Community 1 - "Human Approval Gate Demo"
Cohesion: 0.05
Nodes (59): Approve All / Reject All / Subset Prompt, uv run bishop run TP-01-credential-dumping, Per-Action Blast Radius Description, collect_forensics Action, Rationale: Contain Account And Host Together, Anything Else Rejects (Fail-Closed Default), force_password_reset Action (Irreversible), HUMAN APPROVAL REQUIRED Gate (+51 more)

### Community 2 - "Quarantine Trust Boundary"
Cohesion: 0.06
Nodes (40): CoreSchema, GetCoreSchemaHandler, assert_no_untrusted(), contains_untrusted(), _escape(), Any, RuntimeError, quarantine() (+32 more)

### Community 3 - "Injection Signal Scoring"
Cohesion: 0.06
Nodes (50): _alt(), combine(), _cooccurrence(), _excerpt(), Pattern, Deterministic detection of prompt-injection attempts in alert fields.  No model, A verb and a noun within 40 characters, in either order.      The window is what, Combine independent weights without ever reaching certainty.      Probabilistic (+42 more)

### Community 4 - "Graph State and Alert Schema"
Cohesion: 0.09
Nodes (37): RunCost, The human gate. Nothing irreversible happens on the other side of this without a, merge_cost(), The graph state.  One object flows through every node. Two things about its shap, Sum costs across parallel investigators., BishopModel, Device, DnsEvent (+29 more)

### Community 5 - "Detector Contract and Maths"
Cohesion: 0.08
Nodes (42): DetectorFn, Baseline, clear(), coefficient_of_variation(), DetectorSpec, for_surface(), median_absolute_deviation(), miss() (+34 more)

### Community 6 - "FastAPI Endpoint Surface"
Cohesion: 0.07
Nodes (48): Exception, alert_detail(), alerts(), coverage(), _credentials_from(), Decision, detectors(), health() (+40 more)

### Community 7 - "Corpus and Holdout Builders"
Cohesion: 0.07
Nodes (32): alert(), at(), build(), _chunk(), geo(), main(), Any, A deterministic 58-character pseudo-base32 label.      Built from a fixed alphab (+24 more)

### Community 8 - "Trusted-Block Confusion Attacks"
Cohesion: 0.08
Nodes (26): _parse_block(), Any, Pattern, load_attack_alert(), One of the end-to-end envelopes in `fixtures/injection/alerts/`., Run the whole graph offline against the deterministic mock provider.      The mo, run_pipeline(), BLOCKERS. Attacker text reaching the prompt outside the quarantine fence.  Every (+18 more)

### Community 9 - "Deployment Configuration Guards"
Cohesion: 0.09
Nodes (15): BaseSettings, DeploymentSettings, Auth is on whenever keys exist, and mandatory in production.          Deliberate, Whether production must be pointed at Postgres.          True everywhere except, Whether an alert a visitor supplied may be written to the store.          False, Everything that changes between a laptop and a deployment., The point of these is that production cannot be misconfigured quietly., An audit chain that does not survive a restart is not an audit chain. (+7 more)

### Community 10 - "Fence Rendering and Field Budget"
Cohesion: 0.11
Nodes (19): fence_nonce(), quarantine_alert(), Extract and score every attacker-influenced field in an alert.      Field discov, Render quarantined fields as a fenced, numbered block.      The nonce on both ta, A fence marker derived from the run identifier.      Deterministic given a run i, render_block(), Process, The evidence that gets dropped is chosen by schema order, not by risk. (+11 more)

### Community 11 - "Audit Actions and Ingest Node"
Cohesion: 0.09
Nodes (32): AuditAction, StrEnum, What happened. Kept closed so the log stays greppable., The hash-chained, append-only audit log. See `chain.py` for the guarantees., ingest(), Any, RunnableConfig, Ingest — normalise, quarantine, and raise injection findings.  The first node, (+24 more)

### Community 12 - "Endpoint Detectors"
Cohesion: 0.10
Nodes (16): credential_dumping(), lolbin_abuse(), Process lineage that does not occur in normal operation.      Two rules, in decr, Attempts to read credentials out of memory or off disk.      Three independent r, Living-off-the-land binaries invoked in the ways that matter.      The binary be, suspicious_parent_child(), account_manipulation(), _basename() (+8 more)

### Community 13 - "Identity Detectors"
Cohesion: 0.14
Nodes (15): impossible_travel(), mfa_fatigue(), password_spray(), Repeated MFA denials ending in an acceptance.      The signal is not the denials, Many accounts, few attempts each, one origin.      Per-account lockout does not, Two successful logins too far apart for the same person to have made both., alert(), auth() (+7 more)

### Community 14 - "Bring-Your-Own-Key Providers"
Cohesion: 0.08
Nodes (23): AnthropicHttp, AzureOpenAIHttp, build_provider(), _gemini_schema(), GeminiHttp, _HttpProvider, OpenAIHttp, Providers built from a user's own key, over plain HTTP.  Bishop already had an A (+15 more)

### Community 15 - "Graph Assembly and Response Planning"
Cohesion: 0.08
Nodes (31): BlastRadius, JsonPlusSerializer, Send, after_critic(), build_graph(), build_serialiser(), default_checkpointer(), dispatch_investigators() (+23 more)

### Community 16 - "Model Provider Interface"
Cohesion: 0.12
Nodes (24): AnthropicProvider, Any, The live Claude provider.  Imported lazily and only when `BISHOP_MODEL_PROVIDER=, Claude behind Bishop's model interface., cost_usd(), extract_json(), ModelError, ModelResponse (+16 more)

### Community 17 - "Credential Validation and SSRF Guard"
Cohesion: 0.08
Nodes (18): _check_endpoint(), parse(), provider_catalogue(), ProviderSpec, Any, Bring-your-own-key credentials, carried per request and never stored.  Bishop's, Safe to log, to return, and to write to the audit chain., Validate what a client sent, or raise with a message worth showing.      Validat (+10 more)

### Community 18 - "Endpoint Detector Tests and Catalogues"
Cohesion: 0.09
Nodes (20): Static knowledge the endpoint detectors match against.  Kept in one place, in co, abused_hosting_contact(), _all_processes(), _basename(), _cmd_of(), data_staging(), encoded_command(), _name_of() (+12 more)

### Community 19 - "Incident Store Schema"
Cohesion: 0.11
Nodes (27): AuditEntry, Engine, Incidents that survived the process that produced them., stored_incident(), stored_incidents(), connection(), get_engine(), health() (+19 more)

### Community 20 - "Console Dependencies"
Cohesion: 0.06
Nodes (34): dependencies, next, react, react-dom, reactflow, description, devDependencies, postcss (+26 more)

### Community 21 - "Injection Test Fixtures"
Cohesion: 0.09
Nodes (22): MarkDecorator, attack_alert_labels(), benign_corpus(), blocker_xfail(), _load(), make_alert(), payload_corpus(), Any (+14 more)

### Community 22 - "Mitigating Context Detectors"
Cohesion: 0.08
Nodes (23): _all_processes(), authorised_activity(), _observed_privilege(), Authorisation for activity that genuinely happened.      Supports `benign_true_p, The highest privilege tier this alert shows being touched.      Read from the di, _username(), _within_scope(), _always() (+15 more)

### Community 23 - "TypeScript Build Config"
Cohesion: 0.06
Nodes (31): compilerOptions, allowJs, esModuleInterop, incremental, isolatedModules, jsx, lib, module (+23 more)

### Community 24 - "Environment Policy Loading"
Cohesion: 0.09
Nodes (22): _basename(), load_policy(), Any, Path, Evidence that the rule's premise is wrong rather than its subject approved., Load environment policy. Absent is not an error — it is less context., routine_software(), RegistryChange (+14 more)

### Community 25 - "Prompt Assembly and Grounding"
Cohesion: 0.13
Nodes (26): _ground(), Any, Evidence, Attach each reported finding to the detector it claims to rest on.      A findin, build_critic_prompt(), build_investigator_prompt(), build_response_prompt(), build_synthesis_prompt() (+18 more)

### Community 26 - "Investigator Documentation"
Cohesion: 0.10
Nodes (32): context_investigator, endpoint_investigator, identity_investigator, network_investigator, synthesis, threatintel_investigator, triage_supervisor, T1003 OS Credential Dumping (no detector) (+24 more)

### Community 27 - "API Security Middleware Tests"
Cohesion: 0.10
Nodes (14): FastAPI, lifespan(), Announce the resolved configuration, and create tables if absent.      The unaut, build_app(), Tests for the API's authentication, limits and configuration guards.  These are, A probe hammering /health must not lock out real traffic., So a caller can correlate its own trace with Bishop's logs., The laptop default. `config.py` is what stops this reaching production. (+6 more)

### Community 28 - "Synthesis and Adversarial Critic"
Cohesion: 0.11
Nodes (26): adversarial_critic(), Any, RunnableConfig, The adversarial critic — one bounded pass at proving the verdict wrong.  The fai, _accusatory_examination(), _all_results(), atlas_techniques_for(), _build_verdict() (+18 more)

### Community 29 - "Alert Normalisation"
Cohesion: 0.18
Nodes (30): _as_bool(), _as_int(), _auth(), _basename(), _connections(), _device(), _dig(), _dns() (+22 more)

### Community 30 - "Human Gate Decision Parsing"
Cohesion: 0.10
Nodes (17): _approval_request(), _parse_decision(), Any, HumanDecision, ResponsePlan, RunnableConfig, Turn whatever the human sent into a decision record.      Unrecognised input is, What the analyst is shown. Everything needed to decide, nothing else. (+9 more)

### Community 31 - "API Integration Tests"
Cohesion: 0.10
Nodes (9): API surface tests.  The important ones are in `TestApprovalFlow`: the API is the, The API must not become a way around the human gate., A console bug must not be able to name an action into existence., Poll until the run reaches a status. Runs execute on a worker thread., TestApprovalFlow, TestInjectionThroughTheApi, TestReadOnly, TestRunLifecycle (+1 more)

### Community 32 - "Console Evidence Panel"
Cohesion: 0.09
Nodes (22): EvidencePanel(), KIND_STYLE, Empty(), AttackStage, AuditEntry, BlastRadius, CoverageEntry, DeploymentInfo (+14 more)

### Community 33 - "Pipeline Test Harness"
Cohesion: 0.15
Nodes (11): Settings, credential_theft_alert(), Returns `(invoke, runtime)` for one deterministic run., An unambiguous true positive: LSASS access, persistence, Office parent., run(), LangGraph re-runs the node on resume. The chain says so., TestEndToEndGate, Bishop declines rather than guessing when the bar is not met. (+3 more)

### Community 34 - "Auth, Rate Limit and Headers"
Cohesion: 0.13
Nodes (18): BaseHTTPMiddleware, JSONResponse, Response, Can this instance serve traffic — i.e. can it reach its store., readiness(), AuthMiddleware, _fingerprint(), _presented_key() (+10 more)

### Community 35 - "Injection Corpus Recall"
Cohesion: 0.09
Nodes (18): InjectionSignal, Score one string for injection intent.      Every transformation of the value is, One match. Carries enough to argue with., scan_text(), The payload corpus, one test per payload.  `fixtures/injection/payloads.json` is, A catch that changes technique is a change in the defence, not a bug.      It st, Print the score so the README number comes from a run, not from memory., test_caught_payloads_are_caught_for_the_recorded_reason() (+10 more)

### Community 36 - "Ingest Normaliser Tests"
Cohesion: 0.11
Nodes (10): Tests for the alert normaliser.  Two properties matter more than the field mappi, Ignored means uninterpreted, not discarded — `raw` is still scanned         for, The most useful thing the preview does: tell you the run is pointless         be, A Sysmon EventID 1, in the shape the Windows event log actually emits., Sysmon sends `Image` as a full path and no separate name.          `masquerading, `DOMAIN\\user` left joined breaks the entity key correlation uses., sysmon_process_create(), TestNativePassthrough (+2 more)

### Community 37 - "Console Pages and Primitives"
Cohesion: 0.13
Nodes (13): ApprovalModal(), Props, ApiDown(), Panel(), SeverityDot(), VERDICT_COLOUR, VERDICT_LABEL, VerdictPill() (+5 more)

### Community 38 - "Production Config Enforcement"
Cohesion: 0.11
Nodes (15): ConfigError, _describe_database(), generate_key(), get_settings(), key_matches(), Any, RuntimeError, Deployment configuration, validated once at startup.  Bishop's defaults are tune (+7 more)

### Community 39 - "Deterministic Mock Model"
Cohesion: 0.15
Nodes (12): _combine(), _fired(), MockModel, The deterministic model. Bishop's default, not a test double.  `just demo`, the, The adversarial pass: what would make this verdict wrong., Choose a label from suspicion, mitigation, and injection findings.          The, Confidence in the label that was assigned, not in "something is wrong"., Detectors that fired, strongest first.      `mitigating` selects which side of t (+4 more)

### Community 40 - "Mocked Response Execution"
Cohesion: 0.14
Nodes (18): _authorised(), ExecutionRefused, Executor, MockExecutor, Any, HumanDecision, Protocol, ResponseAction (+10 more)

### Community 41 - "Deployment and Console Docs"
Cohesion: 0.12
Nodes (21): Production API URL Defaulted in lib/api.ts, Netlify Console Deploy Workflow, Static Export Console (output: export), Analyst Console, Dark by Default, The Console Fails Loudly, BISHOP_API_KEYS, BISHOP_CORS_ORIGINS (+13 more)

### Community 42 - "Architecture Decisions"
Cohesion: 0.11
Nodes (21): Run View, useRunStream, FastAPI Surface and SSE Stream, Graph Checkpointer, Deterministic, Generous Supervisor Dispatch, The Human Gate, MockExecutor, report (+13 more)

### Community 43 - "Incident Persistence Round-Trip"
Cohesion: 0.17
Nodes (11): load_incident(), Incident, Persist an incident and, if given, the chain that covers it.      Written as a s, Verify a stored chain against the head recorded with its incident.      This is, save_incident(), verify_stored_chain(), Deleting the record of what executed is the cheapest tamper.          Verifying, A stored incident that lost its signals cannot be re-checked. (+3 more)

### Community 44 - "Console Triage and Detector Pages"
Cohesion: 0.16
Nodes (12): SAMPLES, ModelBanner(), api, ApiError, get(), withAuth(), credentialHeaders(), Coverage (+4 more)

### Community 45 - "Coverage Reporting"
Cohesion: 0.15
Nodes (20): Coverage Page, Covered and Untested Shown Differently, Bishop Architecture, Disjoint Investigator Inputs, _ground(), ATT&CK Coverage Matrix, covered vs untested, T1021.002 SMB/Windows Admin Shares (no detector) (+12 more)

### Community 46 - "Run Manager and SSE Stream"
Cohesion: 0.21
Nodes (6): FastAPI surface and SSE streaming. See `app.py`., Any, Write the finished incident and its chain.          Failure here must not fail t, Yield events as they happen, then stop when the run settles.          Replays wh, Run, RunManager

### Community 47 - "Audit Chain Append Tests"
Cohesion: 0.16
Nodes (5): populate(), A chain verified from genesis says nothing about its own end.      Deleting the, TestAppend, TestTamperDetection, TestTruncation

### Community 48 - "Console Layout and Model Gate"
Cohesion: 0.25
Nodes (11): metadata, ModelGate(), LINKS, Nav(), ProviderSetup(), clearCredentials(), hasChosen(), loadCredentials() (+3 more)

### Community 49 - "Quarantine Laundering Paths"
Cohesion: 0.13
Nodes (18): adversarial_critic, Alert.raw, assert_no_untrusted(), Alert.entity_key(), Nonce-Derived Quarantine Fence, render_block(), response_planner, Trusted Content Precedes Untrusted Content (+10 more)

### Community 50 - "Audit Chain Operations"
Cohesion: 0.17
Nodes (8): AuditEntry, canonical(), hash_payload(), Any, Add a link. The only way to write to the chain., Record that an earlier entry was wrong, without touching it.          The only s, Stable JSON. Two equal payloads must hash identically on any machine.      `sort, One immutable link.      Deliberately not a Pydantic model: nothing may mutate a

### Community 51 - "MITRE ATLAS Mapping"
Cohesion: 0.15
Nodes (8): atlas_for_signals(), AtlasTechnique, is_atlas_id(), MITRE ATLAS — the taxonomy for attacks against the analyst, not the estate.  Ent, Map injection signal names onto ATLAS techniques, in a stable order.      The tw, Split proposals into `(known, unknown)` ATLAS IDs.      Same rule as ATT&CK: an, validate_atlas(), TestAtlas

### Community 52 - "ATT&CK Catalogue Validation"
Cohesion: 0.18
Nodes (6): Coerce a proposal into canonical form.          Returns `(canonical_id, note)`., Validate proposed technique IDs. Nothing invalid survives this call., Validate, raising on the first rejection. For internal callers only.          Mo, An immutable snapshot of ATT&CK, loaded once per process., Technique, TechniqueCatalogue

### Community 53 - "Threat Intel Cache"
Cohesion: 0.18
Nodes (14): default_cache_path(), _indicators_in(), IntelCache, ioc_reputation(), IocRecord, _is_private(), load_cache(), Path (+6 more)

### Community 54 - "DNS Exfiltration Detection"
Cohesion: 0.21
Nodes (8): dns_exfiltration(), Split a hostname into `(registrable domain, subdomain labels)`.      Deliberatel, Data encoded into DNS query names.      Three signals combined: the subdomain la, _registrable_parts(), dns(), Network detector tests.  Every series here is constructed deterministically. A b, TestDnsExfiltration, TestRegistrableParts

### Community 55 - "Outbound Volume and Beaconing"
Cohesion: 0.21
Nodes (7): outbound_volume(), Asymmetry between bytes sent and bytes received.      Browsing is inbound-heavy., beacon_series(), conn(), A deterministic series of connections with a fixed proportional jitter.      The, TestBeaconing, TestOutboundVolume

### Community 56 - "Catalogue Loading"
Cohesion: 0.13
Nodes (10): load_catalogue(), Path, Load the committed catalogue. Memoised — it never changes at runtime., InjectionTechnique, StrEnum, catalogue(), Technique validation tests.  The rule under test is `CLAUDE.md` §3: an ID reache, A detector shipping an invalid ID is a bug, and this is the gate. (+2 more)

### Community 57 - "Audit Chain Verification"
Cohesion: 0.21
Nodes (8): AuditChain, An append-only chain, optionally persisted as JSON Lines.      JSON Lines rather, chain(), fixed_clock(), Audit chain tests.  The chain's whole value is that tampering is detectable. The, The next thing an attacker tries: fix the payload hash too.          That still, A deterministic clock. Two runs of a test must produce identical hashes., TestPersistence

### Community 58 - "Fence Integrity Attacks"
Cohesion: 0.25
Nodes (6): block_for(), field_lines(), Attacks on the fence itself, from inside a field.  `tests/quarantine/test_bounda, The attacker's marker is inside the quotes; Bishop's is outside.          That s, TestForgingStructure, TestFraming

### Community 59 - "Untrusted Input Trust Boundary"
Cohesion: 0.20
Nodes (15): _mark_quoted(), safe_block(), The Trust Boundary, _mark_quoted(), Prefer Invariants You Can Enforce Over Attacks You Can Enumerate, Decision 3: The Invariant Moves to the Render Boundary, safe_block(), No Alert Content Is Ever Logged (+7 more)

### Community 60 - "Test Pipeline"
Cohesion: 0.16
Nodes (9): graph(), make_alert(), An alert about something Bishop has no detector for at all.      A Kerberoasti, uncovered_alert(), `false_positive` needs grounding too — the third direction.      Bishop already, Wording matters here. An analyst reading "no coverage" triages it         themse, The rule must not turn every false positive into an escalation., Context is excluded deliberately.          `authorised_activity` reaches a concl (+1 more)

### Community 61 - "Test Byok"
Cohesion: 0.19
Nodes (9): Drop the cache. For tests that change the environment., reset_settings(), quiet_alert(), Nothing a detector will fire on., A dropped finding is a model trying to invent a signal. Record it., The leak public-demo mode exists to prevent.      A visitor pastes an alert from, Driven through a real run, because the guard sits after the incident         is, The corpus is synthetic and already public, so it still stores. (+1 more)

### Community 62 - "Test Purity"
Cohesion: 0.14
Nodes (7): Detector purity, enforced rather than asserted in a docstring.  `docs/DETECTORS., A missing field must produce a miss, not an exception., A detector that reads the clock gives a different answer next week., Run every detector twice over the whole corpus and compare., A detector that edits its input corrupts every detector after it., TestRuntimePurity, TestSourcePurity

### Community 63 - "Test Gate"
Cohesion: 0.32
Nodes (7): isolate_action(), plan_with(), ResponseAction, ResponsePlan, The human gate and the executor. The controls that must not be theatre.  `CLAUDE, The executor's own check, exercised by calling it directly.      Calling the nod, TestExecutorRefusal

### Community 64 - "Threat Model"
Cohesion: 0.21
Nodes (13): The Approval Modal Is the Product, Alternative: Tiered Autonomy, The Decision Is What Executes, ADR-003: Human-Gated Response with Mocked Executors, Rejected: Auto-Contain Above a Confidence Threshold, account_manipulation, Attacker Model, Attacker Goal 4: Evidence Exfiltration (+5 more)

### Community 65 - "Coverage"
Cohesion: 0.27
Nodes (6): CoverageMatrix, The technique → detector → fixture coverage matrix.  Generated from the detector, Render the matrix as the body of `docs/COVERAGE.md`., render_markdown(), TechniqueCoverage, ATT&CK and ATLAS technique validation.  Nothing that looks like a technique ID r

### Community 66 - "Adr 002 Deterministic Detectors"
Cohesion: 0.17
Nodes (12): MockModel, Coverage of a Technique Is Not Detection of Every Implementation, Alternative: Pure LLM Triage, Alternative: Sigma Rules as the Runtime Engine, Alternative: Train a Classifier, ADR-002: Deterministic Detectors Beneath the Model, Narrower Measurable Coverage Beats Broader Unmeasurable Coverage, Detectors Emit Signals, Not Verdicts (+4 more)

### Community 67 - "Test Validation"
Cohesion: 0.29
Nodes (3): Convenience wrapper over the loaded catalogue., validate_techniques(), TestValidation

### Community 68 - "Test Pipeline"
Cohesion: 0.24
Nodes (6): injection_only_alert(), No detector will fire. The only notable thing is the payload.      This is the, The payload asked to be marked benign. It must not have worked., The payload is the only difference, and it changes the outcome.          Asserte, An alert whose only notable feature is a payload in a field.      No detector fi, TestInjectionOnlyAlert

### Community 69 - "Topology"
Cohesion: 0.25
Nodes (9): baseEdges(), baseNodes(), BishopNodeData, INVESTIGATORS, NodeState, nodeTypes, STATE_COLOUR, statesFor() (+1 more)

### Community 70 - "Logging Setup"
Cohesion: 0.24
Nodes (8): LogRecord, configure_logging(), HumanFormatter, JsonFormatter, Logging that a log aggregator can read.  Human-readable lines on a laptop, one J, One JSON object per line., Readable in a terminal, with `extra` fields appended compactly., Install the formatter. Idempotent — safe to call from several entry points.

### Community 71 - "Test Endpoint"
Cohesion: 0.33
Nodes (4): masquerading(), Names and paths chosen to be misread by a human or a rule.      The right-to-lef, FileObject, TestMasquerading

### Community 72 - "Test Third Party And Gate"
Cohesion: 0.24
Nodes (7): intel_alert(), poisoned_cache(), Two surfaces that are attacker-influenced without looking like it.  **The threat, The note stays in the facts — it is evidence about the feed., The text is kept and the hit is downgraded, rather than silently used., Point the intel detector at a cache with one hostile entry.      The entry is ot, TestPoisonedIntelCache

### Community 73 - "Deployment"
Cohesion: 0.24
Nodes (10): Append-Only Hash-Chained Audit Log, Chain Head Stored Beside the Incident, Storage Layer (SQLite / Postgres), The Gate Is Defended Twice, BISHOP_DB_SCHEMA, bishop verify --expect-head, DATABASE_URL, Supabase Pooler Host Requirement (+2 more)

### Community 74 - "Architecture"
Cohesion: 0.24
Nodes (10): BishopState, ingest, quarantine_evidence State Field, Reducer Fields for Parallel Writes, BLK-03: Detected, Escalated, Still Wrong, Decision 2: A Detected Attempt Is Escalated, Not Stripped, The Injection Scanner, Layer 4.4: A Detected Attempt Is Evidence, Not Noise (+2 more)

### Community 75 - "Catalogue"
Cohesion: 0.20
Nodes (7): ValueError, Technique validation against the ATT&CK bundle.  `CLAUDE.md` §3: a technique ID, A proposed technique ID did not survive validation., Why one proposal was refused. Carried into the audit log., Rejection, TechniqueRejected, Validation

### Community 76 - "Test Endpoint"
Cohesion: 0.33
Nodes (3): persistence(), Anything written that will run again after the machine restarts.      Persistenc, TestPersistence

### Community 77 - "Test Ingest"
Cohesion: 0.31
Nodes (4): load_payload(), Parse submitted text into one alert payload.      Accepts a JSON object, a singl, Exporting one alert from a SIEM usually yields a one-element array., TestLoadPayload

### Community 78 - "Test Security"
Cohesion: 0.27
Nodes (5): TestClient, client(), `EventSource` cannot set headers, so the SSE path takes a query key.      Narrow, The concession must not become a general bypass., TestEventStreamAuth

### Community 79 - "Test Denial Of Analysis"
Cohesion: 0.27
Nodes (5): flooded_alert(), `quarantine_alert` stops *scanning* at the cap, not just rendering.      The `co, The flood still truncates; the payload inside it no longer escapes.          Fie, The drop notice has to distinguish "not shown" from "not checked".          An a, TestFieldFlooding

### Community 80 - "Chain"
Cohesion: 0.33
Nodes (6): load_chain(), datetime, Path, The hash-chained, append-only audit log.  Every agent step, model call, evidence, Load a persisted chain for verification. Does not append., _read_jsonl()

### Community 81 - "Test Ingest"
Cohesion: 0.31
Nodes (4): Turning somebody else's alert into Bishop's alert. See `normalise.py`., detect_format(), Guess which shape this is. Advisory — the mapper tries everything anyway., TestFormatDetection

### Community 82 - "Chain"
Cohesion: 0.25
Nodes (6): ChainBroken, RuntimeError, Recompute the chain. Raises `ChainBroken` at the first bad link.          Pass `, Verify a sequence of entries links correctly, from genesis.      `expected_head`, The chain does not verify. Something was rewritten., verify_entries()

### Community 84 - "Test Ingest"
Cohesion: 0.32
Nodes (4): ecs_document(), Exporters disagree; the user should not have to care., Elastic Common Schema, nested the way Elastic writes it., TestEcs

### Community 85 - "Test Ingest"
Cohesion: 0.25
Nodes (3): `labels` is the eval corpus's ground truth. A submitted alert that         could, Windows' inverted 1-5 scale cannot be told from a normal one without         gue, TestItDoesNotInventStructure

### Community 86 - "Ci"
Cohesion: 0.29
Nodes (7): Console Typecheck and Build Job, Coverage Matrix Freshness Check, Offline CI Pipeline, Scorecard Regression Gate, What Is Still Missing, Held-Out Evaluation Set, What This Doesn't Do

### Community 87 - "Render Terminal Svg"
Cohesion: 0.43
Nodes (6): colourise(), main(), Split one line into (text, role) runs, honouring simple ANSI colour., Apply the colours the CLI would use, which a subprocess cannot capture.      The, render(), spans()

### Community 88 - "Test Identity"
Cohesion: 0.43
Nodes (3): haversine_km(), Great-circle distance in kilometres.      Great-circle rather than driving dista, TestHaversine

### Community 89 - "Test Store"
Cohesion: 0.29
Nodes (4): Bishop can share a Postgres database with another application.      The tables m, Re-imported under the env var, because MetaData binds at declaration., SQLite has no schemas; setting one must not break a local run., TestSchemaIsolation

### Community 90 - "Build Attck Catalogue"
Cohesion: 0.60
Nodes (5): attack_id(), attack_url(), build(), main(), Path

### Community 91 - "Test Validation"
Cohesion: 0.47
Nodes (3): build_matrix(), Build the matrix from the detector registry and fixture labels.      `fixture_te, TestCoverageMatrix

### Community 92 - "Normalise"
Cohesion: 0.33
Nodes (6): _jurisdiction(), _passthrough(), A payload already in Bishop's schema. Validate it and say nothing else.      `la, Which detectors can actually examine this alert.      Computed by running them,, Say what will be weak about this run, before it is run., _warn_about_thin_input()

### Community 93 - "Test Store"
Cohesion: 0.47
Nodes (3): database_url(), Resolve the connection string.      Absent `DATABASE_URL`, SQLite under `storage, TestUrlResolution

### Community 95 - "Types"
Cohesion: 0.70
Nodes (4): eventStreamUrl(), RunEvent, RunState, useRunStream

### Community 96 - "Normalise"
Cohesion: 0.40
Nodes (5): _category_from(), Structure first, words second.      What data the alert actually carries is a fa, AlertCategory, StrEnum, Coarse routing category. Decides which investigators get dispatched.

## Knowledge Gaps
- **110 isolated node(s):** `metadata`, `SAMPLES`, `KIND_STYLE`, `LINKS`, `NodeState` (+105 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 761 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Alert` connect `Mitigating Context Detectors` to `CLI and Run Orchestration`, `Quarantine Trust Boundary`, `Graph State and Alert Schema`, `Detector Contract and Maths`, `Corpus and Holdout Builders`, `Trusted-Block Confusion Attacks`, `Fence Rendering and Field Budget`, `Endpoint Detectors`, `Identity Detectors`, `Graph Assembly and Response Planning`, `Endpoint Detector Tests and Catalogues`, `Injection Test Fixtures`, `Environment Policy Loading`, `Alert Normalisation`, `Pipeline Test Harness`, `Run Manager and SSE Stream`, `Threat Intel Cache`, `DNS Exfiltration Detection`, `Outbound Volume and Beaconing`, `Test Pipeline`, `Test Byok`, `Test Purity`, `Test Pipeline`, `Test Endpoint`, `Test Third Party And Gate`, `Test Endpoint`, `Normalise`?**
  _High betweenness centrality (0.128) - this node is a cross-community bridge._
- **Why does `DetectorResult` connect `Prompt Assembly and Grounding` to `Quarantine Trust Boundary`, `Graph State and Alert Schema`, `Detector Contract and Maths`, `Test Endpoint`, `Audit Actions and Ingest Node`, `Endpoint Detectors`, `Test Endpoint`, `Identity Detectors`, `Graph Assembly and Response Planning`, `Endpoint Detector Tests and Catalogues`, `Threat Intel Cache`, `Mitigating Context Detectors`, `DNS Exfiltration Detection`, `Environment Policy Loading`, `Outbound Volume and Beaconing`, `Synthesis and Adversarial Critic`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Why does `Process` connect `Fence Rendering and Field Budget` to `Pipeline Test Harness`, `Quarantine Trust Boundary`, `Injection Corpus Recall`, `Graph State and Alert Schema`, `Test Pipeline`, `Test Endpoint`, `Endpoint Detectors`, `Graph Assembly and Response Planning`, `Test Denial Of Analysis`, `Endpoint Detector Tests and Catalogues`, `Test Byok`, `Injection Test Fixtures`, `Environment Policy Loading`, `Fence Integrity Attacks`, `Alert Normalisation`, `Test Escalation Is Ioc`?**
  _High betweenness centrality (0.032) - this node is a cross-community bridge._
- **Are the 13 inferred relationships involving `Alert` (e.g. with `Baseline` and `DetectorSpec`) actually correct?**
  _`Alert` has 13 INFERRED edges - model-reasoned connections that need verification._
- **Are the 10 inferred relationships involving `DetectorResult` (e.g. with `Baseline` and `DetectorSpec`) actually correct?**
  _`DetectorResult` has 10 INFERRED edges - model-reasoned connections that need verification._
- **Are the 11 inferred relationships involving `DeploymentSettings` (e.g. with `AuthMiddleware` and `RateLimiter`) actually correct?**
  _`DeploymentSettings` has 11 INFERRED edges - model-reasoned connections that need verification._
- **Are the 38 inferred relationships involving `Process` (e.g. with `.test_a_signed_binary_in_a_trusted_path_mitigates()` and `.test_a_signed_binary_in_temp_does_not_mitigate()`) actually correct?**
  _`Process` has 38 INFERRED edges - model-reasoned connections that need verification._