# AllowIt SDK

AllowIt policies are a restricted, validated subset of Rust. This repository contains the source compiler, deterministic interpreter, function registry, workflow projection, CLI and stdio language server. The same `no_std + alloc` interpreter is used by the contract adapters in `contracts/`.

```rust
use allowit::v1::prelude::*;

struct PolicyParams {}
fn new() -> PolicyParams { PolicyParams {} }

async fn _execute(ctx: &Context, params: &PolicyParams) -> PolicyResult {
    allowit::set_cap(ctx.spent_units, ctx.amount_units, &ctx.token, 100_000_000, "USDC", 6)?;
    allowit::cap_per_transaction(ctx.amount_units, &ctx.token, 10_000_000, "USDC", 6)?;
    allowit::require_merchant(&ctx.merchant, "research.example")?;
    jev::check_preference(
        jev::preference_evidence(ctx, "Does this purchase support the requested research?"),
        "Does this purchase support the requested research?",
        auto("deny"), auto("approve"),
    ).await?;
    Ok(())
}
```

The Rust [action CLI](https://github.com/AllowIt-hq/allowit-cli) is a separate client for `allowit show`, `eval`, `exec` and `status`. This repository's Rust CLI is a developer compiler/evaluator tool; use the repository-local Cargo commands below so the two executables are not confused. The app server owns HTTP transport. Hosted-agent control and runtime are optional, outside the MVP; they are not SDK responsibilities. Restricted Rust remains the policy source and enforcement language.

## Policy source and configuration

New source contains the versioned import, `PolicyParams`, a private `new()` constructor, and private `_execute(ctx: &Context, params: &PolicyParams) -> PolicyResult`. Keep fixed limits inline in the handler. Declare constructor fields only when the owner requests initialized configuration. Supported immutable field types are `u64`, `bool`, `&'static str`, and bounded `&'static [&'static str]` lists. Initialize every field with an inline literal. Undeclared names and duplicate or missing fields fail compilation, including unreachable code.

The [policy template](templates/policy/README.md) builds with its default denial stub. Replace only `src/policy.rs` with complete source to check ordinary Rust and the real restricted compiler. The host wrapper evaluates checked IR. Native wrappers authenticate requests and enforce custody, allocation, replay and settlement independently.

Checks receive the observed primitive and its limit or allowlist. Monetary guard inputs specify integer units, currency and decimal count. This profile admits bound six-decimal USDC. The compiler requires exact authenticated fields for accounting guards. Replacing observed spending with `0` or another claimed value fails compilation. Use sequential guards. Combined `&&` and `||` authoring conditions fail in this profile. `is_one_of` compares a primitive string with 1–32 inline or declared entries.

Immutable constructor values become source-bound IR literals. They are not mutable storage. A change requires a new approved policy artifact. Native mutable limits use explicit `OwnerLimit` descriptors instead:

```rust
struct PolicyParams {
    daily_limit: OwnerLimit,
    action_limit: OwnerLimit,
}
fn new() -> PolicyParams {
    PolicyParams {
        daily_limit: allowit::owner_limit("native_daily_limit", 5_000_000),
        action_limit: allowit::owner_limit("native_action_limit", 1_000_000),
    }
}
```

Inside the handler, `allowit::stored_limit(ctx, params.action_limit)?` returns the current owner-controlled primitive. The native adapter supplies verified account state through `Context.native_policy_storage`. The JSON protocol rejects `native_policy_storage`. Trusted adapters use the typed evaluator. Request JSON and `runtime_context` are not storage. The adapter checks constructor defaults against the original installation and reads current limits after owner-authorized updates. Only the two named native fields are admitted. Missing state fails closed. The portable contract profile rejects native storage, including unreachable reads.

The registry identifies this source profile as 1.2.0. Historical one-argument source profiles retain their old compiler semantics for artifact validation and recovery. Current primitive Rust exports do not reproduce historical whole-context signatures. New generation uses the constructor profile. Typed vendor movements require their own implemented source and execution binding.

## Run

Use Rust 1.98 or later. `Cargo.lock` pins the dependency graph.

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo check --locked --no-default-features --lib
cargo run --locked -- compile examples/research.rs
cargo run --locked -- evaluate examples/research.rs examples/context.json oracle
cargo run --locked -- evaluate examples/approval.rs examples/context.json contract
cargo run --locked -- workflow examples/approval.rs
cargo run --locked -- evaluate examples/green-investments.rs examples/green-context.json oracle
cargo run --locked -- registry
cargo run --locked -- lsp
```

CLI output is JSON. A failed compile or malformed request exits unsuccessfully. A completed evaluation prints its `pass`, `fail` or non-terminal `awaiting_input` decision; callers must inspect that decision before authorizing an action.

The research and green examples require semantic evidence; their supplied contexts intentionally contain no classification scores, so local evaluation returns `SEMANTIC_EVIDENCE_REQUIRED`.

For normal Rust type-checking, depend on this package with the name `allowit`:

```toml
allowit = { package = "allowit-sdk", path = "../AllowIt-sdk" }
```

The prelude is a type-checking facade, not a replacement for the compiler/interpreter. In particular, the restricted runtime uses checked arithmetic, enforces the allocation outside user code, and identifies input calls by their source location. Executing policy source directly with Rust's default arithmetic settings would not enforce this contract. The facade's user-input function fails closed. Tests compile all three example policies against the facade.

## Supported source and execution

Each registered policy function accepts an explicit `allowit::` prefix. `jev::semantic` and `jev::check_preference` select the existing preference checks. Unqualified calls remain supported. The compiler resolves exact registered names and lowers them to the same bounded operations. The registry exposes each accepted spelling with its signature and effect. Wrong prefixes, unknown operations, deeper paths and generic calls fail compilation.

Namespaces identify policy checks. A core check such as `allowit::allow_actions` compares exact labels. It does not execute or classify a vendor operation. PaySH and other vendor prefixes require concrete operations with their own bounded implementation and execution bindings. The restricted compiler rejects `paysh::pay`, `paysh::swap` and other unregistered vendor calls. Native vendor transport requires a separate execution interface.

Source registry 1.2.0 requires compatible rebuilt rail contracts. Contracts that
accept only registry 1.0.0 reject these new artifacts. This change does not deploy contracts.

Qualified calls preserve the current interpreter, contract opcodes and execution requirements. Source spans and source hashes still bind the exact policy text. Changing the spelling therefore requires a new compiled artifact and the corresponding mandate binding. Solana and Stellar adapters consume that artifact through the shared contract core. A Near adapter requires its own host, asset, authorization and settlement integration.

The constructor profile contains the declarations shown above. Historical single-handler profiles remain readable for existing artifacts. Version 1 accepts immutable `let` values, `if`/`else`, early `return fail("reason")`, `Ok(())`, booleans, strings, `u64` integers, boolean/comparison operators and checked integer `+ - * / %`. Context fields expose amount, allocation, spent, action, merchant, recipient, token, network and evaluation time. Confidence intervals expose `lower_bps` and `upper_bps`.

Every function and every branch is validated, including unreachable code. Unknown syntax, imports, macros, attributes, mutation, shadowing, loops, recursion, arbitrary method calls, I/O, unsafe code and unchecked/discarded function results are rejected. Source is limited to 32 KiB and 1,024 syntax tokens (including opening and closing delimiters), IR to 2,048 nodes and semantic nesting to 48 levels. The total token budget never resets across statements or groups. Before invoking `syn`, a token preflight checks the exact function signature and permits only simple `u64`, `bool`, `&str` or `ConfidenceInterval` local annotations. The bounded constructor preflight admits only the declared parameter schema and literal initializers. Other type declarations, casts, closures and qualified type expressions are rejected before Rust's recursive type parser runs. An iterative token-tree walk bounds actual delimiter depth to 32 and each statement/header to 256 tokens, 96 punctuation operators and 32 control prefixes, with at most 32 `else` branches in a policy. Only the function body and statement-level `if`/`else` bodies may contain code blocks; conditional expressions and semicolons inside expression groups are unsupported. Flat guard statements have independent budgets. Parentheses and brackets contribute to their enclosing expression budget, so shallow postfix call/index/cast chains cannot hide a deep AST. String contents and comments do not alter structural depth. UTF-8 source must not contain a leading byte-order mark.

All monetary values in the portable core are micro-USDC (six decimal places). Decimal limit strings are converted exactly; excess precision, zero, negatives and overflow are rejected. Rail adapters must verify the asset and normalize its actual decimal precision without rounding. The Stellar adapter therefore rejects sub-micro-unit dust when converting its seven-decimal asset. Version 1 supports only the bound USDC asset, not arbitrary tokens described as USDC.

`set_cap` is a configuration declaration: it may occur at most once, at the top level, with literal amount and token. It is enforced before user control flow, including when placed after an early return. The host allocation and spent amount are always enforced independently. Policies can restrict this budget but cannot increase it.

The predefined registry contains `set_cap`, `cap_per_transaction`, `allow_actions`, `require_merchant`, `require_recipient`, `confidence`, `semantic`, `context_u64`, `require_user_input` and `fail`. Help, signatures and workflow labels come from that registry.

Classifications such as research purpose, wallet role, or a customer's investment category belong in configurable `check_preference` questions evaluated by Jev. `allow_actions` only compares caller-supplied strings; it does not verify membership in a semantic category. Exact user-specified addresses, merchant identifiers and numeric restrictions remain deterministic checks. A matching address does not establish its purpose or ownership.

Pass and fail are the only terminal outcomes. In the oracle profile, reaching `require_user_input(...).await?` returns a non-authorizing `awaiting_input` decision with an input key and prompt. The engine must authenticate the owner, bind the exact policy/action/evidence snapshot, persist the suspension and answers, reject replay, enforce expiry/revocation and recheck fresh budgets before executing. The SDK does not authenticate a plain `answers` map. Each key binds the policy source digest, call location and prompt; distinct calls cannot share an approval by merely repeating the prompt.

In the contract profile, every reached user-input call fails with `USER_INPUT_REQUIRED`, even when an answer is present. An oracle approval does not change this rule. Confidence intervals must come from trusted, bound evidence. Missing evidence fails, malformed intervals fail, and no score is invented. Valid bounds are ordered integers between 0 and 10,000 basis points. A self-reported model score is not a calibrated interval.

Halted decisions may include `source_start` and `source_end`, exact UTF-8 byte offsets for the failing or awaiting-input call. Arithmetic failures without a call use the containing statement; preflight host guards may have no span. Treat spans as diagnostics, bounds-check them against the exact source, and never use them as authority. Consumers with strict older response decoders must accept these optional fields before upgrading the writer; Rust callers constructing `Decision` literals must supply the new optional fields.

## Preference questions and runtime JSON

`Context.original_intent` preserves up to 16 KiB of the owner's actual instructions. `Context.runtime_context` accepts an object of at most 16 KiB serialized JSON, depth8 and 128 total object/array entries. All available transaction facts and their provenance can travel in that object. They are claims until the host authenticates them. `context_u64(ctx, "key")?` reads a strict non-negative whole number from a top-level key; it never coerces strings, fractions or missing values.

`semantic(ctx, "exact question")?` reads an assessment keyed by lowercase SHA-256 of the exact UTF-8 question. A nonempty original intent is required. Missing evidence produces a terminal SDK failure `SEMANTIC_EVIDENCE_REQUIRED` with `question` and `evidence_key`. The trusted host may intercept that specific result, ask Jev by TypeSafe with the question, original instructions and the complete bound runtime context, authenticate and persist the result, then reevaluate. The SDK never contacts a provider, invents a score or implicitly approves a request. Contract execution requires verified evidence bound to the same mandate/context.

The question hash identifies an evidence slot within one evaluation; it does **not** authenticate evidence or make it reusable. Before populating that slot, the host must bind the provider response to the exact source/IR digests, policy revision, owner, action, amount, recipient, network, token, original intent, complete runtime-context digest and evidence expiry. A change to any bound request field requires fresh applicable evidence. Persisted scores must never be retrieved by question hash alone or copied to another request. If the authenticated provider path is unavailable, preserve the failure for the owner; do not invent an assessment or send context elsewhere.

Jev point scores represented as equal lower/upper basis-point bounds remain **point scores**. They are not calibrated confidence intervals; a real calibrated interval requires supporting provenance. The host owns that distinction and its record. Deterministic constraints still apply independently: `examples/green-investments.rs` rejects an expected-return loss above one **percentage point** (100 basis points), even with the highest preference score. This is distinct from a relative 1% return loss.

The [agent skill](skills/allowit/SKILL.md) includes JSON-context instructions, security boundaries and runnable commands.

## Embedding and wire protocol

Native callers use `process_value(serde_json::Value) -> serde_json::Value` or `process_json(&str) -> String`. The JSON API always compiles source before evaluation and rejects externally supplied executable IR.

Compiler output includes versioned [execution requirements](docs/execution-requirements.md), a conservative inventory of policy dependencies used by host skill assemblers. It does not grant permissions or assert that a dependency is reachable.

Compilation releases its temporary proc-macro source maps after every call so persistent hosts do not retain every edited document. No parser span escapes the SDK. The compiler is intended for standalone native/WASM hosts, not for execution from inside a Rust procedural macro. Hosts must not retain unrelated `proc_macro2::Span` values across compilation calls on the same thread. CLI/JSON error `line` and `column` are one-based Unicode-scalar positions; LSP converts columns to zero-based UTF-16.

```json
{"operation":"compile","source":"pub async fn execute(ctx: &Context) -> PolicyResult { Ok(()) }"}
```

Compilation returns `ok: true` and `policy` with `language: "allowit-rust-v1"`, source/IR SHA-256 digests, registry version, optional limit (empty string when uncapped), token, exact source, workflow blocks, call spans and typed IR. Evaluation accepts `operation: "evaluate"`, `source`, `profile: "oracle" | "contract"` and `context` in the shape of `examples/context.json`. It returns `decision.outcome`, `code` and `reason`, plus `prompt` and `input_key` when suspended. Invalid requests return `ok: false` and a typed `error`.

Parameter edits use the same JSON API and never regenerate the policy:

- `edit_preference`: `source` and `settings: {step_id, auto_approve, approve_percent, auto_deny, deny_percent}`. The ID is from the current compiled `check_preference` workflow block; percentages are strings. Both supported helper signatures are preserved.
- `edit_score_thresholds`: `source`, `step_id`, and `values: [9000, ...]`. Top-level semantic bindings expose `score_thresholds: [{field, operator, value_bps}]` for direct comparisons of `lower_bps`/`upper_bps` against integer or `percent` literals. Supply all displayed values in order, as integers in 0–10000. Operators and branch bodies stay unchanged; computed bounds and other unsupported expressions are not editable through this operation.

Both operations return `{ok: true, source, policy}` after recompilation, or a typed error. Only changed AST-selected argument/literal spans are replaced; comments, unrelated statements and unchanged values retain their exact bytes. IDs from another source revision fail. Hosts must independently authenticate edits and enforce draft/revision rules. These operations adjust decision thresholds, not the statistical validity of evidence.

Raw comparison editing is offered only when every use of that semantic binding is a supported direct literal comparison. Aliases, computed bounds, reversed comparisons or other uses omit the controls and reject this operation; a partial list is never treated as complete. In the four-argument helper, `None` stores no numeric threshold; enabling that outcome requires an explicit value. Changed literals use canonical decimal notation; unchanged literals keep their original spelling.

Workflow and call spans are **UTF-16 code-unit offsets** for browser strings and LSP. Internal IR spans use UTF-8 bytes. Predefined top-level calls with literal arguments become function blocks; contiguous custom statements remain exact Custom code, including their internal comments. Nested calls stay inside their custom block and retain individual help spans. The full source is retained byte-for-byte. The visual projection does not execute independently.

Oracle callers can add `"trace": true` to an evaluation request. The response then includes `trace: {version: 1, source_hash, ir_hash, complete, steps: [{node_id, status, visited}]}`. Every compiled workflow node appears exactly once in display order. IDs and hashes come from freshly compiled source, and a native caller can use `evaluate_with_trace(&policy, &context)`. Invalid artifacts return no trace. The default response is unchanged; a contract-profile request rejects `trace: true`, and contract builds omit the tracing code.

The trace records actual execution, including `set_cap` and `cap_purchase_tiers` checks hoisted before normal control flow. `passed` means the block's executed path completed; it does not mean every condition inside custom code ran. `failed` identifies the block that rejected the request. `verifying` identifies the exact block that requires semantic evidence; the trusted host should persist that state before calling Jev. `awaiting_input` identifies a block waiting for the owner. Both pending states have `complete: false`, with unreached nodes `inactive`. Terminal outcomes have `complete: true`, with unvisited nodes `skipped`, including a final `Ok(())` bypassed by an earlier return. Only `inactive` and `skipped` have `visited: false`. A block containing several custom statements remains one unit; its unselected branches are not separate workflow steps.

Hosts must bind each trace to the request, evaluation attempt and approved revision, verify both hashes and node IDs, and replace it after reevaluation rather than merge results across contexts. A host-level rejection has no policy node unless the host possesses an exact source binding. Trace status describes a policy check, never chain settlement or a transfer receipt. Displaying a previous run's trace must not imply that its checks passed for a newer request.

Contract adapters use `default-features = false`, `validate_program`, `canonical_ir_hash` and `evaluate_ir`. The contract must authenticate the IR artifact during owner activation and bind it to the action, owner, network, asset, current budget, original intent, runtime-context digest and authority. The `no_std` evaluator validates the complete IR but does not contain the source parser; it does not claim to recompile source on chain. Source digests are owner-bound metadata there. Native `evaluate` recompiles source to reject a forged source/IR correspondence and is available only with the compiler feature.

## WebAssembly

```sh
rustup target add wasm32-unknown-unknown
cargo rustc --locked --release --lib --target wasm32-unknown-unknown --crate-type cdylib
```

The artifact is `target/wasm32-unknown-unknown/release/allowit_sdk.wasm`. It imports no filesystem or network capabilities. The host must enforce memory and execution-time limits. A WebAssembly trap aborts Rust cleanup and can leave the stack or allocator state unusable: discard the instance after any trap and create a new instance for subsequent requests. Never retry against a trapped instance or interpret a trap as approval.

- `alloc(len: u32) -> u32`: allocate an input buffer.
- `process(ptr: u32, len: u32) -> u64`: process UTF-8 JSON, returning output pointer in the high 32 bits and output byte length in the low 32 bits.
- `dealloc(ptr: u32, len: u32)`: free the input and output once each, with their exact original lengths.

## Language server

`allowit lsp` uses standard `Content-Length` JSON-RPC framing on stdin/stdout. It implements initialization, full-document synchronization, compiler diagnostics, registry hover help, completion, shutdown and a custom `allowit/workflow` request. That request accepts `textDocument.uri` or explicit `source` and returns the same compiler artifact as the CLI/API. Diagnostics and workflow data cannot disagree with a separate visualization parser because they share the compiler.

## Verification boundaries

The [Lean demonstrator](verification/lean/README.md) supplies a pinned, checked model of compositional policy decisions and instruction-feature coverage. Its theorems do not establish Rust/Go implementation equivalence, complete natural-language intent coverage or classifier accuracy.

Tests cover exact limits, cap bypass attempts, arithmetic overflow, syntax rejection, forged IR, deterministic oracle/contract decisions, source spans, workflow retention, confidence failures, approval continuation keys, contract input failure, facade type-checking, LSP behavior and a seeded bounded mutation corpus. `contracts/` contains native rail adapters and their own build/test instructions. Compilation or a local contract test is not evidence that a program has been deployed or that funds moved on a public network.

## Readable amounts and comparisons

These helpers require source compiler revision `65a9bfe12f5abcbc7786a37b15f7f7a34f708dbd` or later. Older compilers reject helper source; the existing IR registry remains compatible because helpers lower to its existing operations. Hosts must pin the compiler artifact.

Use decimal strings in policy source; runtime context remains JSON with integer base units. The compiler checks these helpers and lowers them to the existing integer/comparison IR used by every rail. No floats or rounding are involved. Keep the `?` on each helper.

| Helper | Meaning |
| --- | --- |
| `usdc("25.50")?` | 25.50 USDC, exactly 25,500,000 units; up to six decimals. Zero is allowed in comparisons. |
| `percent("85.25")?` | 85.25%, exactly 8,525 basis points; 0–100 with up to two decimals. |
| `allowit::amount_at_most(ctx.amount_units, "25.50")?` | Whether this purchase is at or below 25.50 USDC, including equality. |
| `within_percentage_points(candidate, benchmark, "1")?` | Whether a candidate return is at most one percentage point below the benchmark. Both values are immutable integer variables or literals in basis points; 4% versus 5% passes. Higher returns pass. |

These helpers do not create an allowance. Use `set_cap` for the total allocation and `cap_per_transaction` for a per-purchase limit, with explicit positive integer units, currency and decimals. USDC has six policy decimals; Testnet uses its bound six-decimal test token. Other token precisions are not inferred from symbols. Rail adapters bind the actual asset and reject precision loss.

```rust
if !allowit::amount_at_most(ctx.amount_units, "25.50")? {
    allowit::require_user_input(ctx, "Approve this purchase above 25.50 USDC?").await?;
}
jev::check_preference(jev::preference_evidence(ctx, "Is there primary evidence supporting this purchase?"), "Is there primary evidence supporting this purchase?", 0.40, 0.85).await?;
```

Decimal helper arguments must be string literals. Excess decimal places, signs, exponent notation, separators and overflow are compile errors. Bind candidate and benchmark returns to variables before comparing them. Their values are claims until authenticated; comparison helpers do not establish provenance. Helpers inside custom logic keep their exact source and function tips in the workflow.

### Local development and preference thresholds

`local:dev` is a wallet-free oracle network. Contract evaluation rejects it. Local action records are never blockchain settlement.

`jev::check_preference(jev::preference_evidence(ctx, "Question?"), "Question?", 0.40, 0.85).await?;` checks explicit optional numeric evidence against denial and approval thresholds. The compiler binds the exact nested reader to the same question. Arbitrary scores, another question or another context cannot substitute for authenticated evidence. Enabled comparisons include equality. Denial must be strictly below approval when both are enabled. Disable either outcome independently; with both disabled, every reached check asks the owner without calling Jev. Missing or invalid evidence fails closed. The question, original intent and runtime JSON feed the host's Jev assessment. The one estimated field is `preference_fit: number` in `[0,1]`, a point score rather than calibrated confidence. The host rounds down to four decimal places and supplies equal integer basis-point bounds. Hard spending rules still apply.

The helper lowers to the existing semantic, branch, failure and user-input IR operations; no new contract opcode is added. Oracle input suspends for an authenticated answer; a reached input call fails in contracts. Top-level helpers get a distinct Jev workflow block with editable literal settings; nested calls remain inside their conditional custom code. Existing top-level `let fit = semantic(...)` calls also get their own workflow item, while the branches using the result remain custom code.


### Versioned compact policies and purchase tiers

Use the complete constructor-based source shown above. The primitive tier signature is `allowit::cap_purchase_tiers(ctx.amount_units, &ctx.token, &ctx.purchase_counts, 1_000_000, 2, "USDC", 6)?;`. The compiler binds these counts to the authoritative ledger.

Thresholds are exact source decimals in 0..1 with at most four decimal places. `None` disables that outcome; `auto("deny")` and `auto("approve")` resolve to the versioned defaults 0.40 and 0.85. They do not invoke a model to choose a threshold. Compiled workflow arguments expose the resolved percentages and enabled flags. Approval still requires every other rule to pass.

`cap_purchase_tiers` defines separate price bands: two purchases in (0.50, 1.00], four in (0.25, 0.50], eight in (0.125, 0.25], continuing down to the token's smallest representable unit. Boundaries belong to the cheaper band. There is no additional minimum price. It is an unconditional, single top-level configuration; the maximum is 1,000,000 USDC and the first count is 1..1,000,000.

The trusted oracle host supplies `purchase_counts`, exactly 40 unsigned counts derived from its durable ledger, including pending reservations. Callers must not supply authoritative counts through runtime context. Reservation and final evaluation must recheck counts atomically. Missing counts fail with `LEDGER_REQUIRED`. The current contract adapters reject tier policies at activation because they do not store this ledger; the contract evaluator also fails closed. A compiled tier badge describes oracle enforcement, not an on-chain certificate.

Consumers need a build containing this helper; older evaluators fail closed on the new registry call. Wire registry version remains unchanged, so use the SDK commit and artifact digest for compatibility. Context continues to enter the CLI or SDK as JSON; user-supplied runtime evidence is separate from authoritative ledger fields.

The default `oracle-ledger` feature includes host purchase counters. Contract builds disable default features and return `LEDGER_REQUIRED` for tier calls, excluding ledger-only code from tight on-chain upload budgets.

Builds without `oracle-ledger` reject purchase-tier IR during validation with `LEDGER_REQUIRED`, before any evaluation. The registry still describes the function so callers can identify this unsupported feature. The public `spending` module is available only with `oracle-ledger`. Default SDK WASM and host builds include it; contract builds exclude it.


## License

AllowIt-authored source is MIT licensed. Third-party licenses and the companion materials required when redistributing SDK or contract binaries, including historical Actions artifacts, are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Keep the full [licenses/](licenses/) directory and root license with redistributed binaries.
