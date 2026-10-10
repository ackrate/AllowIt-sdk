---
name: allowit
description: Compile, inspect and evaluate AllowIt Rust policies with structured runtime JSON, including preference questions and deterministic spending limits.
---

# AllowIt policies

This is the Rust SDK developer skill. Use this repository's `cargo run --locked --` commands. The separate native Rust `allowit` action client uses `show/eval/exec/status`; generated consumer skills target that client. Compile the exact policy source before evaluating it. A valid compilation does not approve a transaction.

1. Read the original owner instructions and the immutable policy source. Preserve the original instructions across revisions and forks; never replace them with your own summary.
2. Put the complete available request context in a JSON file. Supply `amount_units`, `allocation_units`, `spent_units`, `action`, `merchant`, `recipient`, `token`, `network`, `now`, `original_intent` and `runtime_context`. Amounts use exact integer micro-USDC. Runtime context is an object, at most 16 KiB/depth8/128 entries. Original intent is at most 16 KiB. Include source/provenance information for claims.
3. Run `cargo run --locked -- compile POLICY.rs` and inspect its exact source, limits and workflow. Use `cargo run --locked -- registry` for supported functions and their help.
4. Run `cargo run --locked -- evaluate POLICY.rs CONTEXT.json oracle` or submit the equivalent JSON request to the authenticated engine. Inspect `decision.outcome` and `decision.code`; CLI process success alone is not approval.
5. A `pass` permits only the exact bound request within the host's authenticated mandate. It is not evidence that funds moved. The executing rail must enforce that mandate again and return an actual transaction result.

## Runtime JSON

```json
{
  "amount_units": 10000000,
  "allocation_units": 250000000,
  "spent_units": 0,
  "action": "investment",
  "merchant": "issuer.example",
  "recipient": "the exact destination address",
  "token": "USDC",
  "network": "devnet",
  "now": 1790590000,
  "original_intent": "Prioritize green investments and avoid hype without sacrificing more than one percentage point of expected annual return.",
  "runtime_context": {
    "candidate_yield_bps": 420,
    "benchmark_yield_bps": 500,
    "candidate_name": "Clean-energy bond",
    "environmental_claims": ["Proceeds fund renewable generation"],
    "sources": [{"url": "https://issuer.example/disclosures", "kind": "issuer disclosure"}]
  },
  "answers": {},
  "confidence": {}
}
```

Caller-provided facts are claims until authenticated by the host. Do not invent balances, evidence, answers or scores. The CLI accepts context for local evaluation; the production engine must reconstruct authoritative wallet, budget, timestamp and mandate fields itself and verify evidence provenance.

## Preferences and numeric rules

Use a separate configurable `check_preference` for each classification, including research purpose, wallet/merchant roles and customer-specific categories. Judge the supplied evidence against the user's definitions and exceptions. `allow_actions` is only caller-field string equality; it does not verify a category. Exact user-specified identifiers and numeric limits remain deterministic checks.

`check_preference` lowers to the `semantic` evidence operation. Missing evidence fails with `SEMANTIC_EVIDENCE_REQUIRED`, `question` and `evidence_key`; the key is lowercase SHA-256 of the exact UTF-8 question. A configured trusted engine asks Jev with that question, original instructions and complete bound runtime context, authenticates and persists the response, then reevaluates. The policy and SDK make no network calls. Missing provider capability leaves the assessment unresolved.

The question hash names a slot within one evaluation, not reusable approval. The trusted engine must bind evidence to the exact source/IR digests, revision, owner, action, amount, recipient, network, token, original intent, complete runtime-context digest and expiry. Never copy a score to another request or retrieve it by question hash alone. Changed context requires fresh applicable evidence. If the authorized provider path is unavailable, report the unresolved failure to the owner and stop that transaction.

If Jev supplies a point score, using equal `lower_bps` and `upper_bps` records a **point score**, not a statistically calibrated confidence interval. A calibrated interval needs separate supporting provenance. Missing, malformed or unverifiable evidence fails closed. Host-supplied `confidence` and `answers` are privileged; ordinary agents must not populate them to bypass checks.

Keep hard constraints deterministic. For a maximum loss of **one percentage point (100 basis points)**, `context_u64` reads strict integer values and this expression enforces the rule:

```rust
let candidate = context_u64(ctx, "candidate_yield_bps")?;
let benchmark = context_u64(ctx, "benchmark_yield_bps")?;
if !within_percentage_points(candidate, benchmark, "1")? {
    return fail("The expected return difference exceeds one percentage point");
}
```

This differs from a relative 1% decrease; preserve the owner's intended unit in the policy. No preference score can override this numeric failure, a spending cap, a wrong recipient or a wrong network.

An oracle `awaiting_input` result requires authenticated owner approval through the engine's continuation protocol. Never reuse an answer from another request. A smart contract fails every reached `require_user_input` call even if an answer exists. Cancellation, expiry, replay protection and fresh budget checks belong to the engine and rail.

Runnable policies and contexts are in `examples/research.rs`, `examples/approval.rs`, `examples/green-investments.rs` and `examples/green-context.json`. `cargo run --locked -- lsp` provides editor diagnostics, function help and the `allowit/workflow` projection from the same compiler.

## Readable amounts and comparisons

Use decimal strings in policy source; runtime context remains JSON with integer base units. The compiler checks these helpers and lowers them to the existing integer/comparison IR used by every rail. No floats or rounding are involved. Keep the `?` on each helper.

| Helper | Meaning |
| --- | --- |
| `usdc("25.50")?` | 25.50 USDC, exactly 25,500,000 units; up to six decimals. Zero is allowed in comparisons. |
| `percent("85.25")?` | 85.25%, exactly 8,525 basis points; 0–100 with up to two decimals. |
| `amount_at_most(ctx, "25.50")?` | Whether this purchase is at or below 25.50 USDC, including equality. |
| `within_percentage_points(candidate, benchmark, "1")?` | Whether a candidate return is at most one percentage point below the benchmark. Both values are immutable integer variables or literals in basis points; 4% versus 5% passes. Higher returns pass. |

These helpers do not create an allowance. Use `set_cap` for the total allocation and `cap_per_transaction` for a per-purchase limit, with positive decimal strings. USDC has six policy decimals; Testnet uses its bound six-decimal test token. Other token precisions are not inferred from symbols. Rail adapters bind the actual asset and reject precision loss.

```rust
if !amount_at_most(ctx, "25.50")? {
    require_user_input(ctx, "Approve this purchase above 25.50 USDC?").await?;
}
check_preference(ctx, "Is there primary evidence supporting this purchase?", true, "85", true, "40").await?;
```

Decimal helper arguments must be string literals. Excess decimal places, signs, exponent notation, separators and overflow are compile errors. Bind candidate and benchmark returns to variables before comparing them. Their values are claims until authenticated; comparison helpers do not establish provenance. Helpers inside custom logic keep their exact source and function tips in the workflow.

## Preference gates and Local dev

Use `check_preference(ctx, "Exact preference question", true, "85", true, "40").await?;` for a configurable Jev gate. The flags enable automatic approval at or above 85% and denial at or below 40%. Other scores require the owner's answer. Both flags may be disabled; that asks the owner without calling Jev. Thresholds are exact decimal percentage strings from 0 to 100 with at most two decimals; denial must be below approval when both outcomes are enabled. A preference pass cannot override other constraints. The host's explicit assessment result is an object with exactly one numeric field, `preference_fit`, from 0 to 1; it is not calibrated confidence or multiple estimated dimensions. Context is provided as JSON into the CLI or SDK and forwarded by the trusted host with the exact question and original owner intent.

`local:dev` runs only in the oracle profile. Local records consume the local budget without a wallet or blockchain settlement. A consumer-generated SKILL.md can contain a private scoped access URL and bearer header. Treat that file as a credential, send it only to the intended agent, keep authorization on its specified origin, and obey its expiry/revocation. The capability does not authorize independent wallet spending.


### Versioned compact policies and purchase tiers

New source can use `use allowit::v1::prelude::*;` and `pub async fn execute(ctx: &Context) -> PolicyResult`. The legacy import, `exec` and `evaluate` function names and six-argument preference form remain accepted. The compact versioned form is:

```rust
use allowit::v1::prelude::*;

pub async fn execute(ctx: &Context) -> PolicyResult {
    set_cap(ctx, "10", "USDC")?;
    cap_purchase_tiers(ctx, "1", 2, "USDC")?;
    check_preference(ctx,
        "Does this purchase count as research under the user's stated purpose and definitions?",
        0.40,
        0.85,
    ).await?;
    check_preference(ctx,
        "Is this primary evidence for the research task?",
        0.40, // deny at or below
        0.85, // approve at or above
    ).await?;
    Ok(())
}
```

Thresholds are exact source decimals in 0..1 with at most four decimal places. `None` disables that outcome; `auto("deny")` and `auto("approve")` resolve to the versioned defaults 0.40 and 0.85. They do not invoke a model to choose a threshold. Compiled workflow arguments expose the resolved percentages and enabled flags. Approval still requires every other rule to pass.

`cap_purchase_tiers` defines separate price bands: two purchases in (0.50, 1.00], four in (0.25, 0.50], eight in (0.125, 0.25], continuing down to the token's smallest representable unit. Boundaries belong to the cheaper band. There is no additional minimum price. It is an unconditional, single top-level configuration; the maximum is 1,000,000 USDC and the first count is 1..1,000,000.

The trusted oracle host supplies `purchase_counts`, exactly 40 unsigned counts derived from its durable ledger, including pending reservations. Callers must not supply authoritative counts through runtime context. Reservation and final evaluation must recheck counts atomically. Missing counts fail with `LEDGER_REQUIRED`. The current contract adapters reject tier policies at activation because they do not store this ledger; the contract evaluator also fails closed. A compiled tier badge describes oracle enforcement, not an on-chain certificate.

Consumers need a build containing this helper; older evaluators fail closed on the new registry call. Wire registry version remains unchanged, so use the SDK commit and artifact digest for compatibility. Context continues to enter the CLI or SDK as JSON; user-supplied runtime evidence is separate from authoritative ledger fields.

Generate a single `execute` entrypoint and call standard system functions for standard enforcement. Do not duplicate standard checks in generated helper functions. The native Solana profile exposes its compiled `policy_api.rs` separately from the policy source; its daily ceiling and UTC rollover are system enforcement, not custom generated logic.


## PaySH agent execution

Use the owner-issued policy ID, backend URL and scoped capability from the generated consumer skill. Discover enabled services with `allowit paysh services`. The backend catalog describes available services and prices; it does not provide popularity or reputation unless the provider includes those fields.

```sh
allowit paysh call POLICY_ID OPERATION_ID SERVICE_ID INPUT_JSON
allowit paysh status POLICY_ID OPERATION_ID
```

Set `ALLOWIT_URL` and `ALLOWIT_PAYSH_TOKEN` from the owner handoff in a private environment. Keep the capability out of logs and tracked files. Do not load the owner's wallet key or the backend evaluator or sponsor keys. The backend authenticates the provider challenge, reads native balances and bounded direct-pool quotes, evaluates the original task with Jev, and prepares scoped signed `execute(request)` transactions. A unique operation ID identifies the request; it does not authorize it.

The policy wallet pays the approved service fee first within each successful execution. A separate backend sponsor pays network fees and account rent. A swap may require one execution before the payment execution. Direct-pool swaps still pay the pool's liquidity fee. Testnet uses a custom test token, not mainnet USDC.

Keep the same operation ID after an uncertain response and read `status`; do not create a replacement purchase or assume payment means delivery. Exit 0 means the API response was delivered. Exit 12 means pending, 5 means unknown, and 20 means failed. Missing semantic evidence, provider compatibility or native enforcement fails closed.
