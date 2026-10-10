# Native vault ABI v2 handoff

Native vault setup is one owner-signed Solana transaction: two fixed Compute
Budget instructions, idempotent vault-token-account creation, vault
initialization, the initial owner-funded deposit, and activation. Wallet connect
or sign-in is separate from this single setup confirmation. The shared policy
and custody programs must already be deployed.

`Policy` identifies both enforcement layers. `dailyLimit` and `actionLimit` are
the initial on-chain integer-token limits. `executionPolicyDigest`,
`executionRequirementsDigest`, and `semanticRequired` identify the actual
server-side policy gate; they are distinct from `rust` and `policyArtifact`,
which identify the small on-chain numeric adapter. Use
`Policy::generate_bound` with digests derived from authenticated, compiled
policy data. A numeric-only policy may use `Policy::generate`; it creates a
canonical numeric binding and never claims semantic evaluation.

`Config.authority` is the trusted server signing key's public address and must
be different from the owner and executor. `Binding` returns the exact ABI-v2
vault, token account, executor, and authority. `State` adds `authority`,
`actionLimit`, and the replay-safe `instanceSlot`. ABI-v1 320-byte state is
rejected; ABI v2 is 352 bytes and uses the `allowit-vault-v2` PDA seed.

The release remains bound to one initialized, six-decimal classic SPL Token
mint. That mint may retain its issuer freeze authority, but every token account
used by an operation must be unfrozen. If the issuer freezes a vault or
destination account, SPL Token blocks payment, withdrawal, or closure until
the issuer unfreezes it; this does not relax mint, network, or artifact checks.

## Operations

| Method | Wallet/signers | Result |
| --- | --- | --- |
| `deploy` | owner | Create, configure, initially fund, and activate atomically. `Options.amount` is required. |
| `fund` | owner | Deposit only from the owner's token account; it does not reset spend, nonce, or revision. |
| `execute` | executor + trusted authority | Pay the exact recipient and amount using expiry, commitment, nonce, revision, and instance slot. No owner prompt. |
| `tune` | owner | Change the daily limit and increment revision. |
| `tune_action` | owner | Change the per-action limit and increment revision. |
| `revoke` | owner | Withdraw standing approval and increment revision. |
| `withdraw` | owner | Return a specified amount to the owner's token account. |
| `close` | owner | Return the full balance, close the vault token account and state, and refund rent. `Options.instanceSlot` is required. |

An operation record is `uncertain`, `submitted`, `settled`, or `failed`.
Persist its canonical intent, all ordered signatures, exact signed bytes,
blockhash validity boundary, nonce, revision, expiry, commitment, and instance
slot before broadcast. Retry the same record; do not allocate a replacement
payment. Service delivery status is a separate backend concern.

## Trusted execution example

```rust
let approval = ApprovalCommitment::new(
    &policy,
    &state,
    operation_id,
    recipient_token_account,
    "0.25",
    expires_at,
    request_digest,
    assessment_digest, // Some only when policy.semantic_required is true
)?;
let options = approval.options()?;
let prepared = client.prepare(&policy, owner, "execute", &options)?;

// The server signs only after evaluating the identity-bound policy and request.
let authority_sig = authority.sign(&prepared.transaction.message);
let partial = prepared.transaction.partially_signed(&[
    (prepared.transaction.signers[1], authority_sig),
])?;

// The designated executor must preserve the message byte-for-byte.
let executor_sig = executor.sign(&prepared.transaction.message);
let signed = prepared.transaction.add_signature(
    &partial,
    prepared.transaction.signers[0],
    executor_sig,
)?;
Signed::parse(&signed)?.matches(&prepared.transaction)?;
```

`ApprovalCommitment` canonically binds the operation ID, policy identity and
revision, instance slot, network, custody program, vault, mint, recipient,
amount in base units, nonce, expiry, executor, authority, request digest,
execution-policy and requirements digests, and (only when required) assessment
digest. It records a trusted allow decision; it is not proof that an external
assessment is objectively correct.

`Transaction::partially_signed` preserves zero-filled missing signer slots;
`add_signature` accepts only an expected signer and the exact original message.
`Signed::parse` requires every signature, while `Signed::parse_partial` is the
only partial-proof parser. Transaction validation is byte-for-byte, so wallet
software may add its signature but may not reorder accounts or rewrite the
message.

`NativeClient::prepare` also simulates that exact message, with its real
blockhash, account table, instruction bytes, and Compute Budget instructions,
before asking for any signature. `Prepared.simulation` reports
`contextSlot`, `unitsConsumed`, and `transactionBytes`; a missing compute count
or any simulation error fails preparation. Simulation disables signature
verification only so the pre-sign message can run, and does not replace the
recent blockhash.

Before signing a server-authorized execution, the native lifecycle checks the processed chain tip at or after the simulation context slot. The blockhash must remain valid. At least 32 block heights and 30 seconds must remain in the two expiry bounds. An unavailable or stale observation requires fresh authorization. Recovery of an existing signed proof still uses finalized observations.
