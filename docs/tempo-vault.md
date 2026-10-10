# Tempo vault lifecycle

The `tempo-rust` crate validates prepared owner and executor transactions offline.
It does not hold keys, perform RPC calls, broadcast transactions or assert settlement.
The application backend owns policy evaluation, Jev assessment, owner-input
continuations and durable operation records. Tempo contracts enforce the funded
token, cumulative/daily/action caps, revision, nonce, expiry and EIP-712 authority.

Owner authentication uses an origin-bound, expiring EIP-191 sign-in challenge.
Owner, executor and authority must be separate accounts. A generated policy binds
the configured chain, immutable factory, predicted CREATE2 vault, actual TIP-20
token and symbol, compiled source digest and execution-requirements digest.

`POST /api/tempo/generate` accepts either an exact numeric prompt, an authenticated
owner's approved execution policy ID, or explicitly reviewed restricted Rust
source. `semanticRequired: true` generates visible numeric rules and a Jev
preference gate at denial ≤0.40 and approval ≥0.85; intermediate scores require an
exact owner-signed answer. Full original intent accompanies the assessment.
Caller JSON cannot supply trusted scores or owner answers. A signed owner answer
resumes evaluation and never overrides the contract or deterministic policy caps.

Prepare owner operations with `/api/tempo/prepare`: `approve_deploy`, `deploy`,
`approve_fund`, `fund`, `tune`, `revoke`, `withdraw`. Approvals name only the factory
or vault and the exact funding amount. Setup uses approval then atomic
create-and-fund. Further deposits preserve spend, nonce and revision. Tuning
preserves cumulative and daily usage. Revocation is permanent; withdrawal returns
the full remaining balance to the owner and revokes spending.

`/api/tempo/export` issues a policy-scoped executor capability. Executor
`/api/tempo/execute` returns `allow`, `deny` or `awaiting_input`. Only `allow`
includes prepared calldata and a server EIP-712 authority signature. The executor
must run `validate_execution_request` on the exact request and prepared plan
before submitting through its own wallet. A preparation is not a payment.

Owner `/api/tempo/submit` and executor `/api/tempo/report` accept only the original
request ID and transaction hash. The hash is a lookup hint; the backend verifies
the signer, chain, single call, recipient contract, exact calldata and value.
Tempo type `0x76` binds `calls[0]` and the explicit fee token. A canonical finalized
receipt must contain the exact vault event and real token transfer. Recovery
preserves unresolved hashes across restarts; a prepared payment without a hash
can fail as expired only after finalized chain time and unchanged vault nonce
prove it could not execute. Expiry and token quantities are exact decimal strings
on the JSON boundary.

Local configuration uses `ALLOWIT_TEMPO_NETWORK=tempo:localnet`, chain ID 31337
or 42431, loopback RPC, exact factory runtime Keccak hash, token, actual token
symbol, executor, authority, fee token and a server-local authority key file.
The test profile uses `tempo:testnet` and chain ID 42431. Missing deployment,
provider or authority configuration fails closed. Local validation uses private
chains only.
