# Native Solana policy lifecycle

The JavaScript SDK links the native Rust source in AllowIt-contracts-solana to
owner lifecycle commands and the AllowIt browser. It is a separate adapter from
the restricted Rust compiler/WASM and owner-signed wallet allowance profile.

`new NativePolicySDK(config).generate(prompt)` has exactly one generation
argument. Network, prompt author, deployment, mint and executor are instance
configuration. The default offline author accepts `Spend up to 5 test tokens per
day`, optionally followed by `with PaySH discovery`. It refuses other rules;
it never drops merchant, recipient or purpose restrictions to make deployment
succeed. A host can inject an author returning `{dailyLimit, payDiscovery,
unsupported}`; unsupported constraints must be enumerated and cause refusal.

Each generation creates an explicit new policy instance and vault identity. Keep
its policy.json for all retries; do not regenerate after a lost response. Multiple
vaults have independent limits, not a global owner budget.

Generation returns the **actual pinned Rust policy module** plus its effective
daily-limit parameter. It does not compile arbitrary prompt-authored Rust or
upload a new executable per wallet. Shared immutable policy/custody deployments
are provisioned once; `deploy` creates the policy-bound PDA and token account
and records standing approval atomically in one owner-signed transaction.

## Owner CLI

File journals require a local POSIX filesystem. Native Windows journals are not supported.
On Windows, run the CLI in Linux/WSL. Keep policy and journal state in the Linux filesystem, not `/mnt/c` or `/mnt/d`.
Do not delete an existing Windows journal after an error. Keep its signed proofs and reconcile uncertain operations before another submission.
The platform check runs before the CLI reads keys, writes state, or contacts RPC.

Node >=22 is required for this compatibility SDK. Install with `npm ci` in this
directory and run its client with `node cli.mjs`. The separate Rust
[`allowit` action CLI](https://github.com/AllowIt-hq/allowit-cli) uses the vendored
Rust transport. The repository's Rust compiler CLI is a developer tool.

```sh
node cli.mjs policy generate 'Spend up to 5 test tokens per day with PaySH discovery'
# Or retain the exact browser instance:
# node cli.mjs policy import executor.json
node cli.mjs policy deploy
node cli.mjs policy fund 10
node cli.mjs policy execute RECIPIENT_TOKEN_ACCOUNT 2
node cli.mjs policy status
node cli.mjs policy revoke
node cli.mjs policy withdraw 8
```

Generate prints Rust and parameters and saves policy.json. Deploy prints the
skill and explorer link only after finalized confirmation. Fund prints its
explorer link. All commands accept `--json`. `tune 0` pauses an approved vault;
positive tuning restores its limit within the compiled maximum of 50 tokens.
Revocation preserves funds and counters; withdrawal is owner-controlled.

Environment overrides and the public imported context configure the lifecycle:

| Variable | Value |
| --- | --- |
| ALLOWIT_POLICY_DIR | Private policy/journal directory; default `.allowit` |
| ALLOWIT_POLICY_FILE | Optional policy.json path |
| ALLOWIT_NETWORK | `solana:testnet` default; `solana:devnet` is explicit |
| ALLOWIT_RPC_URL | RPC for the selected cluster; genesis is checked |
| ALLOWIT_DEPLOYMENT_FILE | Public manifest: network, sourceBundle, policy, policyData, custody |
| ALLOWIT_MINT | Initialized classic SPL six-decimal test mint |
| ALLOWIT_EXECUTOR | Designated executor public key |
| ALLOWIT_OWNER | Public owner key for executor/status; no owner signing key is loaded |
| ALLOWIT_OWNER_KEYPAIR | Dedicated owner test key; regular file, mode 0600 |
| ALLOWIT_EXECUTOR_KEYPAIR | Dedicated executor test key, 0600; execute only |
| ALLOWIT_ADDITIONAL_OWNER_OPERATION | `1` explicitly authorizes another fund/withdraw only after verified expiry of the unresolved prior operation |
| ALLOWIT_REQUEST_ID | Optional distinct ASCII request ID for a new intended operation |

Generate requires no key, RPC or deployment. Status requires no signer. Execute loads only the executor signer. Owner commands
load the owner signer. Other commands verify both
immutable loader-v3 deployed artifacts and the mint. Revoke/withdraw check
custody while remaining independent of policy-program availability.

The default request ID is a hash of the full intent and configuration. Repeating
the same command recovers the same operation. For a genuinely new same-amount
fund/transfer, set a fresh `ALLOWIT_REQUEST_ID`; do not change it after uncertainty.
Exit 5 means unconfirmed/uncertain, 20 policy refusal or finalized failure,
6 replay of a settled earlier operation, 3 invalid configuration. A missing/pruned signature alone is uncertainty. An expired execute can be
released only when finalized height exceeds validity and a coherent finalized
vault observation retains its exact nonce (even if tuning/revocation advanced revision). Revoke/tune can also prove nonexecution from an unchanged revision, and deploy from an absent uniquely derived vault at that coherent finalized slot. Fund/withdraw have no marker and stay uncertain without their finalized receipt; an owner may explicitly authorize an additional operation after verified expiry while retaining the original proof. Status never signs a replacement.
The local journal serializes one unresolved executor spend per policy and guards unresolved deposits/withdrawals per method. Use a new request ID plus `ALLOWIT_ADDITIONAL_OWNER_OPERATION=1` only for an explicitly additional owner operation after verified expiry; the earlier proof remains uncertain. It is
not a distributed signing service; multiple devices/process journals sharing
an executor require a gateway with transactional storage before production.

A crashed process may leave `.lock`; after verifying that process has stopped,
remove only the empty lock directory. Keep all signed request files. Never
clear a request to work around an unknown outcome. Local files must remain
private. Neither source artifacts nor SKILL.md contain a signing key.

## Browser integration

Import `NativePolicySDK` and `PolicyLifecycle`/`BrowserJournal` from `./browser`.
Use Wallet Standard **signTransaction**. The lifecycle checks the exact message
and signatures, commits proof to IndexedDB, then broadcasts. Do not inject
signAndSend, which may broadcast before persistence. Signing keys remain in the
wallet. Executor spending uses the separately configured CLI signer.

Finalized status additionally verifies the exact recorded message; executor
transfers require native policy/SPL inner invocations and exact token deltas.
Daily limits, approval, executor, nonce and revision are chain enforcement.
Task purpose and PaySH guidance are metadata. Opt-in PaySH instructions support
discovery only and refuse payment execution and ordinary-wallet fallback.
Stock PaySH x402/MPP verifiers are not claimed to accept vault CPI transfers.

## Verification

`npm test` covers ABI, generation binding, mint layout, genesis refusal,
substituted signed proof and exact-byte retry. `scripts/e2e.mjs` performs real
RPC setup and deploy/fund/execute/retry/denial/pause/revoke/withdraw. It also
bypasses client checks to simulate an over-limit native transfer and requires
contract rejection. Testnet is default. Explicit localhost mode requires
`ALLOWIT_LOCAL_GENESIS` and is recorded as **local-validator**, never as public
Testnet acceptance. `ALLOWIT_E2E_DIR` stores private test identities and public
receipt evidence. Shared program provisioning must precede that test.

Browser handoff downloads SKILL.md and executor.json. `policy import` preserves
the original policy instance and writes only public configuration; configure
the executor signer separately. Status reads all saved operations.

Generated Rust contains only `execute`, calling standard `require_approval` and `enforce_daily_limit` system functions. Their exact implementation lives in the paired, pinned `policy_api.rs`, included in the source-bundle identity. Standard daily rollover, overflow, approval and compiled parameter bounds are not regenerated per policy. The native ABI remains version 1; a new immutable policy version is required for this source bundle. The separate restricted-Rust compiler also accepts `execute` for new policies and retains read compatibility with historical `exec` and `evaluate` source.
