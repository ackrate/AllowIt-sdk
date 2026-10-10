//! PaySH budget preparation regressions. Synthetic keys and an in-memory RPC;
//! no network requests, key files, or broadcasts.
use allowit_native::{
    crypto::{Key, LocalSigner},
    error::Result,
    paysh::{Deployment, PayShClient, PreparedExecution, interface},
    rpc::Rpc,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};

struct FixtureRpc {
    genesis: Key,
    accounts: BTreeMap<Key, Value>,
}

impl Rpc for FixtureRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        match method {
            "getGenesisHash" => Ok(json!(self.genesis.to_string())),
            "getAccountInfo" => {
                assert_eq!(params[1]["commitment"], "finalized");
                assert_eq!(params[1]["encoding"], "base64");
                let key = Key::parse(params[0].as_str().unwrap())?;
                Ok(json!({"context":{"slot":1000},"value":self.accounts.get(&key)}))
            }
            "getLatestBlockhash" => {
                assert_eq!(params[0]["commitment"], "finalized");
                Ok(json!({"context":{"slot":1000},"value":{
                    "blockhash":Key([33;32]).to_string(),"lastValidBlockHeight":2000
                }}))
            }
            _ => panic!("Unexpected RPC call {method}"),
        }
    }
}

fn account(owner: Key, executable: bool, data: &[u8], lamports: u64) -> Value {
    json!({"owner":owner.to_string(),"executable":executable,
        "data":[STANDARD.encode(data),"base64"],"lamports":lamports})
}

fn signer(byte: u8) -> LocalSigner {
    LocalSigner::from_secret(&ed25519_dalek::SigningKey::from_bytes(&[byte; 32]).to_keypair_bytes())
        .unwrap()
}

struct Fixture {
    deployment: Deployment,
    rpc: FixtureRpc,
    policy: Key,
    budget: Key,
    evaluator: LocalSigner,
    sponsor: LocalSigner,
}

impl Fixture {
    fn new() -> Self {
        let program = Key([1; 32]);
        let pool_program = Key([2; 32]);
        let genesis = Key([3; 32]);
        let evaluator = signer(7);
        let sponsor = signer(8);
        let owner = signer(9).public_key();
        // Complete upgradeable-loader headers and pinned synthetic program bytes.
        let mut program_data = vec![0; 45];
        program_data[..4].copy_from_slice(&3u32.to_le_bytes());
        program_data.extend([11, 12, 13]);
        let artifact = Sha256::digest(&program_data[45..]).into();
        let deployment = Deployment {
            program,
            genesis,
            module_digest: [4; 32],
            program_artifact: artifact,
            upgrade_authority: None,
            pool_program,
            pool_program_artifact: artifact,
            pool_upgrade_authority: None,
            lookup_table: None,
            compute_limit: 900_000,
        };
        let instance_id = [5; 32];
        let (policy, bump) =
            Key::find_program_address(&[interface::POLICY_SEED, &owner.0, &instance_id], program)
                .unwrap();
        let token = Key::parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let associated = Key::parse("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let usdc = Key([15; 32]);
        let wsol = Key::parse("So11111111111111111111111111111111111111112").unwrap();
        let vault = |mint: Key| {
            Key::find_program_address(&[&policy.0, &token.0, &mint.0], associated)
                .unwrap()
                .0
                .0
        };
        let config = interface::Config {
            instance_id,
            network: genesis.0,
            module_digest: [4; 32],
            evaluator: evaluator.public_key().0,
            treasury: [14; 32],
            usdc_mint: usdc.0,
            vault_usdc: vault(usdc),
            vault_wsol: vault(wsol),
            vendor_usdc: [18; 32],
            pool: interface::Pool {
                program: pool_program.0,
                state: [19; 32],
                wsol: [20; 32],
                usdc: [21; 32],
                oracle: [22; 32],
            },
            period_seconds: 3600,
            max_usdc_per_period: 1000,
            max_swap_lamports_per_period: 1000,
            max_fee_lamports_per_period: 1000,
            max_sol_debits_per_period: 1000,
            max_swap_lamports_per_call: 1000,
            max_total_swap_lamports: 1000,
            allocation_lamports: 1000,
            service_fee_lamports: 1,
            min_usdc_per_sol: 1,
            max_pool_fee_bps: 10,
            max_age_slots: 180,
            max_age_seconds: 60,
            policy_expires_timestamp: 7200,
            owner_only: false,
        };
        let p = interface::Policy {
            version: 1,
            bump,
            owner: owner.0,
            paused: false,
            total_swap_lamports: 0,
            total_sol_debits: 0,
            config,
        };
        let mut bytes = borsh::to_vec(&p).unwrap();
        bytes.resize(interface::POLICY_BYTES, 0);
        let loader = Key::parse("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
        let mut accounts = BTreeMap::new();
        for deployed in [program, pool_program] {
            let linked = Key::find_program_address(&[&deployed.0], loader).unwrap().0;
            let mut program_bytes = 2u32.to_le_bytes().to_vec();
            program_bytes.extend(linked.0);
            accounts.insert(deployed, account(loader, true, &program_bytes, 1_000_000));
            accounts.insert(linked, account(loader, false, &program_data, 1_000_000));
        }
        accounts.insert(policy, account(program, false, &bytes, 10_000_000));
        let mut clock = vec![0; 40];
        clock[..8].copy_from_slice(&1000u64.to_le_bytes());
        clock[32..40].copy_from_slice(&3600i64.to_le_bytes());
        accounts.insert(
            Key::parse("SysvarC1ock11111111111111111111111111111111").unwrap(),
            account(
                Key::parse("Sysvar1111111111111111111111111111111111111").unwrap(),
                false,
                &clock,
                1_000_000,
            ),
        );
        let budget = Key::find_program_address(
            &[interface::BUDGET_SEED, &policy.0, &1u64.to_le_bytes()],
            program,
        )
        .unwrap()
        .0;
        Self {
            deployment,
            rpc: FixtureRpc { genesis, accounts },
            policy,
            budget,
            evaluator,
            sponsor,
        }
    }

    fn set_budget(&mut self, owner: Key, executable: bool, data: &[u8], lamports: u64) {
        self.rpc
            .accounts
            .insert(self.budget, account(owner, executable, data, lamports));
    }

    fn prepare(self, amount: u64) -> Result<PreparedExecution> {
        let client = PayShClient::new(self.deployment, Arc::new(self.rpc))?;
        let request = client.draft(
            self.policy,
            interface::Action::PayUsdc { amount },
            [25; 32],
            [26; 32],
            [27; 32],
            [28; 32],
        )?;
        client.prepare_execute(&request, &self.evaluator, &self.sponsor)
    }
}

fn spent_budget() -> interface::Budget {
    interface::Budget {
        period: 1,
        usdc: 990,
        swap_lamports: 0,
        fee_lamports: 999,
        sol_debits: 999,
    }
}

#[test]
fn prefunded_empty_system_budget_prepares_the_same_payment_as_missing_budget() {
    let expected = Fixture::new().prepare(10).unwrap();
    // Rent-exempt empty-account donation, and an additional donation.
    for lamports in [890_880, 1_000_000] {
        let mut fixture = Fixture::new();
        fixture.set_budget(Key([0; 32]), false, &[], lamports);
        let actual = fixture.prepare(10).unwrap();
        assert_eq!(actual.request_bytes, expected.request_bytes);
        assert_eq!(actual.signed_bytes, expected.signed_bytes);
        assert_eq!(actual.receipt, expected.receipt);
    }
}

#[test]
fn allocated_budget_uses_existing_spending_and_accepts_exact_caps() {
    let mut fixture = Fixture::new();
    fixture.set_budget(
        fixture.deployment.program,
        false,
        &borsh::to_vec(&spent_budget()).unwrap(),
        1_000_000,
    );
    fixture.prepare(10).unwrap();
}

#[test]
fn allocated_budget_does_not_reset_usdc_fee_or_sol_spending() {
    for field in ["usdc", "fee", "sol"] {
        let mut budget = spent_budget();
        match field {
            "usdc" => budget.usdc += 1,
            "fee" => budget.fee_lamports += 1,
            "sol" => budget.sol_debits += 1,
            _ => unreachable!(),
        }
        let mut fixture = Fixture::new();
        fixture.set_budget(
            fixture.deployment.program,
            false,
            &borsh::to_vec(&budget).unwrap(),
            1_000_000,
        );
        assert_eq!(
            fixture.prepare(10).unwrap_err().message,
            "Approved PaySH budget would be exceeded",
            "{field} spending was not enforced"
        );
    }
}

#[test]
fn foreign_owned_or_nonempty_system_budget_is_rejected() {
    for (owner, data) in [
        (Key([99; 32]), vec![]),
        (Key([99; 32]), borsh::to_vec(&spent_budget()).unwrap()),
        (Key([0; 32]), vec![0]),
    ] {
        let mut fixture = Fixture::new();
        fixture.set_budget(owner, false, &data, 1_000_000);
        assert_eq!(
            fixture.prepare(10).unwrap_err().message,
            "Invalid budget account"
        );
    }
}

#[test]
fn allocated_budget_with_wrong_size_or_period_is_rejected() {
    for size in [0, interface::BUDGET_BYTES - 1, interface::BUDGET_BYTES + 1] {
        let mut fixture = Fixture::new();
        fixture.set_budget(fixture.deployment.program, false, &vec![0; size], 1_000_000);
        assert_eq!(
            fixture.prepare(10).unwrap_err().message,
            "Invalid budget account"
        );
    }
    let mut wrong_period = spent_budget();
    wrong_period.period = 2;
    let mut fixture = Fixture::new();
    fixture.set_budget(
        fixture.deployment.program,
        false,
        &borsh::to_vec(&wrong_period).unwrap(),
        1_000_000,
    );
    assert_eq!(
        fixture.prepare(10).unwrap_err().message,
        "Invalid budget binding"
    );
}

#[test]
fn executable_budget_accounts_are_rejected() {
    for allocated in [false, true] {
        let mut fixture = Fixture::new();
        let (owner, data) = if allocated {
            (
                fixture.deployment.program,
                borsh::to_vec(&spent_budget()).unwrap(),
            )
        } else {
            (Key([0; 32]), vec![])
        };
        fixture.set_budget(owner, true, &data, 1_000_000);
        assert_eq!(
            fixture.prepare(10).unwrap_err().message,
            "Invalid budget account"
        );
    }
}
