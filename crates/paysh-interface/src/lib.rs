//! Minimal bounded PaySH profile. Borsh bytes are the signed protocol.
pub mod allowlist;
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
pub const DOMAIN: &[u8] = b"allowit-paysh-request-v2";
pub const POLICY_SEED: &[u8] = b"paysh-policy-v2";
pub const SOL_SEED: &[u8] = b"paysh-sol-v2";
pub const RECEIPT_SEED: &[u8] = b"paysh-receipt-v2";
pub const BUDGET_SEED: &[u8] = b"paysh-budget-v2";
pub const POLICY_BYTES: usize = 1024;
pub const RECEIPT_BYTES: usize = 73;
pub const BUDGET_BYTES: usize = 40;
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Pool {
    pub program: [u8; 32],
    pub state: [u8; 32],
    pub wsol: [u8; 32],
    pub usdc: [u8; 32],
    pub oracle: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Config {
    pub instance_id: [u8; 32],
    pub network: [u8; 32],
    pub module_digest: [u8; 32],
    pub evaluator: [u8; 32],
    pub treasury: [u8; 32],
    pub usdc_mint: [u8; 32],
    pub vault_usdc: [u8; 32],
    pub vault_wsol: [u8; 32],
    pub vendor_usdc: [u8; 32],
    pub pool: Pool,
    pub period_seconds: u64,
    pub max_usdc_per_period: u64,
    pub max_swap_lamports_per_period: u64,
    pub max_fee_lamports_per_period: u64,
    pub max_sol_debits_per_period: u64,
    pub max_swap_lamports_per_call: u64,
    pub max_total_swap_lamports: u64,
    pub allocation_lamports: u64,
    pub service_fee_lamports: u64,
    pub min_usdc_per_sol: u64,
    pub max_pool_fee_bps: u64,
    pub max_age_slots: u64,
    pub max_age_seconds: u64,
    pub policy_expires_timestamp: i64,
    pub owner_only: bool,
    /// Zero denies every service. Committed by the owner at initialization.
    pub service_allowlist_root: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum Action {
    PayUsdc {
        amount: u64,
    },
    SwapSolToUsdc {
        amount_in_lamports: u64,
        min_out_usdc: u64,
        sqrt_price_limit: u128,
        tick_arrays: [[u8; 32]; 3],
    },
}
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct Request {
    pub network: [u8; 32],
    pub program: [u8; 32],
    pub policy: [u8; 32],
    pub owner: [u8; 32],
    pub module_digest: [u8; 32],
    pub operation_id: [u8; 32],
    pub nonce: [u8; 32],
    pub challenge_hash: [u8; 32],
    pub evidence_hash: [u8; 32],
    pub signing_slot: u64,
    pub signing_timestamp: i64,
    pub expires_slot: u64,
    pub expires_timestamp: i64,
    pub service_fee_lamports: u64,
    pub action: Action,
    pub service_hash: [u8; 32],
    pub service_proof: Vec<[u8; 32]>,
}
impl Request {
    pub fn signed_message(&self) -> Vec<u8> {
        let mut b = DOMAIN.to_vec();
        b.extend(Sha256::digest(
            borsh::to_vec(self).expect("fixed schema serializes"),
        ));
        b
    }
}
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Instruction {
    Initialize(Config),
    Execute(Request),
    Pause(bool),
    /// Owner recovery; leaves a permanent paused policy tombstone.
    Withdraw,
}
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct Policy {
    pub version: u8,
    pub bump: u8,
    pub owner: [u8; 32],
    pub paused: bool,
    pub total_swap_lamports: u64,
    pub total_sol_debits: u64,
    pub config: Config,
}
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct Budget {
    pub period: u64,
    pub usdc: u64,
    pub swap_lamports: u64,
    pub fee_lamports: u64,
    pub sol_debits: u64,
}
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct Receipt {
    pub version: u8,
    pub request_hash: [u8; 32],
    pub operation_id: [u8; 32],
    pub signing_timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_python_pay_vector() {
        let r = Request {
            network: [1; 32],
            program: [2; 32],
            policy: [3; 32],
            owner: [4; 32],
            module_digest: [5; 32],
            operation_id: [6; 32],
            nonce: [7; 32],
            challenge_hash: [8; 32],
            evidence_hash: [9; 32],
            signing_slot: 1000,
            signing_timestamp: 3601,
            expires_slot: 1180,
            expires_timestamp: 3661,
            service_fee_lamports: 1000,
            action: Action::PayUsdc { amount: 1_000_000 },
            service_hash: [10; 32],
            service_proof: vec![],
        };
        let b = borsh::to_vec(&r).unwrap();
        assert_eq!(b.len(), 373);
        let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
        assert_eq!(
            hex(&Sha256::digest(&b)),
            "e72846d82451c2f9b51ee4ce1cef61f2328ac50507a79bef50eca65aebbf344b"
        );
        assert_eq!(r.signed_message().len(), 56);
        assert_eq!(
            hex(&Sha256::digest(r.signed_message())),
            "9781ded0f32e4f7b39c3eb3f2e854a6852c3d760fcbc68531987b7297ddd7ec7"
        );
    }
}
