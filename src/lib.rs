#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "compiler")]
mod compiler;
#[cfg(feature = "compiler")]
mod editing;
#[cfg(feature = "compiler")]
pub mod lsp;
pub mod prelude;
/// Source type-checking facade. Authoritative provider admission uses evaluated IR.
pub mod paysh {
    /// Direct facade evaluation has no authenticated preflight host and fails closed.
    pub fn payment_request_from_curl(
        _outcome: &crate::typed_workflow::CurlOutcome,
        _request: &crate::typed_workflow::CurlRequest,
    ) -> Result<Option<crate::typed_workflow::PaymentRequest>, crate::prelude::PolicyError> {
        Err(crate::prelude::PolicyError {
            code: "WORKFLOW_INPUT_REQUIRED".into(),
            reason: "Use the authenticated host evaluator.".into(),
        })
    }
    /// Direct Rust execution has no authenticated host adapter and fails closed.
    pub fn call(
        _service_id: &str,
        _input_key: &str,
        _max_payment_units: u64,
        _max_swap_lamports: u64,
        _max_service_fee_lamports_per_execution: u64,
    ) -> bool {
        false
    }
}
mod protocol;
mod readability;
mod registry;
#[cfg(feature = "compiler")]
mod requirements;
mod runtime;
#[cfg(feature = "oracle-ledger")]
pub mod spending;
#[cfg(feature = "compiler")]
mod trace;
pub mod typed_workflow;
mod types;
// The source type-checking facade uses floats; contract execution is integer-only.
#[cfg(feature = "std")]
pub mod v1;
mod validation;

#[cfg(feature = "compiler")]
pub use compiler::compile;
pub use protocol::{process_json, process_value};
pub use registry::{FunctionInfo, registry};
// The crate name is the core namespace. Do not import an `allowit` module through
// the prelude: it would conflict with `use allowit::prelude::*` in Rust source.
#[cfg(feature = "compiler")]
mod params;
#[cfg(feature = "compiler")]
pub use params::native_storage_initializers;
mod primitives;
pub use prelude::{
    confidence, context_u64, fail, percent, require_user_input, semantic, usdc,
    within_percentage_points,
};
pub use primitives::{
    allow_actions, amount_at_most, cap_per_transaction, cap_purchase_tiers, is_one_of,
    require_merchant, require_recipient, set_cap,
};

#[cfg(feature = "std")]
pub use primitives::check_preference;
pub use primitives::{OwnerLimit, owner_limit, preference_evidence, stored_limit};

#[cfg(feature = "compiler")]
pub use runtime::evaluate;
pub use runtime::evaluate_ir;
#[cfg(feature = "compiler")]
pub use runtime::evaluate_with_trace;
pub use types::*;
pub use validation::validate_program;

pub fn canonical_ir_hash(program: &Program) -> Result<alloc::string::String, CompileError> {
    validate_program(program)?;
    let bytes = serde_json::to_vec(program)
        .map_err(|_| CompileError::new("INVALID_POLICY", "The policy cannot be serialized."))?;
    Ok(digest(&bytes))
}

pub fn semantic_evidence_key(question: &str) -> alloc::string::String {
    digest(question.as_bytes())
}

pub fn digest(bytes: &[u8]) -> alloc::string::String {
    #[cfg(target_os = "solana")]
    let hash = solana_sha256_hasher::hash(bytes).to_bytes();
    #[cfg(not(target_os = "solana"))]
    let hash = {
        use sha2::{Digest, Sha256};
        let value: [u8; 32] = Sha256::digest(bytes).into();
        value
    };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = alloc::string::String::with_capacity(64);
    for byte in hash {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 15) as usize] as char);
    }
    result
}

#[cfg(all(target_arch = "wasm32", feature = "compiler"))]
mod abi {
    use alloc::vec::Vec;
    /// Allocate a byte buffer. The caller owns it until calling `dealloc`.
    #[unsafe(no_mangle)]
    pub extern "C" fn alloc(len: u32) -> u32 {
        let mut data = alloc::vec![0_u8; len as usize].into_boxed_slice();
        let ptr = data.as_mut_ptr() as u32;
        core::mem::forget(data);
        ptr
    }
    /// Free exactly one buffer returned by alloc or process, with its original length.
    ///
    /// # Safety
    /// The caller must pass a live allocation and its exact length, once only.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn dealloc(ptr: u32, len: u32) {
        if len != 0 {
            unsafe {
                drop(Vec::from_raw_parts(
                    ptr as *mut u8,
                    len as usize,
                    len as usize,
                ));
            }
        }
    }
    /// Process JSON. Return high 32 bits pointer, low 32 bits byte length.
    ///
    /// # Safety
    /// Input must address a live readable allocation of at least len bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn process(ptr: u32, len: u32) -> u64 {
        let input = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
        let text = core::str::from_utf8(input).unwrap_or("");
        let output = crate::process_json(text).into_bytes().into_boxed_slice();
        let packed = ((output.as_ptr() as u64) << 32) | output.len() as u64;
        core::mem::forget(output);
        packed
    }
}

/// Direct facade evaluation has no installed profile validator and fails closed.
pub fn execution_request_validate(
    _request: &typed_workflow::ExecutionRequest,
) -> Result<typed_workflow::ValidatedExecutionRequest, prelude::PolicyError> {
    Err(prelude::PolicyError {
        code: "WORKFLOW_INPUT_REQUIRED".into(),
        reason: "Use the authenticated host evaluator.".into(),
    })
}

/// Direct budget facade has no authenticated protected accounting and fails closed.
pub fn execution_request_cap(
    _request: &typed_workflow::ValidatedExecutionRequest,
    _budget_id: &str,
    _asset_id: &str,
    _decimals: u64,
    _total_budget_units: u64,
    _max_debit_units: u64,
    _max_fee_units: u64,
) -> prelude::PolicyResult {
    Err(prelude::PolicyError {
        code: "WORKFLOW_BUDGET_REQUIRED".into(),
        reason: "Use the authenticated host evaluator.".into(),
    })
}
/// Direct budget facade has no authenticated protected accounting and fails closed.
pub fn payment_request_cap(
    _request: &typed_workflow::PaymentRequest,
    _budget_id: &str,
    _asset_id: &str,
    _decimals: u64,
    _total_budget_units: u64,
    _max_debit_units: u64,
    _max_fee_units: u64,
) -> prelude::PolicyResult {
    Err(prelude::PolicyError {
        code: "WORKFLOW_BUDGET_REQUIRED".into(),
        reason: "Use the authenticated host evaluator.".into(),
    })
}
