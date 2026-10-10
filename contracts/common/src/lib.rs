#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use allowit_sdk::{
    Context, Decision, Profile, Program, canonical_ir_hash, evaluate_ir, supported_registry_version,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

pub mod binary;
#[cfg(feature = "integer-json")]
mod integer_json;

pub const CORE_VERSION: &str = "0.1.0";
pub const MAX_ARTIFACT_BYTES: usize = 16_384;
#[cfg(not(feature = "stellar"))]
pub const MAX_CHAIN_ARTIFACT_BYTES: usize = 8192;
#[cfg(feature = "stellar")]
pub const MAX_CHAIN_ARTIFACT_BYTES: usize = 4096;
pub const MAX_CHAIN_IR_NODES: usize = 256;
pub const MAX_CHAIN_IR_DEPTH: usize = 8;

/// Bounded target profile shared by the Solana and Stellar interpreters.
/// Larger SDK/headless profiles do not imply that every policy fits a chain VM.
pub fn validate_chain_artifact(mandate: &Mandate, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_CHAIN_ARTIFACT_BYTES {
        return Err(Error::InvalidArtifact);
    }
    let artifact = validate_artifact(mandate, bytes)?;
    validate_chain_program(&artifact.ir)
}

// SDK host features can be unified by native callers; every non-chain node fails closed.
#[allow(unreachable_patterns)]
fn validate_chain_program(program: &Program) -> Result<(), Error> {
    // Authenticated host workflow handles are not executable by this chain profile.
    if program.version != "1.0.0" {
        return Err(Error::InvalidArtifact);
    }
    use allowit_sdk::{Expr, Statement};
    enum Node<'a> {
        S(&'a Statement),
        E(&'a Expr),
    }
    let mut pending: Vec<_> = program.statements.iter().map(|s| (Node::S(s), 1)).collect();
    let mut count = 0;
    while let Some((node, depth)) = pending.pop() {
        count += 1;
        if count > MAX_CHAIN_IR_NODES || depth > MAX_CHAIN_IR_DEPTH {
            return Err(Error::InvalidArtifact);
        }
        let next = depth + 1;
        match node {
            Node::S(
                Statement::Let { value, .. }
                | Statement::Return { value, .. }
                | Statement::Expression { value, .. },
            ) => pending.push((Node::E(value), next)),
            Node::S(Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            }) => {
                pending.push((Node::E(condition), next));
                pending.extend(
                    then_branch
                        .iter()
                        .chain(else_branch)
                        .map(|s| (Node::S(s), next)),
                );
            }
            Node::E(
                Expr::Try { value }
                | Expr::Await { value }
                | Expr::Not { value }
                | Expr::Field { object: value, .. },
            ) => pending.push((Node::E(value), next)),
            Node::E(Expr::Binary { left, right, .. }) => {
                pending.push((Node::E(left), next));
                pending.push((Node::E(right), next));
            }
            Node::E(Expr::Call { name, .. })
                if matches!(
                    name.as_str(),
                    "cap_purchase_tiers" | "allowit::cap_purchase_tiers" | "paysh::call"
                ) =>
            {
                return Err(Error::InvalidArtifact);
            }
            Node::E(Expr::Array { values } | Expr::Call { args: values, .. }) => {
                pending.extend(values.iter().map(|e| (Node::E(e), next)))
            }
            Node::E(
                Expr::String { .. }
                | Expr::Integer { .. }
                | Expr::Boolean { .. }
                | Expr::Unit
                | Expr::Variable { .. },
            ) => {}
            _ => return Err(Error::InvalidArtifact),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct EvidenceAuthority {
    pub key: [u8; 32],
    pub key_id: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Interval {
    pub name: String,
    pub lower_bps: u64,
    pub upper_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Evidence {
    pub request_hash: String,
    pub key_id: String,
    pub version: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub intervals: Vec<Interval>,
}

/// These exact fields are approved by BOTH the owner and the named compiler.
/// Compiler authorization is an explicit trust boundary: a chain cannot re-run
/// the host Rust parser and therefore verifies an authenticated compiler artifact.
#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Mandate {
    pub policy_id: [u8; 32],
    pub owner: [u8; 32],
    pub executor: [u8; 32],
    pub compiler: [u8; 32],
    pub compiler_key_id: String,
    pub compiler_version: String,
    pub evidence_authority: Option<EvidenceAuthority>,
    pub registry_version: String,
    pub core_version: String,
    pub network: String,
    pub asset: [u8; 32],
    pub asset_decimals: u32,
    pub recipient: [u8; 32],
    pub recipient_address: String,
    pub action: String,
    pub merchant: String,
    pub revision: u64,
    pub expires_at: u64,
    pub allocation_units: u64,
    pub source_hash: String,
    pub ir_hash: String,
    pub artifact_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct State {
    pub mandate: Mandate,
    pub artifact: Vec<u8>,
    pub active: bool,
    pub revoked: bool,
    pub spent_units: u64,
    pub next_nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct Request {
    pub nonce: u64,
    pub revision: u64,
    pub amount_units: u64,
    pub asset: [u8; 32],
    pub recipient: [u8; 32],
    pub network: String,
    pub action: String,
    pub merchant: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub evidence: Option<Evidence>,
    /// JSON object. The evidence signer attests these exact bytes.
    pub runtime_context: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Immutable owner intent, covered by artifact_hash and both authorizations.
    pub original_intent: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub registry_version: String,
    pub core_version: String,
    pub compiler_version: String,
    pub ir: Program,
}

/// Host-side attester entry point. Compile the reviewed source, do not accept a
/// client's independently supplied IR. Both owner and compiler authenticate the
/// serialized result during rail activation.
#[cfg(feature = "compiler")]
pub fn compile_artifact(
    source: &str,
    original_intent: &str,
) -> Result<Artifact, allowit_sdk::CompileError> {
    if original_intent.len() > 2048 {
        return Err(allowit_sdk::CompileError::new(
            "INVALID_INTENT",
            "Contract intent may contain at most 2048 bytes.",
        ));
    }
    let compiled = allowit_sdk::compile(source)?;
    Ok(Artifact {
        original_intent: original_intent.into(),
        source_hash: compiled.source_hash,
        ir_hash: compiled.ir_hash,
        registry_version: compiled.registry_version,
        core_version: CORE_VERSION.into(),
        compiler_version: CORE_VERSION.into(),
        ir: compiled.ir,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    InvalidMandate = 1,
    InvalidArtifact = 2,
    ArtifactMismatch = 3,
    Inactive = 4,
    Expired = 5,
    BindingMismatch = 6,
    Replay = 7,
    BudgetExceeded = 8,
    PolicyDenied = 9,
    UserInputRequired = 10,
    Overflow = 11,
    Unauthorized = 12,
    InvalidAccount = 13,
    AlreadyInitialized = 14,
    EvidenceRequired = 15,
    InvalidEvidence = 16,
}

fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_mandate(m: &Mandate) -> Result<(), Error> {
    if let Some(authority) = &m.evidence_authority {
        if authority.key == [0; 32]
            || !bounded(&authority.key_id, 64)
            || !bounded(&authority.version, 32)
        {
            return Err(Error::InvalidMandate);
        }
    }
    if [
        m.policy_id,
        m.owner,
        m.executor,
        m.compiler,
        m.asset,
        m.recipient,
    ]
    .contains(&[0; 32])
        || !bounded(&m.compiler_key_id, 64)
        || !bounded(&m.compiler_version, 32)
        || !supported_registry_version(&m.registry_version)
        || m.core_version != CORE_VERSION
        || !bounded(&m.network, 96)
        || !(6..=7).contains(&m.asset_decimals)
        || !bounded(&m.recipient_address, 128)
        || !bounded(&m.action, 64)
        || !bounded(&m.merchant, 128)
        || m.revision == 0
        || m.expires_at == 0
        || m.allocation_units == 0
        || !is_hash(&m.source_hash)
        || !is_hash(&m.ir_hash)
        || !is_hash(&m.artifact_hash)
    {
        return Err(Error::InvalidMandate);
    }
    Ok(())
}

pub fn mandate_hash(m: &Mandate) -> Result<String, Error> {
    validate_mandate(m)?;
    let bytes = borsh::to_vec(m).map_err(|_| Error::InvalidMandate)?;
    Ok(allowit_sdk::digest(&bytes))
}

/// Snapshot authentication binds the whole mandate and exact request, including
/// nonce/revision/asset/amount/recipient. The evidence bytes are excluded so the
/// attester can sign a non-recursive payload containing this hash.
pub fn request_hash(m: &Mandate, request: &Request) -> Result<String, Error> {
    let mut stripped = request.clone();
    stripped.evidence = None;
    let mut bytes = borsh::to_vec(m).map_err(|_| Error::InvalidMandate)?;
    bytes.extend_from_slice(&borsh::to_vec(&stripped).map_err(|_| Error::InvalidMandate)?);
    Ok(allowit_sdk::digest(&bytes))
}

fn validate_artifact_bytes(m: &Mandate, bytes: &[u8]) -> Result<(), Error> {
    validate_mandate(m)?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(Error::InvalidArtifact);
    }
    if allowit_sdk::digest(bytes) != m.artifact_hash {
        return Err(Error::ArtifactMismatch);
    }
    Ok(())
}

pub fn validate_artifact(m: &Mandate, bytes: &[u8]) -> Result<Artifact, Error> {
    validate_artifact_bytes(m, bytes)?;
    let artifact: Artifact = serde_json::from_slice(bytes).map_err(|_| Error::InvalidArtifact)?;
    validate_decoded_artifact(m, artifact)
}

pub fn validate_binary_artifact(m: &Mandate, bytes: &[u8]) -> Result<Artifact, Error> {
    validate_artifact_bytes(m, bytes)?;
    let artifact = binary::decode(bytes)?;
    validate_chain_program(&artifact.ir)?;
    // Changing the wire format must not widen the tested chain policy profile.
    if serde_json::to_vec(&artifact)
        .map_err(|_| Error::InvalidArtifact)?
        .len()
        > MAX_CHAIN_ARTIFACT_BYTES
    {
        return Err(Error::InvalidArtifact);
    }
    validate_decoded_artifact(m, artifact)
}

pub fn validate_binary_chain_artifact(m: &Mandate, bytes: &[u8]) -> Result<(), Error> {
    // The binary decoder enforces chain depth/nodes/bytes before allocating.
    validate_binary_artifact(m, bytes).map(|_| ())
}

fn validate_decoded_artifact(m: &Mandate, artifact: Artifact) -> Result<Artifact, Error> {
    validate_chain_program(&artifact.ir)?;
    if artifact.original_intent.len() > 2048 {
        return Err(Error::InvalidArtifact);
    }
    if artifact.source_hash != m.source_hash
        || artifact.ir_hash != m.ir_hash
        || artifact.registry_version != m.registry_version
        || artifact.core_version != m.core_version
        || artifact.compiler_version != m.compiler_version
    {
        return Err(Error::ArtifactMismatch);
    }
    // This checks every node and effect, even though the compiler authenticated it.
    let ir_hash = canonical_ir_hash(&artifact.ir).map_err(|_| Error::InvalidArtifact)?;
    if ir_hash != m.ir_hash {
        return Err(Error::ArtifactMismatch);
    }
    Ok(artifact)
}

/// No user answers can be passed into a contract evaluation. In particular,
/// an oracle approval can NEVER turn a reached user-input call into success.
/// A rail MUST authenticate the bound evidence-authority account before passing
/// evidence here. This function verifies its complete request/time/interval binding.
pub fn prepare_execution(state: &State, request: &Request, now: u64) -> Result<Decision, Error> {
    prepare_execution_with(state, request, now, validate_artifact)
}

pub fn prepare_binary_execution(
    state: &State,
    request: &Request,
    now: u64,
) -> Result<Decision, Error> {
    prepare_execution_with(state, request, now, validate_binary_artifact)
}

fn prepare_execution_with(
    state: &State,
    request: &Request,
    now: u64,
    decode: impl FnOnce(&Mandate, &[u8]) -> Result<Artifact, Error>,
) -> Result<Decision, Error> {
    let m = &state.mandate;
    if !state.active || state.revoked {
        return Err(Error::Inactive);
    }
    if now >= m.expires_at {
        return Err(Error::Expired);
    }
    if request.revision != m.revision
        || request.asset != m.asset
        || request.recipient != m.recipient
        || request.network != m.network
        || request.action != m.action
        || request.merchant != m.merchant
        || request.source_hash != m.source_hash
        || request.ir_hash != m.ir_hash
    {
        return Err(Error::BindingMismatch);
    }
    if request.nonce != state.next_nonce {
        return Err(Error::Replay);
    }
    if request.amount_units == 0 {
        return Err(Error::InvalidMandate);
    }
    let next_spent = state
        .spent_units
        .checked_add(request.amount_units)
        .ok_or(Error::Overflow)?;
    if next_spent > m.allocation_units {
        return Err(Error::BudgetExceeded);
    }
    state.next_nonce.checked_add(1).ok_or(Error::Overflow)?;
    let artifact = decode(m, &state.artifact)?;
    if request.runtime_context.len() > 1024 {
        return Err(Error::InvalidEvidence);
    }
    #[cfg(feature = "integer-json")]
    let runtime_context = integer_json::parse(&request.runtime_context)?;
    #[cfg(not(feature = "integer-json"))]
    let runtime_context: serde_json::Value =
        serde_json::from_str(&request.runtime_context).map_err(|_| Error::InvalidEvidence)?;
    // One exact encoding prevents duplicate-key/ordering/escape disagreement
    // between an attester and the deterministic evaluator.
    if serde_json::to_string(&runtime_context).map_err(|_| Error::InvalidEvidence)?
        != request.runtime_context
    {
        return Err(Error::InvalidEvidence);
    }
    let runtime_fields = runtime_context.as_object().ok_or(Error::InvalidEvidence)?;
    if !runtime_fields.is_empty() && request.evidence.is_none() {
        return Err(Error::EvidenceRequired);
    }
    let mut confidence = BTreeMap::new();
    if let Some(evidence) = &request.evidence {
        let authority = m
            .evidence_authority
            .as_ref()
            .ok_or(Error::EvidenceRequired)?;
        if evidence.key_id != authority.key_id
            || evidence.version != authority.version
            || evidence.request_hash != request_hash(m, request)?
            || evidence.issued_at > now
            || evidence.expires_at <= now
            || evidence.expires_at > m.expires_at
            || evidence.expires_at <= evidence.issued_at
            || evidence.expires_at - evidence.issued_at > 300
            || (evidence.intervals.is_empty() && runtime_fields.is_empty())
            || evidence.intervals.len() > 4
        {
            return Err(Error::InvalidEvidence);
        }
        for interval in &evidence.intervals {
            if !bounded(&interval.name, 128)
                || interval.lower_bps > interval.upper_bps
                || interval.upper_bps > 10_000
                || confidence.contains_key(&interval.name)
            {
                return Err(Error::InvalidEvidence);
            }
            confidence.insert(
                interval.name.clone(),
                allowit_sdk::ConfidenceInterval {
                    lower_bps: interval.lower_bps,
                    upper_bps: interval.upper_bps,
                },
            );
        }
    }
    // The current language measures USDC in six decimal places. Stellar token
    // amounts may have seven; convert exactly, never round a spend downward.
    let divisor = if m.asset_decimals == 7 { 10 } else { 1 };
    if [request.amount_units, m.allocation_units, state.spent_units]
        .iter()
        .any(|n| n % divisor != 0)
    {
        return Err(Error::InvalidMandate);
    }
    let context = Context {
        native_policy_storage: None,
        amount_units: request.amount_units / divisor,
        allocation_units: m.allocation_units / divisor,
        spent_units: state.spent_units / divisor,
        purchase_counts: None,
        action: request.action.clone(),
        merchant: request.merchant.clone(),
        recipient: m.recipient_address.clone(),
        token: "USDC".into(),
        network: request.network.clone(),
        now,
        answers: BTreeMap::new(),
        confidence,
        original_intent: artifact.original_intent,
        runtime_context,
        ..Context::default()
    };
    let decision = evaluate_ir(&artifact.ir, Profile::Contract, &context);
    if decision.outcome != "pass" {
        if decision.code == "USER_INPUT_REQUIRED" || decision.code == "INPUT_REQUIRED" {
            return Err(Error::UserInputRequired);
        }
        if decision.code == "EVIDENCE_REQUIRED" || decision.code == "SEMANTIC_EVIDENCE_REQUIRED" {
            return Err(Error::EvidenceRequired);
        }
        if decision.code == "INVALID_EVIDENCE" {
            return Err(Error::InvalidEvidence);
        }
        return Err(Error::PolicyDenied);
    }
    Ok(decision)
}

pub fn record_execution(state: &mut State, request: &Request) -> Result<(), Error> {
    // Invoked only AFTER a successful chain transfer. Chain transaction atomicity
    // reverts the transfer too if a later state write fails.
    state.spent_units = state
        .spent_units
        .checked_add(request.amount_units)
        .ok_or(Error::Overflow)?;
    state.next_nonce = state.next_nonce.checked_add(1).ok_or(Error::Overflow)?;
    Ok(())
}

#[cfg(test)]
mod typed_profile_rejection {
    use super::*;

    #[test]
    fn forged_scalar_version_does_not_admit_host_workflow_nodes() {
        let mut program = allowit_sdk::compile(include_str!(
            "../../../tests/fixtures/typed-execution-policy.rs"
        ))
        .unwrap()
        .ir;
        program.version = "1.0.0".into();
        assert_eq!(
            validate_chain_program(&program),
            Err(Error::InvalidArtifact)
        );
    }

    #[test]
    fn minimal_host_nodes_fail_without_depth_or_hash_checks() {
        use allowit_sdk::{Expr, SourceSpan, Statement};
        let span = SourceSpan::default();
        for statement in [
            Statement::IfSome {
                name: "value".into(),
                value: Expr::Unit,
                then_branch: Vec::new(),
                else_branch: Vec::new(),
                span,
            },
            Statement::ForEach {
                name: "value".into(),
                values: Expr::Array { values: Vec::new() },
                body: Vec::new(),
                span,
            },
            Statement::Expression {
                value: Expr::Borrow {
                    value: alloc::boxed::Box::new(Expr::Unit),
                },
                semicolon: true,
                span,
            },
        ] {
            let program = Program {
                version: "1.0.0".into(),
                statements: alloc::vec![statement],
            };
            assert_eq!(
                validate_chain_program(&program),
                Err(Error::InvalidArtifact)
            );
        }
    }

    #[test]
    fn qualified_purchase_ledger_call_is_rejected_by_chain_reader() {
        use allowit_sdk::{Expr, SourceSpan, Statement};
        let span = SourceSpan::default();
        let program = Program {
            version: "1.0.0".into(),
            statements: alloc::vec![Statement::Expression {
                value: Expr::Call {
                    name: "allowit::cap_purchase_tiers".into(),
                    args: Vec::new(),
                    span
                },
                semicolon: true,
                span
            }],
        };
        assert_eq!(
            validate_chain_program(&program),
            Err(Error::InvalidArtifact)
        );
    }

    #[test]
    fn binary_encoder_rejects_typed_version_even_with_only_scalar_nodes() {
        let compiled = allowit_sdk::compile(
            "pub async fn evaluate(ctx: &Context) -> PolicyResult { set_cap(ctx, \"1\", \"USDC\")?; Ok(()) }",
        )
        .unwrap();
        let mut artifact = Artifact {
            original_intent: String::new(),
            source_hash: compiled.source_hash,
            ir_hash: compiled.ir_hash,
            registry_version: compiled.registry_version,
            core_version: CORE_VERSION.into(),
            compiler_version: CORE_VERSION.into(),
            ir: compiled.ir,
        };
        artifact.ir.version = "1.1.0".into();
        assert_eq!(binary::encode(&artifact), Err(Error::InvalidArtifact));
    }
}
