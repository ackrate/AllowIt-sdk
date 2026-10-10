//! Pure typed workflow nodes. The host authenticates inputs and installed profiles.
//! These results establish facts, never spending authorization or settlement.
use alloc::{string::String, sync::Arc, vec::Vec};
use serde::{Deserialize, Serialize};

pub type Digest = [u8; 32];
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount256(pub [u8; 32]);
impl From<u64> for Amount256 {
    fn from(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chain {
    Solana,
    Stellar,
    Tempo,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountKind {
    Wallet,
    TokenAccount,
    Contract,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountId {
    pub chain: Chain,
    pub kind: AccountKind,
    pub address: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetId {
    pub network: Digest,
    pub token: AccountId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkflowAsset {
    Native { chain: Chain, network: Digest },
    Token(AssetId),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowAmount {
    pub asset: WorkflowAsset,
    pub units: Amount256,
    pub decimals: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRef {
    pub policy_instance: Digest,
    pub nonce: Digest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    Quote,
    PaymentChallenge,
    ExternalClaim,
    ProviderMessage,
    PreferenceAssessment,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub namespace_id: u32,
    pub schema: u16,
    pub kind: EvidenceKind,
    pub digest: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEffectBound {
    pub asset: WorkflowAsset,
    pub source: AccountId,
    pub beneficiary: AccountId,
    pub max_debit: Amount256,
    pub min_credit: Amount256,
    pub max_burn: Amount256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowFeeBound {
    pub payer: AccountId,
    pub asset: WorkflowAsset,
    pub max_fee: Amount256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbiValue {
    Bool(bool),
    Unsigned(Amount256),
    Signed128(i128),
    Account(AccountId),
    Bytes(Vec<u8>),
    Text(String),
    Tuple(Vec<AbiValue>),
    Array(Vec<AbiValue>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolanaAccountMeta {
    pub account: AccountId,
    pub is_signer: bool,
    pub is_writable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum NativeInstruction {
    SolanaNativeTransfer {
        source: AccountId,
        destination: AccountId,
        lamports: u64,
    },
    StellarNativeTransfer {
        source: AccountId,
        destination: AccountId,
        stroops: u64,
    },
    SolanaCall {
        program: AccountId,
        schema_digest: Digest,
        accounts: Vec<SolanaAccountMeta>,
        arguments: Vec<AbiValue>,
    },
    StellarCall {
        contract: AccountId,
        schema_digest: Digest,
        function: String,
        arguments: Vec<AbiValue>,
    },
    TempoCall {
        contract: AccountId,
        schema_digest: Digest,
        selector: [u8; 4],
        arguments: Vec<AbiValue>,
        value: Amount256,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecutionInput {
    Instructions(Vec<NativeInstruction>),
    Message(Vec<u8>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    pub operation: OperationRef,
    pub input: ExecutionInput,
    pub effect_bounds: Vec<WorkflowEffectBound>,
    pub fee_bounds: Option<Vec<WorkflowFeeBound>>,
    pub evidence: Vec<EvidenceRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WorkflowAuthority {
    EngineWallet {
        wallet: AccountId,
        signer: AccountId,
    },
    Custody {
        gate: AccountId,
        source: AccountId,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDomain {
    pub chain: Chain,
    pub network: Digest,
    pub authority: WorkflowAuthority,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBinding {
    pub namespace_id: u32,
    pub schema_digest: Digest,
    pub executable_digest: Digest,
}
/// Normalized protocols remain distinct. CooperatingV1 is the existing custom gateway,
/// not the official MPP Solana charge profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentScheme {
    X402ExactSvm,
    MppSolanaCharge,
    CooperatingV1,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BodyParam {
    Text(String),
    JsonBytes(Vec<u8>),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurlRequest {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<Vec<HttpHeader>>,
    pub body: Option<BodyParam>,
    pub body_file: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentChallenge {
    pub scheme: PaymentScheme,
    pub schema: u16,
    pub challenge_digest: Digest,
    pub gateway_origin: String,
    pub endpoint_path: String,
    pub http_request_digest: Digest,
    pub network: Digest,
    pub asset: AssetId,
    pub payee: AccountId,
    pub fee_payer: AccountId,
    pub amount: Amount256,
    pub expires_at_seconds: u64,
    pub response_access_key: Digest,
    pub authenticated_wire_bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub receipt_digest: Digest,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
// A finite authenticated input record; retain the direct typed host API.
#[allow(clippy::large_enum_variant)]
pub enum CurlOutcome {
    PaymentRequired(PaymentChallenge),
    Complete(HttpResponse),
}
/// Authenticated installation/run/source/request identity, supplied by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkflowBinding {
    pub installation_id: Digest,
    pub run_id: Digest,
    pub source_hash: Digest,
    pub ir_hash: Digest,
    pub operation: OperationRef,
    pub profile_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub domain: WorkflowDomain,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedExecutionRequest {
    pub request: ExecutionRequest,
    pub request_digest: Digest,
    pub signing_digest: Digest,
    pub domain: WorkflowDomain,
    pub profile_digest: Digest,
    pub modules: Vec<ModuleBinding>,
    pub instructions: Vec<NativeInstruction>,
    pub binding: WorkflowBinding,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaymentRequest {
    pub operation: OperationRef,
    pub profile_digest: Digest,
    pub http_request_digest: Digest,
    pub evidence: EvidenceRef,
    pub scheme: PaymentScheme,
    pub payer: AccountId,
    pub payee: AccountId,
    pub payment: WorkflowAmount,
    pub fee_payer: AccountId,
    pub fee_bounds: Option<Vec<WorkflowFeeBound>>,
    pub expires_at_seconds: u64,
    pub response_access_key: Digest,
    pub binding: WorkflowBinding,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowError {
    pub code: String,
    pub reason: String,
}
impl WorkflowError {
    pub fn new(code: &str, reason: &str) -> Self {
        Self {
            code: code.into(),
            reason: reason.into(),
        }
    }
}
/// Trusted host implementation must check complete installed native schemas/effects and
/// retained HTTP provenance. Methods are pure: no network, signing or submission here.
pub trait WorkflowHost: core::fmt::Debug + Send + Sync {
    /// Supply retained, binding-specific proof that no extra fee can debit this workflow.
    /// Absence never certifies a zero fee. No network access occurs in this method.
    fn zero_fee_evidence(&self, _binding: &WorkflowBinding) -> Option<ZeroFeeEvidence> {
        None
    }
    fn execution_request_validate(
        &self,
        request: &ExecutionRequest,
        binding: &WorkflowBinding,
    ) -> Result<ValidatedExecutionRequest, WorkflowError>;
    fn payment_request_from_curl(
        &self,
        outcome: &CurlOutcome,
        request: &CurlRequest,
        binding: &WorkflowBinding,
    ) -> Result<Option<PaymentRequest>, WorkflowError>;
}
/// Installed host proof that a token account belongs to this exact wallet/custody authority.
#[derive(Debug, Clone)]
pub struct WorkflowDebitAuthority {
    pub asset: WorkflowAsset,
    pub account: AccountId,
    pub authority: WorkflowAuthority,
    pub binding: WorkflowBinding,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone)]
pub struct WorkflowEnvironment {
    /// Trusted host clock frozen for this evaluation; caller Context.now is not authoritative.
    pub evaluated_at_seconds: u64,
    pub debit_authorities: Vec<WorkflowDebitAuthority>,
    pub binding: WorkflowBinding,
    pub execution_request: Option<ExecutionRequest>,
    pub curl_request: Option<CurlRequest>,
    pub curl_outcome: Option<CurlOutcome>,
    pub host: Arc<dyn WorkflowHost>,
    pub budgets: Vec<WorkflowBudgetObservation>,
}
/// Successful pure outputs. The enclosing final policy decision still does not prove
/// owner signature, payment or delivery. Unresolved fees prohibit final authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum WorkflowOutput {
    Execution(ValidatedExecutionRequest),
    Payment(PaymentRequest),
    FreeResponse {
        request_digest: Digest,
        receipt_digest: Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkflowType {
    Named(String),
    Option(alloc::boxed::Box<WorkflowType>),
    Result(alloc::boxed::Box<WorkflowType>),
    Vec(alloc::boxed::Box<WorkflowType>),
    U64,
    Amount256,
    Bool,
    String,
    Digest,
}
impl WorkflowType {
    pub fn named(name: &str) -> Self {
        Self::Named(name.into())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionParameter {
    pub name: String,
    pub value_type: WorkflowType,
    pub borrowed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowSignature {
    pub parameters: Vec<FunctionParameter>,
    pub result: WorkflowType,
    pub source_profile: String,
    pub effect: String,
}
pub fn signature(name: &str) -> Option<WorkflowSignature> {
    let named = WorkflowType::named;
    let param = |name: &str, ty| FunctionParameter {
        name: name.into(),
        value_type: named(ty),
        borrowed: true,
    };
    let boxed = alloc::boxed::Box::new;
    let (parameters, result) = match name {
        "allowit::execution_request_validate" => (
            alloc::vec![param("request", "ExecutionRequest")],
            WorkflowType::Result(boxed(named("ValidatedExecutionRequest"))),
        ),
        "paysh::payment_request_from_curl" => (
            alloc::vec![
                param("outcome", "CurlOutcome"),
                param("request", "CurlRequest")
            ],
            WorkflowType::Result(boxed(WorkflowType::Option(boxed(named("PaymentRequest"))))),
        ),
        "allowit::execution_request_cap" | "allowit::payment_request_cap" => (
            alloc::vec![
                param(
                    "request",
                    if name == "allowit::execution_request_cap" {
                        "ValidatedExecutionRequest"
                    } else {
                        "PaymentRequest"
                    }
                ),
                FunctionParameter {
                    name: "budget_id".into(),
                    value_type: WorkflowType::String,
                    borrowed: true
                },
                FunctionParameter {
                    name: "asset_id".into(),
                    value_type: WorkflowType::String,
                    borrowed: true
                },
                FunctionParameter {
                    name: "decimals".into(),
                    value_type: WorkflowType::U64,
                    borrowed: false
                },
                FunctionParameter {
                    name: "total_budget_units".into(),
                    value_type: WorkflowType::U64,
                    borrowed: false
                },
                FunctionParameter {
                    name: "max_debit_units".into(),
                    value_type: WorkflowType::U64,
                    borrowed: false
                },
                FunctionParameter {
                    name: "max_fee_units".into(),
                    value_type: WorkflowType::U64,
                    borrowed: false
                }
            ],
            WorkflowType::Result(boxed(named("Unit"))),
        ),
        _ => return None,
    };
    Some(WorkflowSignature {
        parameters,
        result,
        source_profile: "oracle".into(),
        effect: if name.ends_with("_cap") {
            "budget_guard"
        } else {
            "pure_validation"
        }
        .into(),
    })
}

#[cfg(feature = "typed-workflow")]
pub(crate) fn field_type(ty: &str, field: &str) -> Option<WorkflowType> {
    use WorkflowType as T;
    let n = T::named;
    let v = |name| T::Vec(alloc::boxed::Box::new(n(name)));
    let o = |ty| T::Option(alloc::boxed::Box::new(ty));
    Some(match (ty, field) {
        ("ExecutionRequest", "operation") | ("PaymentRequest", "operation") => n("OperationRef"),
        ("ExecutionRequest", "effect_bounds") => v("WorkflowEffectBound"),
        ("ExecutionRequest", "fee_bounds") | ("PaymentRequest", "fee_bounds") => {
            o(v("WorkflowFeeBound"))
        }
        ("ValidatedExecutionRequest", "request") => n("ExecutionRequest"),
        ("ValidatedExecutionRequest", "instructions") => v("NativeInstruction"),
        ("ValidatedExecutionRequest", "request_digest" | "signing_digest" | "profile_digest")
        | ("PaymentRequest", "profile_digest" | "http_request_digest" | "response_access_key") => {
            T::Digest
        }
        ("PaymentRequest", "payment") => n("WorkflowAmount"),
        ("PaymentRequest", "payer" | "payee" | "fee_payer")
        | ("WorkflowEffectBound", "source" | "beneficiary")
        | ("WorkflowFeeBound", "payer") => n("AccountId"),
        ("PaymentRequest", "expires_at_seconds") | ("WorkflowAmount", "decimals") => T::U64,
        ("WorkflowAmount", "units")
        | ("WorkflowEffectBound", "max_debit" | "min_credit" | "max_burn")
        | ("WorkflowFeeBound", "max_fee") => T::Amount256,
        ("WorkflowAmount", "asset")
        | ("WorkflowEffectBound", "asset")
        | ("WorkflowFeeBound", "asset") => n("WorkflowAsset"),
        ("AccountId", "address") | ("OperationRef", "policy_instance" | "nonce") => T::Digest,
        ("CurlRequest", "url") => T::String,
        _ => return None,
    })
}
#[cfg(feature = "typed-workflow")]
pub(crate) fn required(program: &crate::Program) -> bool {
    use crate::{Expr, Statement};
    let mut statements: Vec<_> = program.statements.iter().collect();
    let mut expressions = Vec::new();
    while let Some(s) = statements.pop() {
        match s {
            Statement::ForEach { .. } | Statement::IfSome { .. } => return true,
            Statement::Let { value, .. }
            | Statement::Return { value, .. }
            | Statement::Expression { value, .. } => expressions.push(value),
            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                expressions.push(condition);
                statements.extend(then_branch);
                statements.extend(else_branch);
            }
        }
    }
    while let Some(e) = expressions.pop() {
        match e {
            Expr::Call { name, args, .. } => {
                if signature(name).is_some() {
                    return true;
                }
                expressions.extend(args);
            }
            Expr::Field { object, name } => {
                if ["execution_request", "curl_request", "curl_outcome"].contains(&name.as_str()) {
                    return true;
                }
                expressions.push(object);
            }
            Expr::Borrow { value }
            | Expr::Try { value }
            | Expr::Await { value }
            | Expr::Not { value } => expressions.push(value),
            Expr::Binary { left, right, .. } => {
                expressions.push(left);
                expressions.push(right);
            }
            Expr::Array { values } => expressions.extend(values),
            _ => {}
        }
    }
    false
}

#[cfg(not(feature = "typed-workflow"))]
pub(crate) fn required(_program: &crate::Program) -> bool {
    false
}

#[cfg(feature = "typed-workflow")]
pub(crate) fn binding_valid(binding: &WorkflowBinding) -> bool {
    [
        binding.installation_id,
        binding.run_id,
        binding.source_hash,
        binding.ir_hash,
        binding.profile_digest,
        binding.request_digest,
        binding.evidence_digest,
        binding.operation.policy_instance,
        binding.operation.nonce,
        binding.domain.network,
    ]
    .iter()
    .all(|v| *v != [0; 32])
        && binding.installation_id == binding.operation.policy_instance
        && match &binding.domain.authority {
            WorkflowAuthority::EngineWallet { wallet, signer } => {
                wallet.chain == binding.domain.chain && signer.chain == binding.domain.chain
            }
            WorkflowAuthority::Custody { gate, source } => {
                gate.chain == binding.domain.chain && source.chain == binding.domain.chain
            }
        }
}
pub(crate) fn hex(digest: &Digest) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut result = String::new();
    for b in digest {
        result.push(HEX[(b >> 4) as usize] as char);
        result.push(HEX[(b & 15) as usize] as char);
    }
    result
}
pub(crate) fn execution_shape(request: &ExecutionRequest) -> bool {
    request.effect_bounds.len() <= 16
        && request.fee_bounds.as_ref().is_none_or(|v| v.len() <= 16)
        && request.evidence.len() <= 8
        && match &request.input {
            ExecutionInput::Instructions(v) => {
                !v.is_empty() && v.len() <= 16 && v.iter().all(instruction_shape)
            }
            ExecutionInput::Message(v) => !v.is_empty() && v.len() <= 65536,
        }
}
#[cfg(feature = "typed-workflow")]
pub(crate) fn curl_shape(request: &CurlRequest) -> bool {
    request.body_file.is_none() && curl_input_size(request)
}
pub(crate) fn curl_input_size(request: &CurlRequest) -> bool {
    request
        .body_file
        .as_ref()
        .is_none_or(|value| value.len() <= 4096)
        && request.url.len() <= 4096
        && !request.url.is_empty()
        && request.headers.as_ref().is_none_or(|v| {
            v.len() <= 32
                && v.iter()
                    .all(|h| h.name.len() <= 256 && h.value.len() <= 8192)
        })
        && request.body.as_ref().is_none_or(|b| match b {
            BodyParam::Text(v) => v.len() <= 65536,
            BodyParam::JsonBytes(v) => v.len() <= 65536,
        })
}

/// Bound untrusted response bytes before JSON serialization or hashing.
pub(crate) fn curl_outcome_shape(outcome: &CurlOutcome) -> bool {
    match outcome {
        CurlOutcome::Complete(response) => response.body.len() <= 65536,
        CurlOutcome::PaymentRequired(challenge) => {
            challenge.authenticated_wire_bytes.len() <= 8192
                && challenge.gateway_origin.len() <= 4096
                && challenge.endpoint_path.len() <= 4096
        }
    }
}

/// Nominal declaration order is stable for registry 1.4. UI colors are presentation only.
pub fn type_declarations() -> Vec<String> {
    [
        "ExecutionRequest",
        "ValidatedExecutionRequest",
        "CurlRequest",
        "CurlOutcome",
        "PaymentRequest",
        "WorkflowAmount",
        "WorkflowAsset",
        "WorkflowEffectBound",
        "WorkflowFeeBound",
        "AccountId",
        "OperationRef",
        "NativeInstruction",
        "Unit",
    ]
    .iter()
    .map(|s| String::from(*s))
    .collect()
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkflowPort {
    pub name: String,
    pub value_type: WorkflowType,
    #[serde(with = "exact_port_binding")]
    pub binding: crate::Expr,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedWorkflowNode {
    pub operation: String,
    /// UTF-8 byte offsets in the original approved source.
    pub span: crate::SourceSpan,
    pub span_encoding: String,
    pub inputs: Vec<TypedWorkflowPort>,
    pub output_type: WorkflowType,
    pub output_binding: Option<String>,
    pub output_value_type: WorkflowType,
    pub output_state: String,
}

/// Domain-separated commitment to all original typed ingress and authenticated scope.
/// Call after freezing preflight and before creating approval/continuation challenges.
pub fn request_digest(
    binding: &WorkflowBinding,
    execution: &Option<ExecutionRequest>,
    request: &Option<CurlRequest>,
    outcome: &Option<CurlOutcome>,
) -> Result<Digest, WorkflowError> {
    if execution
        .as_ref()
        .is_some_and(|value| !execution_shape(value))
        || request
            .as_ref()
            .is_some_and(|value| !curl_input_size(value))
        || outcome
            .as_ref()
            .is_some_and(|value| !curl_outcome_shape(value))
    {
        return Err(WorkflowError::new(
            "WORKFLOW_INPUT_LIMIT",
            "Typed HTTP response exceeds its bounded shape",
        ));
    }
    let document = (
        &binding.installation_id,
        &binding.run_id,
        &binding.source_hash,
        &binding.ir_hash,
        &binding.operation,
        &binding.profile_digest,
        &binding.evidence_digest,
        &binding.domain,
        execution,
        request,
        outcome,
    );
    let mut bytes = b"allowit:typed-workflow-input:v1\0".to_vec();
    bytes.extend(
        serde_json::to_vec(&document)
            .map_err(|_| WorkflowError::new("WORKFLOW_BINDING", "Cannot encode typed ingress"))?,
    );
    let hash = crate::digest(&bytes);
    let mut result = [0; 32];
    for (i, b) in result.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16)
            .map_err(|_| WorkflowError::new("WORKFLOW_BINDING", "Cannot encode typed digest"))?;
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroFeeEvidence {
    pub binding: WorkflowBinding,
    pub evidence: EvidenceRef,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowBudgetObservation {
    pub budget_id: String,
    pub asset: WorkflowAsset,
    pub decimals: u8,
    pub limit_units: Amount256,
    pub spent_units: Amount256,
    /// Other operations' unresolved reservations. Original-ID replay excludes its own reservation.
    pub reserved_units: Amount256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBudgetRequirement {
    pub operation: String,
    pub budget_id: String,
    pub asset_id: String,
    pub decimals: u8,
    #[serde(with = "decimal_u64")]
    pub total_budget_units: u64,
    #[serde(with = "decimal_u64")]
    pub max_debit_units: u64,
    #[serde(with = "decimal_u64")]
    pub max_fee_units: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypedBudgetPlan {
    pub requirement: TypedBudgetRequirement,
    pub asset: WorkflowAsset,
    pub debit_units: Amount256,
    pub fee_units: Amount256,
}
impl Amount256 {
    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut result = [0; 32];
        let mut carry = 0_u16;
        for i in (0..32).rev() {
            let v = u16::from(self.0[i]) + u16::from(other.0[i]) + carry;
            result[i] = v as u8;
            carry = v >> 8;
        }
        if carry > 0 { None } else { Some(Self(result)) }
    }
}
pub fn asset_identity(asset: &WorkflowAsset) -> String {
    let chain = |c| match c {
        Chain::Solana => "solana",
        Chain::Stellar => "stellar",
        Chain::Tempo => "tempo",
    };
    match asset {
        WorkflowAsset::Native { chain: c, network } => {
            alloc::format!("native:{}:{}", chain(*c), hex(network))
        }
        WorkflowAsset::Token(a) => alloc::format!(
            "token:{}:{}:{}:{}",
            chain(a.token.chain),
            hex(&a.network),
            hex(&a.token.address),
            match a.token.kind {
                AccountKind::Wallet => "wallet",
                AccountKind::TokenAccount => "token-account",
                AccountKind::Contract => "contract",
            }
        ),
    }
}
#[cfg(feature = "typed-workflow")]
pub(crate) fn asset_from_identity(value: &str) -> Option<WorkflowAsset> {
    let parts: Vec<_> = value.split(':').collect();
    let chain = |s| match s {
        "solana" => Some(Chain::Solana),
        "stellar" => Some(Chain::Stellar),
        "tempo" => Some(Chain::Tempo),
        _ => None,
    };
    let bytes = |s: &str| {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut result = [0; 32];
        for (i, b) in result.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        }
        if result == [0; 32] {
            None
        } else {
            Some(result)
        }
    };
    match parts.as_slice() {
        ["native", c, n] => Some(WorkflowAsset::Native {
            chain: chain(c)?,
            network: bytes(n)?,
        }),
        ["token", c, n, a, k] => Some(WorkflowAsset::Token(AssetId {
            network: bytes(n)?,
            token: AccountId {
                chain: chain(c)?,
                address: bytes(a)?,
                kind: match *k {
                    "wallet" => AccountKind::Wallet,
                    "token-account" => AccountKind::TokenAccount,
                    "contract" => AccountKind::Contract,
                    _ => return None,
                },
            },
        })),
        _ => None,
    }
}

pub(crate) fn instruction_shape(instruction: &NativeInstruction) -> bool {
    let args = match instruction {
        NativeInstruction::SolanaNativeTransfer { lamports, .. } => return *lamports > 0,
        NativeInstruction::StellarNativeTransfer { stroops, .. } => {
            return *stroops > 0 && *stroops <= i64::MAX as u64;
        }
        NativeInstruction::SolanaCall {
            accounts,
            arguments,
            ..
        } => {
            if accounts.len() > 64 {
                return false;
            }
            arguments
        }
        NativeInstruction::StellarCall {
            function,
            arguments,
            ..
        } => {
            if function.is_empty() || function.len() > 32 {
                return false;
            }
            arguments
        }
        NativeInstruction::TempoCall { arguments, .. } => arguments,
    };
    if args.len() > 16 {
        return false;
    }
    let mut stack: Vec<_> = args.iter().map(|a| (a, 1_usize)).collect();
    let mut nodes = 0;
    let mut bytes = 0;
    while let Some((value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > 64 || depth > 4 {
            return false;
        }
        match value {
            AbiValue::Bytes(v) => bytes += v.len(),
            AbiValue::Text(v) => bytes += v.len(),
            AbiValue::Tuple(v) | AbiValue::Array(v) => {
                if v.len() > 64 {
                    return false;
                }
                stack.extend(v.iter().map(|a| (a, depth + 1)));
            }
            _ => {}
        }
        if bytes > 65536 {
            return false;
        }
    }
    true
}

impl PartialEq<u64> for Amount256 {
    fn eq(&self, value: &u64) -> bool {
        *self == Self::from(*value)
    }
}
impl PartialOrd<u64> for Amount256 {
    fn partial_cmp(&self, value: &u64) -> Option<core::cmp::Ordering> {
        Some(self.cmp(&Self::from(*value)))
    }
}

mod decimal_u64 {
    use alloc::string::{String, ToString};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        let number = value.parse::<u64>().map_err(serde::de::Error::custom)?;
        if number.to_string() != value {
            return Err(serde::de::Error::custom(
                "expected canonical unsigned decimal string",
            ));
        }
        Ok(number)
    }
}

#[cfg(feature = "typed-workflow")]
pub(crate) fn asset_in_domain(asset: &WorkflowAsset, domain: &WorkflowDomain) -> bool {
    match asset {
        WorkflowAsset::Native { chain, network } => {
            *chain == domain.chain && *network == domain.network
        }
        WorkflowAsset::Token(asset) => {
            asset.token.chain == domain.chain && asset.network == domain.network
        }
    }
}
#[cfg(feature = "typed-workflow")]
pub(crate) fn authority_source(domain: &WorkflowDomain) -> &AccountId {
    match &domain.authority {
        WorkflowAuthority::EngineWallet { wallet, .. } => wallet,
        WorkflowAuthority::Custody { source, .. } => source,
    }
}

/// Cheap aggregate transfer coverage. Registered ABI effect decoding remains the installed host's responsibility.
#[cfg(feature = "typed-workflow")]
pub(crate) fn native_transfers_covered(
    request: &ExecutionRequest,
    domain: &WorkflowDomain,
) -> bool {
    let ExecutionInput::Instructions(instructions) = &request.input else {
        return true;
    };
    for instruction in instructions {
        let (source, beneficiary) = match instruction {
            NativeInstruction::SolanaNativeTransfer {
                source,
                destination,
                ..
            }
            | NativeInstruction::StellarNativeTransfer {
                source,
                destination,
                ..
            } => (source, destination),
            NativeInstruction::TempoCall { value, .. } if *value != Amount256::from(0) => {
                if request.effect_bounds.is_empty() {
                    return false;
                }
                continue;
            }
            _ => continue,
        };
        let mut actual = Amount256::from(0);
        for other in instructions {
            let units = match other {
                NativeInstruction::SolanaNativeTransfer {
                    source: s,
                    destination: d,
                    lamports,
                } if s == source && d == beneficiary => Amount256::from(*lamports),
                NativeInstruction::StellarNativeTransfer {
                    source: s,
                    destination: d,
                    stroops,
                } if s == source && d == beneficiary => Amount256::from(*stroops),
                _ => continue,
            };
            let Some(sum) = actual.checked_add(units) else {
                return false;
            };
            actual = sum;
        }
        let mut declared = Amount256::from(0);
        for effect in &request.effect_bounds {
            if effect.source == *source
                && effect.beneficiary == *beneficiary
                && effect.asset
                    == (WorkflowAsset::Native {
                        chain: domain.chain,
                        network: domain.network,
                    })
            {
                let Some(sum) = declared.checked_add(effect.max_debit) else {
                    return false;
                };
                declared = sum;
            }
        }
        if actual > declared {
            return false;
        }
    }
    true
}

#[cfg(feature = "typed-workflow")]
pub(crate) fn debit_authorized(
    account: &AccountId,
    asset: &WorkflowAsset,
    environment: &WorkflowEnvironment,
) -> bool {
    if matches!(asset, WorkflowAsset::Native { .. })
        && account == authority_source(&environment.binding.domain)
    {
        return true;
    }
    account.kind == AccountKind::TokenAccount
        && account.chain == environment.binding.domain.chain
        && environment.debit_authorities.len() <= 16
        && environment
            .debit_authorities
            .iter()
            .filter(|proof| proof.account == *account)
            .count()
            == 1
        && environment.debit_authorities.iter().any(|proof| {
            proof.account == *account
                && proof.asset == *asset
                && proof.authority == environment.binding.domain.authority
                && proof.binding == environment.binding
                && proof.evidence.kind == EvidenceKind::ExternalClaim
                && proof.evidence.namespace_id > 0
                && proof.evidence.schema > 0
                && proof.evidence.digest != [0; 32]
        })
}
mod exact_port_binding {
    use alloc::string::ToString;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    fn convert(value: &mut serde_json::Value, to_wire: bool) -> Result<(), &'static str> {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("kind").and_then(|v| v.as_str()) == Some("integer") {
                    let Some(raw) = map.get_mut("value") else {
                        return Err("missing integer");
                    };
                    if to_wire {
                        *raw = serde_json::Value::String(
                            raw.as_u64().ok_or("invalid integer")?.to_string(),
                        );
                    } else {
                        let text = raw.as_str().ok_or("expected exact decimal string")?;
                        let number = text.parse::<u64>().map_err(|_| "invalid decimal")?;
                        if number.to_string() != text {
                            return Err("noncanonical decimal");
                        }
                        *raw = number.into();
                    }
                }
                for child in map.values_mut() {
                    convert(child, to_wire)?;
                }
            }
            serde_json::Value::Array(values) => {
                for child in values {
                    convert(child, to_wire)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    pub fn serialize<S: Serializer>(expr: &crate::Expr, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(expr).map_err(serde::ser::Error::custom)?;
        convert(&mut value, true).map_err(serde::ser::Error::custom)?;
        value.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<crate::Expr, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        convert(&mut value, false).map_err(serde::de::Error::custom)?;
        serde_json::from_value(value).map_err(serde::de::Error::custom)
    }
}

/// The host verifies current owner/evaluator signature expiry before installing keyed answers/evidence.
/// Full binding includes installation, operation, source, IR, profile, raw evidence and request digest.
pub fn input_key(binding: &WorkflowBinding, span: usize, prompt: &str) -> String {
    let bytes = serde_json::to_vec(&("allowit-typed-input-v1", binding, span, prompt))
        .expect("finite binding serialization");
    crate::digest(&bytes)
}
pub fn evidence_key(binding: &WorkflowBinding, label: &str) -> String {
    let bytes = serde_json::to_vec(&("allowit-typed-evidence-v1", binding, label))
        .expect("finite binding serialization");
    crate::digest(&bytes)
}
#[cfg(feature = "typed-workflow")]
pub(crate) fn requires_zero_fee_proof(
    fees: &[WorkflowFeeBound],
    payer: &AccountId,
    domain: &WorkflowDomain,
) -> bool {
    !fees.iter().any(|fee| {
        fee.payer == *payer
            && fee.asset
                == (WorkflowAsset::Native {
                    chain: domain.chain,
                    network: domain.network,
                })
            && fee.max_fee != Amount256::from(0)
    })
}

#[cfg(feature = "typed-workflow")]
pub(crate) fn instruction_in_domain(
    instruction: &NativeInstruction,
    domain: &WorkflowDomain,
) -> bool {
    match instruction {
        NativeInstruction::SolanaNativeTransfer {
            source,
            destination,
            ..
        } => {
            domain.chain == Chain::Solana
                && source.chain == domain.chain
                && destination.chain == domain.chain
        }
        NativeInstruction::StellarNativeTransfer {
            source,
            destination,
            ..
        } => {
            domain.chain == Chain::Stellar
                && source.chain == domain.chain
                && destination.chain == domain.chain
        }
        NativeInstruction::SolanaCall {
            program, accounts, ..
        } => {
            domain.chain == Chain::Solana
                && program.chain == domain.chain
                && program.address != [0; 32]
                && accounts.iter().all(|a| a.account.chain == domain.chain)
        }
        NativeInstruction::StellarCall { contract, .. } => {
            domain.chain == Chain::Stellar && contract.chain == domain.chain
        }
        NativeInstruction::TempoCall {
            contract, value, ..
        } => {
            domain.chain == Chain::Tempo
                && contract.chain == domain.chain
                && *value == Amount256::from(0)
        }
    }
}
