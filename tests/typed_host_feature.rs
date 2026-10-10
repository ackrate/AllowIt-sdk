#![cfg(feature = "typed-workflow")]
use allowit_sdk::typed_workflow::*;
use allowit_sdk::{Context, Profile, Program, canonical_ir_hash, evaluate_ir};
use std::sync::Arc;

fn account(n: u8) -> AccountId {
    AccountId {
        chain: Chain::Solana,
        kind: AccountKind::Wallet,
        address: [n; 32],
    }
}
fn asset() -> WorkflowAsset {
    WorkflowAsset::Native {
        chain: Chain::Solana,
        network: [9; 32],
    }
}
fn digest(value: &str) -> Digest {
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes
}
#[derive(Debug)]
struct InstalledFixtureHost;
impl WorkflowHost for InstalledFixtureHost {
    fn execution_request_validate(
        &self,
        request: &ExecutionRequest,
        binding: &WorkflowBinding,
    ) -> Result<ValidatedExecutionRequest, WorkflowError> {
        let ExecutionInput::Instructions(instructions) = &request.input else {
            return Err(WorkflowError::new(
                "UNSUPPORTED",
                "Fixture only supports instructions",
            ));
        };
        Ok(ValidatedExecutionRequest {
            request: request.clone(),
            request_digest: binding.request_digest,
            signing_digest: [10; 32],
            domain: binding.domain.clone(),
            profile_digest: binding.profile_digest,
            modules: vec![ModuleBinding {
                namespace_id: 1,
                schema_digest: [11; 32],
                executable_digest: [12; 32],
            }],
            instructions: instructions.clone(),
            binding: binding.clone(),
        })
    }
    fn payment_request_from_curl(
        &self,
        _: &CurlOutcome,
        _: &CurlRequest,
        _: &WorkflowBinding,
    ) -> Result<Option<PaymentRequest>, WorkflowError> {
        Err(WorkflowError::new(
            "UNSUPPORTED",
            "No payment converter installed",
        ))
    }
}
fn fixture() -> (Program, Context) {
    let ir: Program =
        serde_json::from_str(include_str!("fixtures/typed-execution-policy.ir.json")).unwrap();
    let mut binding = WorkflowBinding {
        installation_id: [1; 32],
        run_id: [2; 32],
        source_hash: [3; 32],
        ir_hash: digest(&canonical_ir_hash(&ir).unwrap()),
        operation: OperationRef {
            policy_instance: [1; 32],
            nonce: [4; 32],
        },
        profile_digest: [5; 32],
        request_digest: [6; 32],
        evidence_digest: [7; 32],
        domain: WorkflowDomain {
            chain: Chain::Solana,
            network: [9; 32],
            authority: WorkflowAuthority::EngineWallet {
                wallet: account(7),
                signer: account(7),
            },
        },
    };
    let request = ExecutionRequest {
        operation: binding.operation.clone(),
        input: ExecutionInput::Instructions(vec![NativeInstruction::SolanaNativeTransfer {
            source: account(7),
            destination: account(8),
            lamports: 1_000_000,
        }]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: asset(),
            source: account(7),
            beneficiary: account(8),
            max_debit: 1_000_000.into(),
            min_credit: 1_000_000.into(),
            max_burn: 0.into(),
        }],
        fee_bounds: Some(vec![WorkflowFeeBound {
            payer: account(7),
            asset: asset(),
            max_fee: 5_000.into(),
        }]),
        evidence: vec![],
    };
    binding.request_digest =
        request_digest(&binding, &Some(request.clone()), &None, &None).unwrap();
    let mut context = Context::default();
    context.install_workflow(WorkflowEnvironment {
        evaluated_at_seconds: 100,
        debit_authorities: vec![],
        execution_request: Some(request),
        curl_request: None,
        curl_outcome: None,
        binding,
        host: Arc::new(InstalledFixtureHost),
        budgets: vec![WorkflowBudgetObservation {
            budget_id: "native-budget".into(),
            asset: asset(),
            decimals: 9,
            limit_units: 50_000_000.into(),
            spent_units: 0.into(),
            reserved_units: 0.into(),
        }],
    });
    (ir, context)
}
#[test]
fn compiler_free_host_evaluates_authentic_typed_ir_and_protected_budget() {
    let (ir, context) = fixture();
    let result = evaluate_ir(&ir, Profile::Oracle, &context);
    assert_eq!(result.outcome, "pass", "{result:?}");
    assert_eq!(result.workflow_outputs.len(), 1);
    assert_eq!(result.typed_budget_plans.len(), 1);
    assert_eq!(
        result.typed_budget_plans[0].debit_units,
        Amount256::from(1_000_000)
    );
    assert_eq!(
        result.typed_budget_plans[0].fee_units,
        Amount256::from(5_000)
    );
    let mut exhausted = context.clone();
    exhausted.workflow.as_mut().unwrap().budgets[0].reserved_units = 50_000_000.into();
    let refused = evaluate_ir(&ir, Profile::Oracle, &exhausted);
    assert_eq!(refused.code, "WORKFLOW_BUDGET_EXCEEDED");
    assert_ne!(refused.outcome, "pass");
    assert!(refused.workflow_outputs.is_empty());
    assert!(refused.typed_budget_plans.is_empty());
    let mut substituted = context.clone();
    substituted
        .workflow
        .as_mut()
        .unwrap()
        .binding
        .request_digest = [99; 32];
    let refused = evaluate_ir(&ir, Profile::Oracle, &substituted);
    assert_eq!(refused.code, "WORKFLOW_BINDING");
    assert_ne!(refused.outcome, "pass");
    assert!(refused.workflow_outputs.is_empty());
    assert!(refused.typed_budget_plans.is_empty());
    let mut wrong_ir = context.clone();
    wrong_ir.workflow.as_mut().unwrap().binding.ir_hash = [99; 32];
    let refused = evaluate_ir(&ir, Profile::Oracle, &wrong_ir);
    assert_eq!(refused.code, "WORKFLOW_BINDING");
    assert_ne!(refused.outcome, "pass");
    assert!(refused.workflow_outputs.is_empty());
    assert!(refused.typed_budget_plans.is_empty());
    for field in ["limit", "decimals", "asset"] {
        let mut mismatched = context.clone();
        let budget = &mut mismatched.workflow.as_mut().unwrap().budgets[0];
        match field {
            "limit" => budget.limit_units = 50_000_001.into(),
            "decimals" => budget.decimals = 6,
            "asset" => {
                budget.asset = WorkflowAsset::Native {
                    chain: Chain::Solana,
                    network: [99; 32],
                }
            }
            _ => unreachable!(),
        }
        let refused = evaluate_ir(&ir, Profile::Oracle, &mismatched);
        assert_ne!(refused.outcome, "pass", "{field}: {refused:?}");
        assert!(refused.workflow_outputs.is_empty());
        assert!(refused.typed_budget_plans.is_empty());
    }
}
#[cfg(feature = "compiler")]
#[test]
fn frozen_ir_is_the_exact_compiler_output_for_its_source() {
    let (ir, _) = fixture();
    assert_eq!(
        allowit_sdk::compile(include_str!("fixtures/typed-execution-policy.rs"))
            .unwrap()
            .ir,
        ir
    );
}
