use allowit_sdk::typed_workflow::*;
use allowit_sdk::{Context, Profile, compile, evaluate};
use std::sync::Arc;
const EXEC: &str = include_str!("fixtures/typed-execution-policy.rs");
const PAYMENT: &str = include_str!("fixtures/typed-payment-policy.rs");
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
fn decode(s: &str) -> Digest {
    let mut b = [0; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    b
}
fn binding(policy: &allowit_sdk::CompiledPolicy) -> WorkflowBinding {
    WorkflowBinding {
        installation_id: [1; 32],
        run_id: [2; 32],
        source_hash: decode(&policy.source_hash),
        ir_hash: decode(&policy.ir_hash),
        operation: OperationRef {
            policy_instance: [1; 32],
            nonce: [3; 32],
        },
        profile_digest: [4; 32],
        request_digest: [5; 32],
        evidence_digest: [6; 32],
        domain: WorkflowDomain {
            chain: Chain::Solana,
            network: [9; 32],
            authority: WorkflowAuthority::EngineWallet {
                wallet: account(7),
                signer: account(7),
            },
        },
    }
}
fn fee() -> WorkflowFeeBound {
    WorkflowFeeBound {
        payer: account(7),
        asset: asset(),
        max_fee: 5000.into(),
    }
}
fn request(b: &WorkflowBinding) -> ExecutionRequest {
    ExecutionRequest {
        operation: b.operation.clone(),
        input: ExecutionInput::Instructions(vec![NativeInstruction::SolanaNativeTransfer {
            source: account(7),
            destination: account(8),
            lamports: 1000000,
        }]),
        effect_bounds: vec![WorkflowEffectBound {
            asset: asset(),
            source: account(7),
            beneficiary: account(8),
            max_debit: 1000000.into(),
            min_credit: 1000000.into(),
            max_burn: 0.into(),
        }],
        fee_bounds: Some(vec![fee()]),
        evidence: vec![],
    }
}
#[derive(Debug)]
struct Host {
    wrong_binding: bool,
    free: bool,
    error: bool,
}
impl WorkflowHost for Host {
    fn execution_request_validate(
        &self,
        r: &ExecutionRequest,
        b: &WorkflowBinding,
    ) -> Result<ValidatedExecutionRequest, WorkflowError> {
        let ExecutionInput::Instructions(i) = &r.input else {
            return Err(WorkflowError::new(
                "UNSUPPORTED",
                "Message codec unavailable in fixture",
            ));
        };
        if i.iter().any(
            |v| !matches!(v,NativeInstruction::SolanaNativeTransfer{lamports,..} if *lamports>0),
        ) {
            return Err(WorkflowError::new("UNSUPPORTED", "Uninstalled instruction"));
        }
        let mut binding = b.clone();
        if self.wrong_binding {
            binding.run_id = [99; 32];
        }
        Ok(ValidatedExecutionRequest {
            request: r.clone(),
            request_digest: b.request_digest,
            signing_digest: [10; 32],
            domain: b.domain.clone(),
            profile_digest: b.profile_digest,
            modules: vec![ModuleBinding {
                namespace_id: 1,
                schema_digest: [11; 32],
                executable_digest: [12; 32],
            }],
            instructions: i.clone(),
            binding,
        })
    }
    fn payment_request_from_curl(
        &self,
        o: &CurlOutcome,
        _: &CurlRequest,
        b: &WorkflowBinding,
    ) -> Result<Option<PaymentRequest>, WorkflowError> {
        if self.error {
            return Err(WorkflowError::new("MALFORMED", "Malformed challenge"));
        }
        if self.free {
            return Ok(None);
        }
        let CurlOutcome::PaymentRequired(c) = o else {
            return Err(WorkflowError::new(
                "HTTP_FAILURE",
                "Response was not a payment challenge",
            ));
        };
        Ok(Some(PaymentRequest {
            operation: b.operation.clone(),
            profile_digest: b.profile_digest,
            http_request_digest: c.http_request_digest,
            evidence: EvidenceRef {
                namespace_id: 1,
                schema: 1,
                kind: EvidenceKind::PaymentChallenge,
                digest: c.challenge_digest,
            },
            scheme: c.scheme,
            payer: AccountId {
                kind: AccountKind::TokenAccount,
                ..account(17)
            },
            payee: c.payee.clone(),
            payment: WorkflowAmount {
                asset: WorkflowAsset::Token(c.asset.clone()),
                units: c.amount,
                decimals: 6,
            },
            fee_payer: c.fee_payer.clone(),
            fee_bounds: Some(vec![fee()]),
            expires_at_seconds: c.expires_at_seconds,
            response_access_key: c.response_access_key,
            binding: b.clone(),
        }))
    }
}
fn host() -> Arc<Host> {
    Arc::new(Host {
        wrong_binding: false,
        free: false,
        error: false,
    })
}
fn freeze(c: &mut Context) {
    if c.workflow.as_ref().unwrap().budgets.is_empty() {
        c.workflow
            .as_mut()
            .unwrap()
            .budgets
            .push(WorkflowBudgetObservation {
                budget_id: "native-budget".into(),
                asset: asset(),
                decimals: 9,
                limit_units: 50000000.into(),
                spent_units: 0.into(),
                reserved_units: 0.into(),
            });
        if let Some(CurlOutcome::PaymentRequired(challenge)) =
            &c.workflow.as_ref().unwrap().curl_outcome
        {
            let a = challenge.asset.clone();
            c.workflow
                .as_mut()
                .unwrap()
                .budgets
                .push(WorkflowBudgetObservation {
                    budget_id: "token-budget".into(),
                    asset: WorkflowAsset::Token(a),
                    decimals: 6,
                    limit_units: 5000.into(),
                    spent_units: 0.into(),
                    reserved_units: 0.into(),
                });
        }
    }
    let e = c.workflow.as_mut().unwrap();
    e.binding.request_digest = request_digest(
        &e.binding,
        &e.execution_request,
        &e.curl_request,
        &e.curl_outcome,
    )
    .unwrap();
    for proof in &mut e.debit_authorities {
        proof.binding = e.binding.clone();
    }
}
fn execution() -> (allowit_sdk::CompiledPolicy, Context) {
    let p = compile(EXEC).unwrap();
    let b = binding(&p);
    let mut c = Context::default();
    c.install_workflow(WorkflowEnvironment {
        evaluated_at_seconds: 100,
        debit_authorities: vec![],
        execution_request: Some(request(&b)),
        curl_request: None,
        curl_outcome: None,
        binding: b,
        host: host(),
        budgets: vec![],
    });
    freeze(&mut c);
    (p, c)
}
fn payment() -> (allowit_sdk::CompiledPolicy, Context) {
    let p = compile(PAYMENT).unwrap();
    let b = binding(&p);
    let mut c = Context {
        now: 100,
        ..Context::default()
    };
    c.install_workflow(WorkflowEnvironment {
        evaluated_at_seconds: 100,
        debit_authorities: vec![],
        binding: b,
        execution_request: None,
        curl_request: Some(CurlRequest {
            url: "https://provider.invalid/report".into(),
            method: Some("GET".into()),
            headers: None,
            body: None,
            body_file: None,
        }),
        curl_outcome: Some(CurlOutcome::PaymentRequired(PaymentChallenge {
            scheme: PaymentScheme::CooperatingV1,
            schema: 1,
            challenge_digest: [20; 32],
            gateway_origin: "https://provider.invalid".into(),
            endpoint_path: "/report".into(),
            http_request_digest: [21; 32],
            network: [9; 32],
            asset: AssetId {
                network: [9; 32],
                token: AccountId {
                    chain: Chain::Solana,
                    kind: AccountKind::Contract,
                    address: [22; 32],
                },
            },
            payee: account(8),
            fee_payer: account(7),
            amount: 1000.into(),
            expires_at_seconds: 200,
            response_access_key: [23; 32],
            authenticated_wire_bytes: vec![1, 2, 3],
        })),
        host: host(),
        budgets: vec![],
    });
    let e = c.workflow.as_mut().unwrap();
    if let Some(CurlOutcome::PaymentRequired(challenge)) = &e.curl_outcome {
        e.debit_authorities.push(WorkflowDebitAuthority {
            account: AccountId {
                kind: AccountKind::TokenAccount,
                ..account(17)
            },
            asset: WorkflowAsset::Token(challenge.asset.clone()),
            authority: e.binding.domain.authority.clone(),
            binding: e.binding.clone(),
            evidence: EvidenceRef {
                namespace_id: 1,
                schema: 1,
                kind: EvidenceKind::ExternalClaim,
                digest: [44; 32],
            },
        });
    }
    freeze(&mut c);
    (p, c)
}
#[test]
fn actual_source_typed_fields_and_all_entries() {
    let (p, mut c) = execution();
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.outcome, "pass", "{d:?}");
    assert_eq!(d.workflow_outputs.len(), 1);
    assert_eq!(p.ir.version, "1.1.0");
    assert_eq!(p.typed_workflow_requirements.len(), 2);
    let env = c.workflow.as_mut().unwrap();
    let r = env.execution_request.as_mut().unwrap();
    let mut second = r.effect_bounds[0].clone();
    second.max_debit = 10000001.into();
    r.effect_bounds.push(second);
    freeze(&mut c);
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.outcome, "fail");
    assert!(d.workflow_outputs.is_empty());
}
#[test]
fn payment_some_free_none_and_error_are_distinct() {
    let (p, mut c) = payment();
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.outcome, "pass", "{d:?}");
    assert!(matches!(d.workflow_outputs[0], WorkflowOutput::Payment(_)));
    c.workflow.as_mut().unwrap().host = Arc::new(Host {
        wrong_binding: false,
        free: true,
        error: false,
    });
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.code, "WORKFLOW_BINDING");
    c.workflow.as_mut().unwrap().curl_outcome = Some(CurlOutcome::Complete(HttpResponse {
        status: 200,
        body: b"real body".to_vec(),
        receipt_digest: [31; 32],
    }));
    freeze(&mut c);
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.outcome, "pass");
    assert!(matches!(
        d.workflow_outputs[0],
        WorkflowOutput::FreeResponse { .. }
    ));
    assert!(
        matches!(&c.workflow.as_ref().unwrap().curl_outcome,Some(CurlOutcome::Complete(r)) if r.body==b"real body")
    );
    c.workflow.as_mut().unwrap().host = Arc::new(Host {
        wrong_binding: false,
        free: false,
        error: true,
    });
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "MALFORMED");
}
#[test]
fn unsupported_profile_wrong_binding_and_missing_fees_fail_closed() {
    let (p, mut c) = execution();
    assert_eq!(
        evaluate(&p, Profile::Contract, &c).code,
        "WORKFLOW_PROFILE_UNSUPPORTED"
    );
    c.workflow.as_mut().unwrap().host = Arc::new(Host {
        wrong_binding: true,
        free: false,
        error: false,
    });
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    c.workflow.as_mut().unwrap().host = host();
    c.workflow.as_mut().unwrap().binding.profile_digest = [0; 32];
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .fee_bounds = None;
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).outcome, "fail");
}
#[test]
fn opaque_json_cannot_install_authority_and_static_metadata_is_checked() {
    let (p, c) = execution();
    let json = serde_json::to_value(&c).unwrap();
    assert!(json.get("workflow").is_none());
    assert!(json.get("execution_request").is_none());
    let clone: Context = serde_json::from_value(json).unwrap();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &clone).code,
        "WORKFLOW_INPUT_REQUIRED"
    );
    let mut p = p;
    p.typed_workflow_requirements[0].inputs[0].value_type = WorkflowType::named("PaymentRequest");
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "INVALID_ARTIFACT");
}
#[test]
fn no_early_loop_approval_or_effectful_loop() {
    assert!(
        compile(&EXEC.replace(
            "return allowit::fail(\"Debit exceeds owner ceiling\")",
            "return Ok(())"
        ))
        .is_err()
    );
    assert!(
        compile(&EXEC.replace(
            "if effect.max_burn > 0",
            "if paysh::call(\"service\", \"input\", 1, 1, 1)"
        ))
        .is_err()
    );
    assert!(
        compile(&EXEC.replace("effect.max_debit > 10000000", "ctx.amount_units > 10000000"))
            .is_err()
    );
}
#[test]
fn old_ir_cannot_smuggle_new_semantics() {
    let (p, _) = execution();
    let mut ir = p.ir;
    ir.version = "1.0.0".into();
    assert!(allowit_sdk::validate_program(&ir).is_err());
    let registry = allowit_sdk::process_value(serde_json::json!({"operation":"registry"}));
    assert_eq!(registry["registry_version"], "1.4.0");
    assert_eq!(registry["type_declarations"][0], "ExecutionRequest");
}

#[test]
fn complete_sum_and_all_asset_coverage_are_mandatory() {
    let (p, mut c) = execution();
    let r = c
        .workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap();
    let mut second = r.effect_bounds[0].clone();
    second.max_debit = 9500000.into();
    r.effect_bounds.push(second);
    freeze(&mut c);
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_REQUEST_CAP_EXCEEDED"
    );
    let (p, mut c) = execution();
    c.workflow.as_mut().unwrap().budgets[0].spent_units = 49000000.into();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_BUDGET_EXCEEDED"
    );
    let (p, mut c) = execution();
    c.workflow.as_mut().unwrap().budgets[0].reserved_units = 49000000.into();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_BUDGET_EXCEEDED"
    );
    let (p, mut c) = execution();
    let r = c
        .workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap();
    r.effect_bounds[0].asset = WorkflowAsset::Native {
        chain: Chain::Solana,
        network: [88; 32],
    };
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
}
#[test]
fn immutable_ingress_scale_limits_and_zero_fee_proof() {
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .effect_bounds[0]
        .max_debit = 2.into();
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    c.workflow.as_mut().unwrap().budgets[0].decimals = 6;
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_ASSET_MISMATCH"
    );
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .fee_bounds = Some(vec![]);
    freeze(&mut c);
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_ZERO_FEE_EVIDENCE_REQUIRED"
    );
    let (p, mut c) = payment();
    c.workflow
        .as_mut()
        .unwrap()
        .curl_request
        .as_mut()
        .unwrap()
        .body_file = Some("/private/path".into());
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
}
#[test]
fn typed_source_has_exact_constructor_budgets_without_scalar_currency() {
    let (p, _) = execution();
    assert!(p.limit.is_empty());
    assert!(p.token.is_empty());
    assert_eq!(p.typed_budget_requirements[0].decimals, 9);
    assert_eq!(p.typed_budget_requirements[0].total_budget_units, 50000000);
    let (p, c) = payment();
    assert_eq!(p.typed_budget_requirements.len(), 2);
    let d = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(d.typed_budget_plans.len(), 2);
    assert!(
        d.typed_budget_plans
            .iter()
            .any(|b| b.requirement.decimals == 9
                && b.debit_units == Amount256::from(0)
                && b.fee_units == Amount256::from(5000))
    );
}

#[test]
fn unicode_spans_and_exact_budget_wire_metadata() {
    let source = include_str!("fixtures/typed-execution-unicode-policy.rs");
    let compiled = compile(source).unwrap();
    for node in &compiled.typed_workflow_requirements {
        assert_eq!(node.span_encoding, "utf8_bytes");
        assert!(source.is_char_boundary(node.span.start));
        assert!(source.is_char_boundary(node.span.end));
        assert!(source[node.span.start..node.span.end].starts_with(&node.operation));
    }
    let cap = compiled
        .typed_workflow_requirements
        .iter()
        .find(|n| n.operation.ends_with("_cap"))
        .unwrap();
    assert_eq!(cap.inputs[0].state, "via_try");
    let mut requirement = compiled.typed_budget_requirements[0].clone();
    requirement.total_budget_units = u64::MAX;
    let json = serde_json::to_value(&requirement).unwrap();
    assert_eq!(json["total_budget_units"], "18446744073709551615");
    assert_eq!(
        serde_json::from_value::<TypedBudgetRequirement>(json).unwrap(),
        requirement
    );
    let mut invalid = serde_json::to_value(&requirement).unwrap();
    invalid["total_budget_units"] = serde_json::json!(1);
    assert!(serde_json::from_value::<TypedBudgetRequirement>(invalid).is_err());
}

#[test]
fn comments_cannot_enable_typed_ir_or_unicode_legacy_variables() {
    let source = "// allowit::execution_request_validate 🟢\nasync fn _execute(ctx: &Context) -> PolicyResult { let validé = true; Ok(()) }";
    assert!(compile(source).is_err());
    let source = EXEC.replace("validated", "valide\u{301}");
    assert!(compile(&source).is_err());
}

#[test]
fn strict_canonical_ingress_rejects_variant_extensions() {
    let value = serde_json::json!({"Native":{"chain":"Solana","network":vec![9;32],"forged":true}});
    assert!(serde_json::from_value::<WorkflowAsset>(value).is_err());
    let instruction = NativeInstruction::SolanaNativeTransfer {
        source: account(1),
        destination: account(2),
        lamports: 1,
    };
    let mut value = serde_json::to_value(instruction).unwrap();
    value["SolanaNativeTransfer"]["forged"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NativeInstruction>(value).is_err());
    assert!(
        serde_json::from_str::<ExecutionInput>(r#"{"Message":[1],"Instructions":[]}"#).is_err()
    );
    assert!(serde_json::from_str::<BodyParam>(r#"{"Text":"x","extra":true}"#).is_err());
}

#[test]
fn unicode_span_and_budget_projection_tampering_are_rejected() {
    let source = include_str!("fixtures/typed-execution-unicode-policy.rs");
    let mut policy = compile(source).unwrap();
    let (_, context) = execution();
    policy.typed_workflow_requirements[0].span.start = source.find('é').unwrap() + 1;
    assert!(!source.is_char_boundary(policy.typed_workflow_requirements[0].span.start));
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &context).code,
        "INVALID_ARTIFACT"
    );
    let (mut policy, context) = execution();
    policy.typed_budget_requirements[0].total_budget_units += 1;
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &context).code,
        "INVALID_ARTIFACT"
    );
}

#[test]
fn producer_families_repetition_clock_and_transfer_coverage_fail_closed() {
    assert!(
        compile(&EXEC.replace(
            "let validated =",
            "let duplicate = allowit::execution_request_validate(&request)?; let validated ="
        ))
        .is_err()
    );
    assert!(compile(&EXEC.replace("for effect in &validated.request.effect_bounds {", "for effect in &validated.request.effect_bounds { allowit::execution_request_validate(&request)?;")).is_err());
    assert!(compile(&EXEC.replace("Ok(())", "paysh::call(\"s\",\"i\",1,1,1); Ok(())")).is_err());
    let (p, mut c) = execution();
    c.workflow.as_mut().unwrap().evaluated_at_seconds = 0;
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    let (_, payment) = payment();
    c.workflow.as_mut().unwrap().curl_request =
        payment.workflow.as_ref().unwrap().curl_request.clone();
    c.workflow.as_mut().unwrap().curl_outcome =
        payment.workflow.as_ref().unwrap().curl_outcome.clone();
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .effect_bounds
        .clear();
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    if let ExecutionInput::Instructions(items) = &mut c
        .workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .input
    {
        items.push(items[0].clone());
    }
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
}

#[test]
fn token_debit_requires_exact_installed_account_mint_authority_and_binding() {
    let (p, mut c) = payment();
    c.workflow.as_mut().unwrap().debit_authorities.clear();
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    for kind in 0..4 {
        let (p, mut c) = payment();
        let proof = &mut c.workflow.as_mut().unwrap().debit_authorities[0];
        match kind {
            0 => proof.account.address = [99; 32],
            1 => proof.asset = asset(),
            2 => {
                proof.authority = WorkflowAuthority::EngineWallet {
                    wallet: account(99),
                    signer: account(99),
                }
            }
            _ => proof.binding.run_id = [99; 32],
        }
        assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    }
    let (p, mut c) = payment();
    c.now = 0;
    c.workflow.as_mut().unwrap().evaluated_at_seconds = 201;
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = payment();
    if let Some(CurlOutcome::PaymentRequired(challenge)) =
        &mut c.workflow.as_mut().unwrap().curl_outcome
    {
        challenge.network = [88; 32];
    }
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
}
#[test]
fn typed_metadata_integer_ports_preserve_exact_decimal_without_changing_ir() {
    let compiled = compile(EXEC).unwrap();
    let node = compiled
        .typed_workflow_requirements
        .iter()
        .find(|n| n.operation.ends_with("_cap"))
        .unwrap();
    let json = serde_json::to_value(node).unwrap();
    assert_eq!(json["inputs"][4]["binding"]["value"], "50000000");
    assert_eq!(
        serde_json::from_value::<TypedWorkflowNode>(json).unwrap(),
        *node
    );
    let mut forged = node.clone();
    forged.inputs[4].binding = allowit_sdk::Expr::Integer { value: u64::MAX };
    let json = serde_json::to_value(&forged).unwrap();
    assert_eq!(
        json["inputs"][4]["binding"]["value"],
        "18446744073709551615"
    );
    assert_eq!(
        serde_json::from_value::<TypedWorkflowNode>(json).unwrap(),
        forged
    );
}

#[test]
fn owner_answers_and_semantic_evidence_do_not_cross_typed_runs() {
    let source = EXEC.replace(
        "Ok(())",
        "allowit::require_user_input(ctx,\"Approve this exact native request?\").await?; Ok(())",
    );
    let p = compile(&source).unwrap();
    let (_, mut c) = execution();
    c.workflow.as_mut().unwrap().binding = binding(&p);
    freeze(&mut c);
    let first = evaluate(&p, Profile::Oracle, &c);
    assert_eq!(first.outcome, "awaiting_input");
    c.answers.insert(first.input_key.unwrap(), true);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).outcome, "pass");
    c.workflow.as_mut().unwrap().binding.run_id = [99; 32];
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).outcome, "awaiting_input");
    let mut other = c.workflow.as_ref().unwrap().binding.clone();
    other.evidence_digest = [77; 32];
    assert_ne!(
        evidence_key(&other, "Same question"),
        evidence_key(&c.workflow.as_ref().unwrap().binding, "Same question")
    );
}
#[test]
fn deceptive_context_guards_unicode_and_fee_claims_fail_closed() {
    for statement in [
        "allowit::require_recipient(&ctx.recipient,\"X\")?;",
        "allowit::allow_actions(ctx,[\"send\"])?;",
        "let amount=allowit::context_u64(ctx,\"amount\");",
    ] {
        assert!(compile(&EXEC.replace("Ok(())", &format!("{statement} Ok(())"))).is_err());
    }
    assert!(compile(&EXEC.replace("owner ceiling", "owner \u{202e} ceiling")).is_err());
    assert!(compile(&EXEC.replace("validated", "validatеd")).is_err());
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .fee_bounds
        .as_mut()
        .unwrap()[0]
        .max_fee = 0.into();
    freeze(&mut c);
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_ZERO_FEE_EVIDENCE_REQUIRED"
    );
    let source = "async fn _execute(ctx:&Context)->PolicyResult { if let Some(request)=&ctx.execution_request {let exists=true;} else {return allowit::fail(\"Missing\");} Ok(()) }";
    let p = compile(source).unwrap();
    let (_, mut c) = execution();
    c.workflow.as_mut().unwrap().binding = binding(&p);
    freeze(&mut c);
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_PROPOSAL_REQUIRED"
    );
}

#[derive(Debug)]
struct MessageHost {
    lamports: u64,
}
impl WorkflowHost for MessageHost {
    fn execution_request_validate(
        &self,
        request: &ExecutionRequest,
        binding: &WorkflowBinding,
    ) -> Result<ValidatedExecutionRequest, WorkflowError> {
        let decoded = ExecutionRequest {
            input: ExecutionInput::Instructions(vec![NativeInstruction::SolanaNativeTransfer {
                source: account(7),
                destination: account(8),
                lamports: self.lamports,
            }]),
            ..request.clone()
        };
        let mut validated = host().execution_request_validate(&decoded, binding)?;
        validated.request = request.clone();
        Ok(validated)
    }
    fn payment_request_from_curl(
        &self,
        _outcome: &CurlOutcome,
        _request: &CurlRequest,
        _binding: &WorkflowBinding,
    ) -> Result<Option<PaymentRequest>, WorkflowError> {
        Err(WorkflowError::new("UNSUPPORTED", "No payment fixture"))
    }
}
#[test]
fn decoded_message_native_coverage_and_native_fee_presence_are_mandatory() {
    let (p, mut c) = execution();
    c.workflow
        .as_mut()
        .unwrap()
        .execution_request
        .as_mut()
        .unwrap()
        .input = ExecutionInput::Message(b"authenticated fixture packet".to_vec());
    c.workflow.as_mut().unwrap().host = Arc::new(MessageHost { lamports: 1000000 });
    freeze(&mut c);
    assert_eq!(evaluate(&p, Profile::Oracle, &c).outcome, "pass");
    c.workflow.as_mut().unwrap().host = Arc::new(MessageHost { lamports: 2000000 });
    assert_eq!(evaluate(&p, Profile::Oracle, &c).code, "WORKFLOW_BINDING");
    let (p, mut c) = execution();
    let e = c.workflow.as_mut().unwrap();
    let fee = &mut e
        .execution_request
        .as_mut()
        .unwrap()
        .fee_bounds
        .as_mut()
        .unwrap()[0];
    fee.asset = WorkflowAsset::Token(AssetId {
        network: [9; 32],
        token: AccountId {
            chain: Chain::Solana,
            kind: AccountKind::Contract,
            address: [22; 32],
        },
    });
    freeze(&mut c);
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_ZERO_FEE_EVIDENCE_REQUIRED"
    );
}

#[derive(Debug)]
struct MissingPaymentFees;
impl WorkflowHost for MissingPaymentFees {
    fn execution_request_validate(
        &self,
        request: &ExecutionRequest,
        binding: &WorkflowBinding,
    ) -> Result<ValidatedExecutionRequest, WorkflowError> {
        host().execution_request_validate(request, binding)
    }
    fn payment_request_from_curl(
        &self,
        outcome: &CurlOutcome,
        request: &CurlRequest,
        binding: &WorkflowBinding,
    ) -> Result<Option<PaymentRequest>, WorkflowError> {
        let mut payment = host().payment_request_from_curl(outcome, request, binding)?;
        if let Some(payment) = &mut payment {
            payment.fee_bounds = None;
        }
        Ok(payment)
    }
}
#[test]
fn final_authorization_rejects_missing_fees_even_without_source_fee_refusal() {
    for (source, is_payment) in [(EXEC, false), (PAYMENT, true)] {
        let source = source.replace(
            "return allowit::fail(\"Fees are unresolved\");",
            "let unresolved = true;",
        );
        let policy = compile(&source).unwrap();
        let (_, mut context) = if is_payment { payment() } else { execution() };
        let environment = context.workflow.as_mut().unwrap();
        environment.binding = binding(&policy);
        if is_payment {
            environment.host = Arc::new(MissingPaymentFees);
        } else {
            environment.execution_request.as_mut().unwrap().fee_bounds = None;
        }
        freeze(&mut context);
        let decision = evaluate(&policy, Profile::Oracle, &context);
        assert_eq!(decision.code, "WORKFLOW_FEES_UNRESOLVED");
        assert_eq!(decision.outcome, "fail");
    }
}

#[test]
fn oversized_provider_responses_are_rejected_before_hashing() {
    let (p, mut c) = payment();
    let environment = c.workflow.as_mut().unwrap();
    if let Some(CurlOutcome::PaymentRequired(challenge)) = &mut environment.curl_outcome {
        challenge.authenticated_wire_bytes = vec![0; 8193];
    }
    assert!(
        request_digest(
            &environment.binding,
            &environment.execution_request,
            &environment.curl_request,
            &environment.curl_outcome
        )
        .is_err()
    );
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_INPUT_LIMIT"
    );
    c.workflow.as_mut().unwrap().curl_outcome = Some(CurlOutcome::Complete(HttpResponse {
        status: 200,
        body: vec![0; 65537],
        receipt_digest: [31; 32],
    }));
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_INPUT_LIMIT"
    );
}

#[test]
fn oversized_agent_requests_are_rejected_before_hashing() {
    let (p, mut c) = payment();
    let env = c.workflow.as_mut().unwrap();
    env.curl_request.as_mut().unwrap().method = Some("x".repeat(17));
    assert!(
        request_digest(
            &env.binding,
            &env.execution_request,
            &env.curl_request,
            &env.curl_outcome
        )
        .is_err()
    );
    env.curl_request.as_mut().unwrap().method = None;
    env.curl_request.as_mut().unwrap().url = "x".repeat(4097);
    assert!(
        request_digest(
            &env.binding,
            &env.execution_request,
            &env.curl_request,
            &env.curl_outcome
        )
        .is_err()
    );
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_INPUT_LIMIT"
    );
    let (p, mut c) = execution();
    let env = c.workflow.as_mut().unwrap();
    env.execution_request.as_mut().unwrap().input = ExecutionInput::Message(vec![0; 65537]);
    assert!(
        request_digest(
            &env.binding,
            &env.execution_request,
            &env.curl_request,
            &env.curl_outcome
        )
        .is_err()
    );
    assert_eq!(
        evaluate(&p, Profile::Oracle, &c).code,
        "WORKFLOW_INPUT_LIMIT"
    );
}
