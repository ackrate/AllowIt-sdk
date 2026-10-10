use allowit_sdk::{
    Context, ExecutionFeature, Profile, ProviderCallInput, ProviderPaymentAsset, compile, evaluate,
    process_value,
};
use serde_json::json;

const CALL: &str = "paysh::call(\"air-quality\", \"request\", 1000, 5000000, 100000)";
fn source(body: &str) -> String {
    format!(
        "use allowit::prelude::*; pub async fn execute(ctx: &Context) -> PolicyResult {{ set_cap(ctx, \"100\", \"HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv\")?; {body} }}"
    )
}
fn context() -> Context {
    let mut ctx: Context = serde_json::from_str(include_str!("../examples/context.json")).unwrap();
    ctx.amount_units = 1000;
    ctx.token = "HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv".into();
    ctx.provider_call_input = Some(ProviderCallInput {
        payment_asset: ProviderPaymentAsset {
            network: ctx.network.clone(),
            asset: "HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv".into(),
            decimals: 6,
        },
        service_id: "air-quality".into(),
        input_key: "request".into(),
        request_digest: "a".repeat(64),
    });
    ctx
}
#[test]
fn qualified_operation_retains_typed_args_requirements_and_executed_effect() {
    let policy = compile(&source(&format!(
        "let admitted = {CALL}; if !admitted {{ return fail(\"Unavailable\"); }} Ok(())"
    )))
    .unwrap();
    assert!(policy.calls.iter().any(|call| call.name == "paysh::call"));
    for feature in [
        ExecutionFeature::ProviderCall,
        ExecutionFeature::PaidHttpCall,
        ExecutionFeature::NativeSettlement,
    ] {
        assert!(policy.execution_requirements.features.contains(&feature));
    }
    let decision = evaluate(&policy, Profile::Oracle, &context());
    assert_eq!(decision.outcome, "pass");
    let effect = &decision.system_operations[0];
    assert_eq!(effect.operation, "paysh::call");
    assert_eq!(effect.request_digest, "a".repeat(64));
    assert_eq!(
        (
            effect.max_payment_units,
            effect.max_swap_lamports,
            effect.max_service_fee_lamports_per_execution
        ),
        (1000, 5000000, 100000)
    );
}
#[test]
fn unregistered_aliases_wrong_types_and_multiple_calls_fail_compilation() {
    for call in [
        "call(\"air-quality\", \"request\", 1000, 5000000, 100000)",
        "allowit::call(\"air-quality\", \"request\", 1000, 5000000, 100000)",
        "paysh::pay(\"air-quality\", \"request\", 1000, 5000000, 100000)",
        "paysh::swap(\"air-quality\", \"request\", 1000, 5000000, 100000)",
        "paysh::call(\"air-quality\", \"request\", \"1000\", 5000000, 100000)",
    ] {
        assert!(
            compile(&source(&format!("{call}; Ok(())"))).is_err(),
            "{call}"
        );
    }
    assert!(
        compile(&source(&format!(
            "if true {{ let admitted = {CALL}; }} else {{ let admitted = {CALL}; }} Ok(())"
        )))
        .is_err()
    );
}
#[test]
fn missing_forged_or_mismatched_host_binding_never_exposes_effects() {
    let policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    for field in ["missing", "service", "input", "digest"] {
        let mut ctx = context();
        match field {
            "missing" => ctx.provider_call_input = None,
            "service" => ctx.provider_call_input.as_mut().unwrap().service_id = "other".into(),
            "input" => ctx.provider_call_input.as_mut().unwrap().input_key = "other".into(),
            _ => ctx.provider_call_input.as_mut().unwrap().request_digest = "invalid".into(),
        }
        let result = evaluate(&policy, Profile::Oracle, &ctx);
        assert_eq!(result.outcome, "fail");
        assert!(result.system_operations.is_empty());
    }
    let result = process_value(
        json!({"operation":"evaluate","profile":"oracle","source":source(&format!("let admitted = {CALL}; Ok(())")),"context":context()}),
    );
    assert_eq!(result["error"]["code"], "INVALID_CONTEXT");
}
#[test]
fn later_refusal_pause_caps_or_untaken_branch_discard_provider_effects() {
    for body in [
        format!("let admitted = {CALL}; fail(\"Denied\")"),
        format!("let admitted = {CALL}; require_user_input(ctx, \"Approve\").await?; Ok(())"),
        format!(
            "let admitted = {CALL}; cap_per_transaction(ctx, \"0.000001\", \"HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv\")?; Ok(())"
        ),
    ] {
        let result = evaluate(
            &compile(&source(&body)).unwrap(),
            Profile::Oracle,
            &context(),
        );
        assert_ne!(result.outcome, "pass");
        assert!(result.system_operations.is_empty());
    }
    let skipped = evaluate(
        &compile(&source(&format!(
            "if false {{ let admitted = {CALL}; }} Ok(())"
        )))
        .unwrap(),
        Profile::Oracle,
        &context(),
    );
    assert_eq!(skipped.outcome, "pass");
    assert!(skipped.system_operations.is_empty());
    let mut capped = context();
    capped.spent_units = 100_000_000;
    let result = evaluate(
        &compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap(),
        Profile::Oracle,
        &capped,
    );
    assert_eq!(result.outcome, "fail");
    assert!(result.system_operations.is_empty());
}
#[test]
fn every_contract_profile_rejects_provider_effects_including_untaken_branches() {
    for body in [
        format!("let admitted = {CALL}; Ok(())"),
        format!("if false {{ let admitted = {CALL}; }} Ok(())"),
    ] {
        let result = evaluate(
            &compile(&source(&body)).unwrap(),
            Profile::Contract,
            &context(),
        );
        assert_eq!(result.code, "PROVIDER_PROFILE_UNSUPPORTED");
        assert!(result.system_operations.is_empty());
    }
}

#[test]
fn private_source_owner_continuation_and_trace_release_only_the_approved_effect() {
    let policy = compile(include_str!("fixtures/provider-call-policy.rs")).unwrap();
    let mut ctx = context();
    ctx.amount_units = 1000;
    ctx.provider_call_input.as_mut().unwrap().input_key = "canonical-service-input".into();
    let (paused, trace) = allowit_sdk::evaluate_with_trace(&policy, &ctx);
    assert_eq!(paused.outcome, "awaiting_input");
    assert!(paused.system_operations.is_empty());
    assert!(!trace.unwrap().complete);
    let key = paused.input_key.unwrap();
    ctx.answers.insert(key.clone(), false);
    assert!(
        evaluate(&policy, Profile::Oracle, &ctx)
            .system_operations
            .is_empty()
    );
    ctx.answers.insert(key, true);
    let (approved, trace) = allowit_sdk::evaluate_with_trace(&policy, &ctx);
    assert_eq!(approved.outcome, "pass");
    assert_eq!(approved.system_operations.len(), 1);
    assert!(trace.unwrap().complete);
    ctx.amount_units = 1001;
    let refused = evaluate(&policy, Profile::Oracle, &ctx);
    assert_eq!(refused.outcome, "fail");
    assert!(refused.system_operations.is_empty());
}

mod source_facade {
    extern crate allowit_sdk as allowit;
    include!("fixtures/provider-call-policy.rs");
    #[test]
    fn provider_source_typechecks_and_direct_facade_cannot_admit_effects() {
        let ctx = Context::default();
        let params = new();
        let _future = _execute(&ctx, &params);
        assert!(!paysh::call(
            "air-quality",
            "canonical-service-input",
            1000,
            5000000,
            100000
        ));
    }
}

#[test]
fn new_operations_cannot_claim_legacy_registry_metadata() {
    let mut policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    policy.registry_version = "1.2.0".into();
    let rejected = evaluate(&policy, Profile::Oracle, &context());
    assert_eq!(rejected.code, "INVALID_ARTIFACT");
    assert!(rejected.system_operations.is_empty());
}

#[test]
fn guarded_exact_payment_is_within_static_ceiling_and_metadata_cannot_be_forged() {
    let mut policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    assert_eq!(policy.provider_call_requirements.len(), 1);
    assert_eq!(policy.provider_call_requirements[0].max_payment_units, 1000);
    for amount in [1, 499, 1000] {
        let mut ctx = context();
        ctx.amount_units = amount;
        let result = evaluate(&policy, Profile::Oracle, &ctx);
        assert_eq!(result.outcome, "pass");
        assert_eq!(result.system_operations[0].payment_units, amount);
        assert_eq!(result.system_operations[0].max_payment_units, 1000);
    }
    for amount in [0, 1001] {
        let mut ctx = context();
        ctx.amount_units = amount;
        let result = evaluate(&policy, Profile::Oracle, &ctx);
        assert_eq!(result.outcome, "fail");
        assert!(result.system_operations.is_empty());
    }
    policy.provider_call_requirements[0].max_payment_units = 2000;
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &context()).code,
        "INVALID_ARTIFACT"
    );
}
#[test]
fn dynamic_source_caps_reject_and_constructor_constants_are_projected() {
    for value in ["ctx.amount_units", "context_u64(ctx, \"fee\")?"] {
        assert!(
            compile(&source(&format!(
                "let admitted=paysh::call(\"air-quality\",\"request\",1000,5000000,{value}); Ok(())"
            )))
            .is_err()
        );
    }
    let src = "use allowit::v1::prelude::*; struct PolicyParams {max_units:u64} fn new()->PolicyParams{PolicyParams{max_units:1000}} async fn _execute(ctx:&Context,params:&PolicyParams)->PolicyResult { allowit::set_cap(ctx.spent_units,ctx.amount_units,&ctx.token,100000000,\"HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv\",6)?; if !paysh::call(\"air-quality\",\"request\",params.max_units,5000000,100000){return allowit::fail(\"Unavailable\");} Ok(()) }";
    let compiled = compile(src).unwrap();
    assert_eq!(
        compiled.provider_call_requirements[0].max_payment_units,
        1000
    );
    assert_eq!(
        evaluate(&compiled, Profile::Oracle, &context()).outcome,
        "pass"
    );
}
#[test]
fn deserializers_cannot_set_trusted_provider_binding() {
    let mut wire = serde_json::to_value(context()).unwrap();
    assert!(serde_json::from_value::<Context>(wire.clone()).is_err());
    wire.as_object_mut().unwrap().remove("provider_call_input");
    let decoded: Context = serde_json::from_value(wire).unwrap();
    assert!(decoded.provider_call_input.is_none());
    let policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &decoded).code,
        "PROVIDER_INPUT_REQUIRED"
    );
}
#[test]
fn forged_ir_aliases_duplicate_calls_and_legacy_hidden_calls_fail_closed() {
    let policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    for alias in ["call", "paysh::pay", "paysh::swap", "other::call"] {
        let mut forged = policy.ir.clone();
        if let allowit_sdk::Statement::Let {
            value: allowit_sdk::Expr::Call { name, .. },
            ..
        } = &mut forged.statements[1]
        {
            *name = alias.into();
        } else {
            panic!("Expected typed call");
        }
        assert!(allowit_sdk::validate_program(&forged).is_err());
        assert!(
            allowit_sdk::evaluate_ir(&forged, Profile::Oracle, &context())
                .system_operations
                .is_empty()
        );
    }
    let mut duplicate = policy.ir.clone();
    duplicate
        .statements
        .insert(2, duplicate.statements[1].clone());
    assert!(allowit_sdk::validate_program(&duplicate).is_err());
    let mut hidden = compile(&source(&format!(
        "if false {{ let admitted = {CALL}; }} Ok(())"
    )))
    .unwrap();
    hidden.registry_version = "1.2.0".into();
    assert_eq!(
        evaluate(&hidden, Profile::Oracle, &context()).code,
        "INVALID_ARTIFACT"
    );
}

#[test]
fn authenticated_testnet_asset_is_exact_and_legacy_usdc_semantics_are_unchanged() {
    let mint = "HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv";
    let policy = compile(&source(&format!("let admitted = {CALL}; Ok(())"))).unwrap();
    assert_eq!(policy.token, mint);
    assert_eq!(policy.provider_call_requirements[0].payment_asset_id, mint);
    let passed = evaluate(&policy, Profile::Oracle, &context());
    assert_eq!(passed.outcome, "pass");
    assert_eq!(passed.system_operations[0].payment_asset.asset, mint);
    for field in ["SOL", "USDC", "mint", "decimals", "network"] {
        let mut ctx = context();
        match field {
            "SOL" => ctx.token = "SOL".into(),
            "USDC" => ctx.token = "USDC".into(),
            "mint" => {
                ctx.token = "wrong-mint".into();
                ctx.provider_call_input
                    .as_mut()
                    .unwrap()
                    .payment_asset
                    .asset = "wrong-mint".into();
            }
            "decimals" => {
                ctx.provider_call_input
                    .as_mut()
                    .unwrap()
                    .payment_asset
                    .decimals = 9
            }
            _ => {
                ctx.provider_call_input
                    .as_mut()
                    .unwrap()
                    .payment_asset
                    .network = "solana:mainnet".into()
            }
        }
        let result = evaluate(&policy, Profile::Oracle, &ctx);
        assert_eq!(result.outcome, "fail", "{field}");
        assert!(result.system_operations.is_empty());
    }
    let usdc_guard = compile(&source(&format!(
        "if ctx.token != \"USDC\" {{ return fail(\"Not USDC\"); }} let admitted = {CALL}; Ok(())"
    )))
    .unwrap();
    assert_eq!(
        evaluate(&usdc_guard, Profile::Oracle, &context()).reason,
        "Not USDC"
    );
    let legacy = compile("use allowit::prelude::*; pub async fn execute(ctx:&Context)->PolicyResult { set_cap(ctx, \"100\", \"USDC\")?; Ok(()) }").unwrap();
    assert_eq!(
        evaluate(&legacy, Profile::Oracle, &context()).outcome,
        "fail"
    );
    let ctx: Context = serde_json::from_str(include_str!("../examples/context.json")).unwrap();
    assert_eq!(evaluate(&legacy, Profile::Oracle, &ctx).outcome, "pass");
    assert!(compile(&format!("use allowit::prelude::*; pub async fn execute(ctx:&Context)->PolicyResult {{ {CALL}; Ok(()) }}")).is_err());
    let mut forged = policy;
    forged.provider_call_requirements[0].payment_asset_id = "USDC".into();
    assert_eq!(
        evaluate(&forged, Profile::Oracle, &context()).code,
        "INVALID_ARTIFACT"
    );
}

#[test]
fn provider_symbol_assets_and_forged_decision_authority_are_rejected() {
    for symbol in ["USDC", "SOL"] {
        assert!(
            compile(
                &source(&format!("let admitted={CALL}; Ok(())"))
                    .replace("HNCXuc5dkQrUimi76UaezxrF3hfEhWDr9BXvWXGyi2qv", symbol)
            )
            .is_err()
        );
    }
    let policy = compile(&source(&format!("let admitted={CALL}; Ok(())"))).unwrap();
    let wire = serde_json::to_value(evaluate(&policy, Profile::Oracle, &context())).unwrap();
    assert!(serde_json::from_value::<allowit_sdk::Decision>(wire).is_err());
    let too_long = "x".repeat(129);
    assert!(
        compile(&source(&format!(
            "cap_per_transaction(ctx, \"1\", \"{too_long}\")?; let admitted={CALL}; Ok(())"
        )))
        .is_err()
    );
}

#[test]
fn service_allowlist_branches_compile_but_only_one_exact_effect_can_execute() {
    let body = "if ctx.merchant == \"air-quality\" { if !paysh::call(\"air-quality\",\"request\",1000,5000000,100000) { return fail(\"Unavailable\"); } } else if ctx.merchant == \"weather\" { if !paysh::call(\"weather\",\"weather\",1000,5000000,100000) { return fail(\"Unavailable\"); } } else { return fail(\"Service not allowed\"); } Ok(())";
    let policy = compile(&source(body)).unwrap();
    assert_eq!(policy.provider_call_requirements.len(), 2);
    for (service, input) in [("air-quality", "request"), ("weather", "weather")] {
        let mut ctx = context();
        ctx.merchant = service.into();
        let binding = ctx.provider_call_input.as_mut().unwrap();
        binding.service_id = service.into();
        binding.input_key = input.into();
        let decision = evaluate(&policy, Profile::Oracle, &ctx);
        assert_eq!(decision.outcome, "pass");
        assert_eq!(decision.system_operations.len(), 1);
        assert_eq!(decision.system_operations[0].service_id, service);
    }
    let mut ctx = context();
    ctx.merchant = "unknown".into();
    assert_eq!(evaluate(&policy, Profile::Oracle, &ctx).outcome, "fail");
    let two=compile(&source("let a=paysh::call(\"air-quality\",\"request\",1000,5000000,100000); let b=paysh::call(\"weather\",\"weather\",1000,5000000,100000); Ok(())")).unwrap();
    assert_eq!(
        evaluate(&two, Profile::Oracle, &context()).code,
        "PROVIDER_CALL_LIMIT"
    );
    let nine = (0..9)
        .map(|i| {
            format!("let a{i}=paysh::call(\"service-{i}\",\"input-{i}\",1000,5000000,100000);")
        })
        .collect::<String>();
    assert!(compile(&source(&(nine + "Ok(())"))).is_err());
}
