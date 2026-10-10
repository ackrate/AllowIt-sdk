use allowit_sdk::{Context, Profile, compile, evaluate};
fn context() -> Context {
    serde_json::from_str(include_str!("../examples/context.json")).unwrap()
}
fn source(body: &str) -> String {
    format!(
        "use allowit::v1::prelude::*; struct PolicyParams {{}} fn new()->PolicyParams {{PolicyParams{{}}}} async fn _execute(ctx:&Context, params:&PolicyParams)->PolicyResult {{{body}}}"
    )
}
#[test]
fn constructor_and_primitives_preserve_real_accounting() {
    let source = include_str!("fixtures/constructor-policy.rs");
    let policy = compile(source).unwrap();
    assert_eq!(policy.limit, "5");
    assert_eq!(policy.registry_version, "1.4.0");
    for profile in [Profile::Oracle, Profile::Contract] {
        let mut ctx = context();
        ctx.amount_units = 2_000_000;
        assert_eq!(evaluate(&policy, profile, &ctx).outcome, "pass");
        ctx.amount_units = 2_000_001;
        assert_eq!(
            evaluate(&policy, profile, &ctx).code,
            "PURCHASE_CAP_EXCEEDED"
        );
        ctx.amount_units = 2_000_000;
        ctx.spent_units = 3_000_001;
        assert_eq!(evaluate(&policy, profile, &ctx).code, "POLICY_CAP_EXCEEDED");
        ctx.spent_units = 0;
        ctx.recipient = "unapproved".into();
        assert_eq!(evaluate(&policy, profile, &ctx).outcome, "fail");
        ctx.recipient = "11111111111111111111111111111111".into();
        ctx.token = "OTHER".into();
        assert_eq!(evaluate(&policy, profile, &ctx).outcome, "fail");
    }
    let changed =
        compile(&source.replace("total_limit: 5_000_000,", "total_limit: 1_000_000,")).unwrap();
    assert_ne!(changed.source_hash, policy.source_hash);
    assert_ne!(changed.ir_hash, policy.ir_hash);
    assert_eq!(changed.limit, "1");
}
#[test]
fn empty_template_builds_and_denies_in_every_profile() {
    let policy = compile(include_str!("fixtures/empty-policy.rs")).unwrap();
    for profile in [Profile::Oracle, Profile::Contract] {
        assert_eq!(evaluate(&policy, profile, &context()).outcome, "fail");
    }
}
#[test]
fn primitive_guards_reject_substitutes_and_hidden_configuration() {
    for body in [
        "allowit::set_cap(0, ctx.amount_units, &ctx.token, 5_000_000, \"USDC\", 6)?; Ok(())",
        "allowit::set_cap(ctx.spent_units, 0, &ctx.token, 5_000_000, \"USDC\", 6)?; Ok(())",
        "allowit::set_cap(ctx.spent_units, ctx.amount_units, \"USDC\", 5_000_000, \"USDC\", 6)?; Ok(())",
        "allowit::set_cap(ctx.spent_units, ctx.amount_units, &ctx.token, 5_000_000, \"USDC\", 9)?; Ok(())",
        "allowit::set_cap(ctx.spent_units, ctx.amount_units, &ctx.token, REPORT_PAYMENT, \"USDC\", 6)?; Ok(())",
        "allowit::set_cap(ctx, \"5\", \"USDC\")?; Ok(())",
        "set_cap(ctx, \"5\", \"USDC\")?; Ok(())",
        "allowit::require_recipient(\"allowed\", \"allowed\")?; Ok(())",
        "let params = 0; Ok(())",
        "let limit = params.missing; Ok(())",
        "if true && false {return allowit::fail(\"no\");} Ok(())",
        "if true || false {return allowit::fail(\"no\");} Ok(())",
        "if !allowit::is_one_of(&ctx.recipient, &[])? {return allowit::fail(\"no\");} Ok(())",
    ] {
        assert!(compile(&source(body)).is_err(), "accepted {body}");
    }
}
#[test]
fn constructor_is_a_bounded_rust_literal_declaration() {
    let good = include_str!("fixtures/constructor-policy.rs");
    for (from, to) in [
        ("total_limit: 5_000_000,", "total_limit: REPORT_PAYMENT,"),
        ("total_limit: 5_000_000,", "total_limit: 5_000_000 + 1,"),
        ("total_limit: 5_000_000,", "total_limit: true,"),
        (
            "total_limit: 5_000_000,",
            "total_limit: 5_000_000, total_limit: 1,",
        ),
        ("total_limit: 5_000_000,", ""),
        ("total_limit: u64,", "total_limit: Vec<Vec<u64>>,"),
        ("total_limit: u64,", "total_limit: u64,,"),
        ("fn new()", "pub fn new()"),
        ("fn new()", "fn new(ctx: &Context)"),
        ("enabled: true,", "enabled: true, unknown: false,"),
        (
            "recipients: &[\"11111111111111111111111111111111\"],",
            "recipients: &[\"a\",,\"b\"],",
        ),
        (
            "async fn _execute(ctx: &Context, params: &PolicyParams)",
            "async fn _execute(ctx: &Context)",
        ),
    ] {
        assert!(compile(&good.replace(from, to)).is_err(), "accepted {to}");
    }
}
#[test]
fn primitive_budget_still_precedes_early_return_and_checks_overflow() {
    let policy=compile(&source("return Ok(()); allowit::set_cap(ctx.spent_units,ctx.amount_units,&ctx.token,1_000_000,\"USDC\",6)?;")).unwrap();
    let mut ctx = context();
    ctx.amount_units = 1_000_001;
    for profile in [Profile::Oracle, Profile::Contract] {
        assert_eq!(evaluate(&policy, profile, &ctx).outcome, "fail");
    }
    assert!(allowit_sdk::set_cap(u64::MAX, 1, "USDC", u64::MAX, "USDC", 6).is_err());
}
#[allow(dead_code, unused_variables)]
mod empty_template_rust_build {
    use allowit_sdk as allowit;
    include!("fixtures/empty-policy.rs");
    #[test]
    fn template_accepts_actual_wrapper() {
        let config = new();
        let ctx = super::context();
        let _future = _execute(&ctx, &config);
    }
}
#[allow(dead_code, unused_variables)]
mod complete_template_rust_build {
    use allowit_sdk as allowit;
    include!("fixtures/constructor-policy.rs");
    #[test]
    fn template_accepts_actual_wrapper() {
        let config = new();
        let ctx = super::context();
        let _future = _execute(&ctx, &config);
    }
}

fn preference_source(deny: &str, approve: &str) -> String {
    source(&format!(
        "jev::check_preference(jev::preference_evidence(ctx, \"Research?\"), \"Research?\", {deny}, {approve}).await?; Ok(())"
    ))
}
#[test]
fn explicit_preference_evidence_preserves_thresholds_and_owner_continuation() {
    let p = compile(&preference_source("0.40", "0.85")).unwrap();
    let mut ctx = context();
    ctx.amount_units = 1;
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).code,
        "SEMANTIC_EVIDENCE_REQUIRED"
    );
    ctx.confidence.insert(
        allowit_sdk::semantic_evidence_key("Wrong question?"),
        allowit_sdk::ConfidenceInterval {
            lower_bps: 10000,
            upper_bps: 10000,
        },
    );
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).code,
        "SEMANTIC_EVIDENCE_REQUIRED"
    );
    let key = allowit_sdk::semantic_evidence_key("Research?");
    for (score, expected) in [(8500, "pass"), (4000, "fail"), (6000, "awaiting_input")] {
        ctx.confidence.insert(
            key.clone(),
            allowit_sdk::ConfidenceInterval {
                lower_bps: score,
                upper_bps: score,
            },
        );
        assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, expected);
    }
    ctx.confidence.clear();
    let p = compile(&preference_source("None", "None")).unwrap();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).outcome,
        "awaiting_input"
    );
    assert_eq!(
        evaluate(&p, Profile::Contract, &ctx).code,
        "USER_INPUT_REQUIRED"
    );
}
#[test]
fn preference_guard_rejects_forged_or_mismatched_evidence() {
    let good = preference_source("0.40", "0.85");
    for (from, to) in [
        ("jev::preference_evidence(ctx, \"Research?\")", "ctx"),
        ("jev::preference_evidence(ctx, \"Research?\")", "None"),
        ("jev::preference_evidence(ctx, \"Research?\")", "8500"),
        (
            "jev::preference_evidence(ctx, \"Research?\")",
            "jev::preference_evidence(ctx, \"Other?\")",
        ),
        (
            "jev::preference_evidence(ctx, \"Research?\")",
            "jev::semantic(ctx, \"Research?\")?",
        ),
    ] {
        assert!(compile(&good.replace(from, to)).is_err(), "accepted {to}");
    }
}
#[test]
fn constructor_preference_threshold_edits_preserve_reader_and_config() {
    let original = preference_source("0.40", "0.85");
    let p = compile(&original).unwrap();
    let step = p
        .workflow
        .iter()
        .find(|s| s.name == "check_preference")
        .unwrap();
    let result = allowit_sdk::process_value(
        serde_json::json!({"operation":"edit_preference","source":original,"settings":{"step_id":step.id,"auto_deny":false,"deny_percent":"40","auto_approve":false,"approve_percent":"85"}}),
    );
    assert_eq!(result["ok"], true, "{result}");
    let changed = result["source"].as_str().unwrap();
    assert_eq!(changed, preference_source("None", "None"));
    let p = compile(changed).unwrap();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &context()).outcome,
        "awaiting_input"
    );
}

#[test]
fn primitive_preference_rust_guard_agrees_with_runtime_outcomes() {
    fn ready<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let waker = std::task::Waker::noop();
        match future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(waker))
        {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("The numeric facade must not perform I/O"),
        }
    }
    assert_eq!(
        ready(allowit_sdk::check_preference(None, "Research?", None, None))
            .unwrap_err()
            .code,
        "USER_INPUT_REQUIRED"
    );
    assert_eq!(
        ready(allowit_sdk::check_preference(None, "Research?", 0.4, 0.85))
            .unwrap_err()
            .code,
        "SEMANTIC_EVIDENCE_REQUIRED"
    );
    let evidence = Some(allowit_sdk::ConfidenceInterval {
        lower_bps: 8500,
        upper_bps: 8500,
    });
    assert!(
        ready(allowit_sdk::check_preference(
            evidence,
            "Research?",
            0.4,
            0.85
        ))
        .is_ok()
    );
}

#[test]
fn native_storage_reads_current_owner_state_and_fails_closed_elsewhere() {
    let source = include_str!("fixtures/native-storage-policy.rs");
    let p = compile(source).unwrap();
    assert_eq!(
        p.execution_requirements.features,
        vec![allowit_sdk::ExecutionFeature::NativePolicyStorage]
    );
    let initial = allowit_sdk::native_storage_initializers(source).unwrap();
    assert_eq!(initial["native_daily_limit"], 5_000_000);
    assert_eq!(initial["native_action_limit"], 1_000_000);
    let mut ctx = context();
    ctx.amount_units = 2_000_000;
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).code,
        "NATIVE_STORAGE_REQUIRED"
    );
    ctx.runtime_context =
        serde_json::json!({"native_daily_limit":50_000_000,"native_action_limit":50_000_000});
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).code,
        "NATIVE_STORAGE_REQUIRED"
    );
    ctx.native_policy_storage = Some(allowit_sdk::NativePolicyStorage {
        daily_limit_units: 5_000_000,
        action_limit_units: 1_000_000,
    });
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "fail");
    ctx.native_policy_storage
        .as_mut()
        .unwrap()
        .action_limit_units = 2_000_000;
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "pass");
    ctx.spent_units = 3_000_001;
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "fail");
    ctx.native_policy_storage
        .as_mut()
        .unwrap()
        .daily_limit_units = 6_000_000;
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "pass");
    assert_eq!(
        evaluate(&p, Profile::Contract, &ctx).code,
        "NATIVE_STORAGE_UNSUPPORTED"
    );
    let changed = source
        .replace("daily_limit: 5_000_000", "daily_limit: 4_000_000")
        .replace(
            "\"native_daily_limit\", 5_000_000",
            "\"native_daily_limit\", 4_000_000",
        );
    let q = compile(&changed).unwrap();
    assert_ne!(p.source_hash, q.source_hash);
    assert_eq!(
        allowit_sdk::native_storage_initializers(&changed).unwrap()["native_daily_limit"],
        4_000_000
    );
}
#[test]
fn native_storage_schema_and_origins_are_unambiguous() {
    let good = include_str!("fixtures/native-storage-policy.rs");
    for (from, to) in [
        (
            "\"native_daily_limit\", 5_000_000",
            "\"native_action_limit\", 5_000_000",
        ),
        (
            "\"native_daily_limit\", 5_000_000",
            "\"unknown_limit\", 5_000_000",
        ),
        (
            "\"native_daily_limit\", 5_000_000",
            "\"native_daily_limit\", 0",
        ),
        (
            "\"native_daily_limit\", 5_000_000",
            "\"native_daily_limit\", 50_000_001",
        ),
        (
            "allowit::stored_limit(ctx, params.action_limit)",
            "allowit::stored_limit(ctx, allowit::owner_limit(\"native_action_limit\", 1000000))",
        ),
        (
            "allowit::stored_limit(ctx, params.action_limit)?",
            "ctx.native_action_limit",
        ),
        ("fn new() -> PolicyParams", "fn new() - > PolicyParams"),
    ] {
        assert!(compile(&good.replace(from, to)).is_err(), "accepted {to}");
    }
    let early = good.replace(
        "    if ctx.amount_units >",
        "    return Ok(());\n    if ctx.amount_units >",
    );
    let p = compile(&early).unwrap();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &context()).code,
        "NATIVE_STORAGE_REQUIRED"
    );
}
#[test]
fn source_checks_preserve_rust_borrow_types() {
    for body in [
        "if &ctx.amount_units > 2 {return allowit::fail(\"no\");} Ok(())",
        "if !allowit::is_one_of(ctx.recipient, &[\"a\"])? {return allowit::fail(\"no\");} Ok(())",
    ] {
        assert!(compile(&source(body)).is_err(), "accepted {body}");
    }
    let good = include_str!("fixtures/constructor-policy.rs");
    assert!(compile(&good.replace("if !params.enabled", "if &params.enabled")).is_err());
    assert!(
        compile(&good.replace("fn new() -> PolicyParams", "fn new() - > PolicyParams")).is_err()
    );
}
#[allow(dead_code, unused_variables)]
mod native_storage_rust_build {
    use allowit_sdk as allowit;
    include!("fixtures/native-storage-policy.rs");
    #[test]
    fn template_accepts_actual_wrapper() {
        let config = new();
        let ctx = super::context();
        let _future = _execute(&ctx, &config);
    }
}

#[test]
fn optional_storage_preserves_legacy_context_serialization() {
    let ctx = context();
    let wire = serde_json::to_value(&ctx).unwrap();
    assert!(wire.get("native_policy_storage").is_none());
    let decoded: Context = serde_json::from_value(wire).unwrap();
    assert!(decoded.native_policy_storage.is_none());
}
#[test]
fn storage_declarations_preserve_rust_token_validity() {
    let source = include_str!("fixtures/native-storage-policy.rs");
    assert!(compile(&source.replace("allowit::owner_limit", "allowit : : owner_limit")).is_err());
    let source = include_str!("fixtures/constructor-policy.rs");
    assert!(
        compile(
            &source
                .replace("enabled: bool,", "r#enabled: bool, enabled: bool,")
                .replace("enabled: true,", "r#enabled: true, enabled: true,")
        )
        .is_err()
    );
}

#[test]
fn new_source_requires_namespaces_and_borrowed_string_reads() {
    for body in [
        "if !is_one_of(\"a\", &[\"a\"])? {return allowit::fail(\"no\");} Ok(())",
        "if !allowit::is_one_of((ctx.recipient), &[\"a\"])? {return allowit::fail(\"no\");} Ok(())",
        "if !allowit::is_one_of((ctx).recipient, &[\"a\"])? {return allowit::fail(\"no\");} Ok(())",
        "let recipient=ctx.recipient; if !allowit::is_one_of(recipient, &[\"a\"])? {return allowit::fail(\"no\");} Ok(())",
        "let alias=(ctx); let recipient=alias.recipient; Ok(())",
        "return fail(\"no\");",
        "let limit=usdc(\"2\")?; Ok(())",
    ] {
        assert!(compile(&source(body)).is_err(), "accepted {body}");
    }
    assert!(compile(&source("let recipient=&ctx.recipient; if !allowit::is_one_of(recipient, &[\"a\"])? {return allowit::fail(\"no\");} Ok(())")).is_ok());
}

#[test]
fn purchase_amount_helper_requires_authenticated_amount() {
    let good = source(
        "if !allowit::amount_at_most(ctx.amount_units, \"3\")? { return allowit::fail(\"Too large\"); } Ok(())",
    );
    let policy = compile(&good).unwrap();
    let mut ctx = context();
    ctx.amount_units = 3_000_000;
    assert_eq!(evaluate(&policy, Profile::Oracle, &ctx).outcome, "pass");
    ctx.amount_units += 1;
    assert_eq!(evaluate(&policy, Profile::Oracle, &ctx).outcome, "fail");
    for replacement in ["0", "ctx.spent_units", "params.amount"] {
        let forged = good
            .replace("ctx.amount_units", replacement)
            .replace(
                "struct PolicyParams {}",
                "struct PolicyParams { amount: u64 }",
            )
            .replace("PolicyParams{}", "PolicyParams{amount: 0}");
        assert!(compile(&forged).is_err(), "accepted {replacement}");
    }
}
#[test]
fn public_json_protocol_cannot_supply_native_storage() {
    let source = include_str!("fixtures/native-storage-policy.rs");
    let mut request = serde_json::json!({"operation":"evaluate","profile":"oracle","source":source,"context":context()});
    let response = allowit_sdk::process_value(request.clone());
    assert_eq!(response["decision"]["code"], "NATIVE_STORAGE_REQUIRED");
    for claimed in [
        serde_json::Value::Null,
        serde_json::json!({"daily_limit_units":50_000_000,"action_limit_units":50_000_000}),
    ] {
        request["context"]["native_policy_storage"] = claimed;
        let response = allowit_sdk::process_value(request.clone());
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "INVALID_CONTEXT");
        request["trace"] = serde_json::json!(true);
        let traced = allowit_sdk::process_value(request.clone());
        assert_eq!(traced["error"]["code"], "INVALID_CONTEXT");
    }
    let mut ctx = context();
    ctx.native_policy_storage = Some(allowit_sdk::NativePolicyStorage {
        daily_limit_units: 50_000_001,
        action_limit_units: 1,
    });
    assert_eq!(
        allowit_sdk::stored_limit(&ctx, allowit_sdk::owner_limit("native_action_limit", 1))
            .unwrap_err()
            .code,
        "INVALID_NATIVE_STORAGE"
    );
}
