use allowit_sdk::{Context, Profile, compile, evaluate, evaluate_ir, process_value};
use serde_json::json;

fn source(body: &str) -> String {
    format!("pub async fn evaluate(ctx: &Context) -> PolicyResult {{ {body} }}")
}
fn context() -> Context {
    serde_json::from_str(include_str!("../examples/context.json")).unwrap()
}
fn decision(body: &str, ctx: &Context) -> allowit_sdk::Decision {
    evaluate(&compile(&source(body)).unwrap(), Profile::Oracle, ctx)
}

#[test]
fn spending_limits_are_exact_and_global() {
    let mut ctx = context();
    ctx.amount_units = 10_000_000;
    let body =
        "set_cap(ctx, \"100\", \"USDC\")?; cap_per_transaction(ctx, \"10\", \"USDC\")?; Ok(())";
    assert_eq!(decision(body, &ctx).outcome, "pass");
    ctx.amount_units += 1;
    assert_eq!(decision(body, &ctx).code, "PURCHASE_CAP_EXCEEDED");
    ctx.amount_units = 10_000_000;
    ctx.spent_units = 90_000_001;
    ctx.allocation_units = 200_000_000;
    assert_eq!(decision(body, &ctx).code, "POLICY_CAP_EXCEEDED");
    assert_eq!(
        decision("return Ok(()); set_cap(ctx, \"1\", \"USDC\")?;", &ctx).code,
        "POLICY_CAP_EXCEEDED"
    );
    ctx.allocation_units = 1;
    assert_eq!(decision("Ok(())", &ctx).code, "BUDGET_EXCEEDED");
    ctx.allocation_units = u64::MAX;
    ctx.spent_units = u64::MAX;
    assert_eq!(decision("Ok(())", &ctx).code, "BUDGET_EXCEEDED");
}
#[test]
fn decimals_cannot_round_up_or_overflow() {
    let mut ctx = context();
    ctx.amount_units = 1;
    assert_eq!(
        decision("set_cap(ctx, \"0.000001\", \"USDC\")?; Ok(())", &ctx).outcome,
        "pass"
    );
    for amount in [
        "0",
        "-1",
        "1e3",
        ".1",
        "1.",
        "0.0000001",
        "18446744073709551615",
    ] {
        assert!(
            compile(&source(&format!(
                "set_cap(ctx, \"{amount}\", \"USDC\")?; Ok(())"
            )))
            .is_err(),
            "{amount}"
        );
    }
}
#[test]
fn oracle_suspends_resumes_declines_and_contract_always_fails_input() {
    let p = compile(&source(
        "require_user_input(ctx, \"Approve?\").await?; Ok(())",
    ))
    .unwrap();
    let mut ctx = context();
    let d = evaluate(&p, Profile::Oracle, &ctx);
    assert_eq!(d.outcome, "awaiting_input");
    let key = d.input_key.unwrap();
    ctx.answers.insert(key.clone(), true);
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "pass");
    assert_eq!(
        evaluate(&p, Profile::Contract, &ctx).code,
        "USER_INPUT_REQUIRED"
    );
    ctx.answers.insert(key, false);
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).code, "USER_DECLINED");
    let changed = compile(&source(
        "require_user_input(ctx, \"Approve another purchase?\").await?; Ok(())",
    ))
    .unwrap();
    assert_eq!(
        evaluate(&changed, Profile::Oracle, &ctx).outcome,
        "awaiting_input"
    );
}
#[test]
fn repeated_prompts_have_distinct_call_site_keys() {
    let p=compile(&source("require_user_input(ctx, \"Approve?\").await?; require_user_input(ctx, \"Approve?\").await?; Ok(())")).unwrap();
    let mut ctx = context();
    let one = evaluate(&p, Profile::Oracle, &ctx).input_key.unwrap();
    ctx.answers.insert(one.clone(), true);
    let two = evaluate(&p, Profile::Oracle, &ctx).input_key.unwrap();
    assert_ne!(one, two);
}
#[test]
fn confidence_threshold_and_missing_or_malformed_evidence() {
    let p = compile(include_str!("../examples/approval.rs")).unwrap();
    let mut ctx = context();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).outcome,
        "awaiting_input"
    );
    ctx.confidence.get_mut("safety").unwrap().lower_bps = 8000;
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).outcome, "pass");
    ctx.confidence.get_mut("safety").unwrap().upper_bps = 10001;
    assert_eq!(evaluate(&p, Profile::Oracle, &ctx).code, "INVALID_EVIDENCE");
    ctx.confidence.clear();
    assert_eq!(
        evaluate(&p, Profile::Oracle, &ctx).code,
        "EVIDENCE_REQUIRED"
    );
}
#[test]
fn custom_logic_is_checked_and_arithmetic_fails_closed() {
    let ctx = context();
    assert_eq!(decision("let total: u64 = ctx.amount_units + 1; if total > 5 && ctx.action == \"research\" { return fail(\"No\"); } Ok(())",&ctx).code,"POLICY_REJECTED");
    for calculation in [
        "18446744073709551615 + 1",
        "0 - 1",
        "1 / 0",
        "1 % 0",
        "18446744073709551615 * 2",
    ] {
        assert_eq!(
            decision(&format!("let n = {calculation}; Ok(())"), &ctx).code,
            "ARITHMETIC_ERROR"
        );
    }
    assert_eq!(
        decision(
            "if false && 1 / 0 > 2 { return fail(\"No\"); } Ok(())",
            &ctx
        )
        .outcome,
        "pass"
    );
}
#[test]
fn unsupported_or_unchecked_code_is_rejected_including_unreachable_branches() {
    for body in [
        "loop {}",
        "while true {} Ok(())",
        "let mut x = 1; Ok(())",
        "unsafe { Ok(()) }",
        "std::fs::read(\"secret\"); Ok(())",
        "if false { unknown(ctx)?; } Ok(())",
        "set_cap(ctx, \"1\", \"USDC\"); Ok(())",
        "require_user_input(ctx, \"Approve?\")?; Ok(())",
        "require_user_input(ctx, \"Approve?\").await; Ok(())",
        "set_cap(ctx, \"1\", \"USDC\")?; set_cap(ctx, \"2\", \"USDC\")?; Ok(())",
        "if true { set_cap(ctx, \"1\", \"USDC\")?; } Ok(())",
        "let amount = \"1\"; set_cap(ctx, amount, \"USDC\")?; Ok(())",
        "let ctx = 1; Ok(())",
        "if true { Ok(()) } Ok(())",
        "allow_actions(ctx, [\"research\"])?; Ok(())",
        "let merchant = ctx.merchant; Ok(())",
        "return true;",
        "let n = 1;",
        "panic!(\"boom\"); Ok(())",
    ] {
        assert!(compile(&source(body)).is_err(), "accepted {body}");
    }
    assert!(
        compile("use std::fs::*; pub async fn evaluate(ctx: &Context) -> PolicyResult { Ok(()) }")
            .is_err()
    );
}
#[test]
fn action_merchant_recipient_and_network_are_enforced() {
    let mut ctx = context();
    assert_eq!(
        decision("allow_actions(ctx, &[\"different\"])?; Ok(())", &ctx).code,
        "ACTION_NOT_ALLOWED"
    );
    assert_eq!(
        decision("require_merchant(ctx, \"other\")?; Ok(())", &ctx).code,
        "MERCHANT_NOT_ALLOWED"
    );
    assert_eq!(
        decision("require_recipient(ctx, \"other\")?; Ok(())", &ctx).code,
        "RECIPIENT_NOT_ALLOWED"
    );
    ctx.network = "wrong".into();
    assert_eq!(decision("Ok(())", &ctx).code, "INVALID_NETWORK");
    for network in [
        "solana:mainnet",
        "solana:devnet",
        "solana:testnet",
        "stellar:mainnet",
        "stellar:testnet",
    ] {
        ctx.network = network.into();
        assert_eq!(decision(&format!("if ctx.network != \"{network}\" {{ return fail(\"Network label changed\"); }} Ok(())"),&ctx).outcome,"pass");
    }
}
#[test]
fn workflow_preserves_custom_source_and_unicode_offsets() {
    let text = source(
        "// keep 👋\n set_cap(ctx, \"100\", \"USDC\")?;\n let label = \"café 👋\";\n // custom comment\n if ctx.amount_units > 10 { require_user_input(ctx, label).await?; }\n Ok(())",
    );
    let p = compile(&text).unwrap();
    assert_eq!(p.workflow.len(), 3);
    assert_eq!(p.workflow[0].kind, "function");
    assert_eq!(p.workflow[1].kind, "custom");
    assert!(p.workflow[1].source.contains("// custom comment"));
    assert_eq!(p.workflow[2].kind, "pass");
    let units = text.encode_utf16().collect::<Vec<_>>();
    for b in &p.workflow {
        assert_eq!(
            String::from_utf16(&units[b.start..b.end]).unwrap(),
            b.source
        );
    }
    for call in &p.calls {
        assert_eq!(
            String::from_utf16(&units[call.start..call.end]).unwrap(),
            call.name
        );
    }
    assert!(p.calls.iter().any(|c| c.name == "require_user_input"));
    assert_eq!(compile(&text).unwrap(), p);
    let windows = text.replace('\n', "\r\n");
    let windows_policy = compile(&windows).unwrap();
    let units = windows.encode_utf16().collect::<Vec<_>>();
    for call in &windows_policy.calls {
        assert_eq!(
            String::from_utf16(&units[call.start..call.end]).unwrap(),
            call.name
        );
    }
    assert!(compile(&format!("\u{feff}{text}")).is_err());
}
#[test]
fn malformed_ir_and_artifact_tampering_fail_closed() {
    let mut p = compile(&source("Ok(())")).unwrap();
    p.ir.version = "unknown".into();
    assert_eq!(
        evaluate_ir(&p.ir, Profile::Contract, &context()).code,
        "INVALID_POLICY"
    );
    let mut p = compile(&source("Ok(())")).unwrap();
    p.source.push(' ');
    assert_eq!(
        evaluate(&p, Profile::Oracle, &context()).code,
        "INVALID_ARTIFACT"
    );
    let mut value = serde_json::to_value(compile(&source("Ok(())")).unwrap().ir).unwrap();
    value["unexpected"] = json!(true);
    assert!(serde_json::from_value::<allowit_sdk::Program>(value).is_err());
}
#[test]
fn json_wire_protocol_is_exact() {
    let compiled = process_value(
        json!({"operation":"compile","source":source("set_cap(ctx, \"20\", \"USDC\")?; Ok(())")}),
    );
    assert_eq!(compiled["ok"], true);
    assert_eq!(compiled["policy"]["language"], "allowit-rust-v1");
    assert_eq!(compiled["policy"]["limit"], "20");
    let evaluated = process_value(
        json!({"operation":"evaluate","source":source("Ok(())"),"profile":"oracle","context":context()}),
    );
    assert_eq!(evaluated["decision"]["outcome"], "pass");
    assert_eq!(
        process_value(
            json!({"operation":"evaluate","source":source("Ok(())"),"profile":"bad","context":context()})
        )["error"]["code"],
        "INVALID_PROFILE"
    );
    assert_eq!(
        process_value(json!({"operation":"registry"}))["functions"]
            .as_array()
            .unwrap()
            .len(),
        48
    );
}
#[test]
fn deep_and_large_source_is_bounded() {
    assert!(compile(&" ".repeat(32769)).is_err());
    assert!(
        compile(&source(&format!(
            "let x = {}1{}; Ok(())",
            "(".repeat(200),
            ")".repeat(200)
        )))
        .is_err()
    );
}
