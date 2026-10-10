use allowit_sdk::{Context, Profile, compile, evaluate, registry};

fn source(body: &str) -> String {
    format!("pub async fn evaluate(ctx: &Context) -> PolicyResult {{ {body} }}")
}
fn context() -> Context {
    serde_json::from_str(include_str!("../examples/context.json")).unwrap()
}
#[test]
fn qualified_calls_preserve_effects_requirements_and_contract_decisions() {
    let plain = compile(&source("set_cap(ctx, \"100\", \"USDC\")?; if !amount_at_most(ctx, \"10\")? { return fail(\"limit\"); } require_merchant(ctx, \"research.example\")?; Ok(())")).unwrap();
    let named = compile(&source("allowit::set_cap(ctx, \"100\", \"USDC\")?; if !allowit::amount_at_most(ctx, \"10\")? { return allowit::fail(\"limit\"); } allowit::require_merchant(ctx, \"research.example\")?; Ok(())")).unwrap();
    assert_eq!(plain.execution_requirements, named.execution_requirements);
    assert_eq!(plain.limit, named.limit);
    assert_ne!(plain.source_hash, named.source_hash);
    assert_ne!(plain.ir_hash, named.ir_hash); // Source spans remain part of the bound artifact.
    let ir = serde_json::to_string(&named.ir).unwrap();
    assert!(!ir.contains("allowit::"));
    assert!(!ir.contains("amount_at_most"));
    for amount in [1, 10_000_000, 10_000_001, 100_000_001] {
        let mut ctx = context();
        ctx.amount_units = amount;
        for profile in [Profile::Oracle, Profile::Contract] {
            assert_eq!(
                evaluate(&plain, profile, &ctx).outcome,
                evaluate(&named, profile, &ctx).outcome
            );
        }
    }
    let entry = registry()
        .into_iter()
        .find(|f| f.name == "allowit::set_cap")
        .unwrap();
    assert_eq!(entry.effect, "config");
    assert!(entry.signature.starts_with("allowit::set_cap("));
}
#[test]
fn jev_preferences_lower_to_existing_evidence_and_owner_input() {
    for namespace in ["allowit", "jev"] {
        let p = compile(&source(&format!(
            "{namespace}::check_preference(ctx, \"Research?\", None, None).await?; Ok(())"
        )))
        .unwrap();
        assert_eq!(
            evaluate(&p, Profile::Oracle, &context()).outcome,
            "awaiting_input"
        );
        assert_eq!(p.calls[0].name, "check_preference");
        let plain = compile(&source(
            "check_preference(ctx, \"Research?\", None, None).await?; Ok(())",
        ))
        .unwrap();
        assert_eq!(p.execution_requirements, plain.execution_requirements);
        let p = compile(&source(&format!("{namespace}::check_preference(ctx, \"Research?\", auto(\"deny\"), auto(\"approve\")).await?; Ok(())"))).unwrap();
        assert_eq!(
            evaluate(&p, Profile::Contract, &context()).code,
            "SEMANTIC_EVIDENCE_REQUIRED"
        );
    }
    let plain = compile(&source("let score = semantic(ctx, \"Research?\")?; Ok(())")).unwrap();
    let p = compile(&source(
        "let score = jev::semantic(ctx, \"Research?\")?; Ok(())",
    ))
    .unwrap();
    assert_eq!(p.execution_requirements, plain.execution_requirements);
}
#[test]
fn exact_registry_rejects_unknown_vendors_operations_and_type_paths() {
    for name in [
        "paysh::set_cap",
        "paysh::pay",
        "stripe::pay",
        "jev::set_cap",
        "jev::confidence",
        "allowit::pay",
        "allowit::Ok",
        "::allowit::set_cap",
        "allowit::v1::set_cap",
        "allowit::set_cap::<u64>",
        "<Context as Vendor>::set_cap",
    ] {
        assert!(
            compile(&source(&format!("{name}(ctx, \"100\", \"USDC\")?; Ok(())"))).is_err(),
            "{name}"
        );
    }
    assert!(compile(&source("let check = allowit::set_cap; Ok(())")).is_err());
    assert!(compile(&source("if true { allowit::require_merchant(ctx, \"research.example\")?; } allowit::require_recipient(ctx, \"recipient\")?; Ok(())")).is_ok());
}
#[test]
fn named_configuration_keeps_the_same_placement_and_feature_rules() {
    assert!(
        compile(&source(
            "if true { allowit::set_cap(ctx, \"100\", \"USDC\")?; } Ok(())"
        ))
        .is_err()
    );
    assert!(
        compile(&source(
            "set_cap(ctx, \"100\", \"USDC\")?; allowit::set_cap(ctx, \"100\", \"USDC\")?; Ok(())"
        ))
        .is_err()
    );
    let p = compile(&source(
        "allowit::cap_purchase_tiers(ctx, \"10\", 2, \"USDC\")?; Ok(())",
    ));
    #[cfg(feature = "oracle-ledger")]
    assert!(p.is_ok());
    #[cfg(not(feature = "oracle-ledger"))]
    assert_eq!(p.unwrap_err().code, "LEDGER_REQUIRED");
}
mod native_facade {
    use allowit_sdk as allowit;
    use allowit_sdk::prelude::*;
    pub async fn check(ctx: &Context) -> PolicyResult {
        allowit::set_cap(
            ctx.spent_units,
            ctx.amount_units,
            &ctx.token,
            100_000_000,
            "USDC",
            6,
        )?;
        jev::check_preference(
            jev::preference_evidence(ctx, "Research?"),
            "Research?",
            None,
            None,
        )
        .await?;
        allowit::check_preference(
            allowit::preference_evidence(ctx, "Research?"),
            "Research?",
            None,
            None,
        )
        .await?;
        Ok(())
    }
}
mod versioned_facade {
    use allowit_sdk as allowit;
    use allowit_sdk::v1::prelude::*;
    pub async fn check(ctx: &Context) -> PolicyResult {
        allowit::set_cap(
            ctx.spent_units,
            ctx.amount_units,
            &ctx.token,
            100_000_000,
            "USDC",
            6,
        )?;
        jev::check_preference(
            jev::preference_evidence(ctx, "Research?"),
            "Research?",
            None,
            auto("approve"),
        )
        .await?;
        allowit::check_preference(
            allowit::preference_evidence(ctx, "Research?"),
            "Research?",
            None,
            auto("approve"),
        )
        .await?;
        Ok(())
    }
}
#[test]
fn registered_names_type_check_in_both_facades() {
    let _ = native_facade::check;
    let _ = versioned_facade::check;
}

#[test]
fn every_registered_core_alias_compiles_to_its_bounded_operation() {
    for body in [
        "allowit::set_cap(ctx, \"100\", \"USDC\")?;",
        "allowit::cap_per_transaction(ctx, \"10\", \"USDC\")?;",
        "let amount = allowit::usdc(\"10\")?;",
        "let score = allowit::percent(\"85\")?;",
        "let allowed = allowit::amount_at_most(ctx, \"10\")?;",
        "let allowed = allowit::within_percentage_points(400, 500, \"1\")?;",
        "allowit::allow_actions(ctx, &[\"research\"])?;",
        "allowit::require_merchant(ctx, \"research.example\")?;",
        "allowit::require_recipient(ctx, \"recipient\")?;",
        "let evidence = allowit::confidence(ctx, \"source\")?;",
        "let fit = allowit::semantic(ctx, \"Research?\")?;",
        "allowit::check_preference(ctx, \"Research?\", auto(\"deny\"), auto(\"approve\")).await?;",
        "let risk = allowit::context_u64(ctx, \"risk\")?;",
        "allowit::require_user_input(ctx, \"Proceed?\").await?;",
        "return allowit::fail(\"Denied\");",
    ] {
        assert!(
            compile(&source(&format!("{body} Ok(())"))).is_ok(),
            "{body}"
        );
    }
    #[cfg(feature = "oracle-ledger")]
    assert!(
        compile(&source(
            "allowit::cap_purchase_tiers(ctx, \"10\", 2, \"USDC\")?; Ok(())"
        ))
        .is_ok()
    );
}

#[test]
fn runtime_artifacts_require_canonical_operation_names() {
    let mut policy = compile(&source(
        "allowit::require_merchant(ctx, \"research.example\")?; Ok(())",
    ))
    .unwrap();
    let allowit_sdk::Statement::Expression {
        value: allowit_sdk::Expr::Try { value },
        ..
    } = &mut policy.ir.statements[0]
    else {
        panic!("Expected a policy check");
    };
    let allowit_sdk::Expr::Call { name, .. } = &mut **value else {
        panic!("Expected canonical call");
    };
    assert_eq!(name, "require_merchant");
    *name = "paysh::require_merchant".into();
    assert!(allowit_sdk::validate_program(&policy.ir).is_err());
    assert!(allowit_sdk::canonical_ir_hash(&policy.ir).is_err());
}

#[test]
fn registry_minor_version_advertises_aliases_without_changing_ir_schema() {
    let source = source("set_cap(ctx, \"100\", \"USDC\")?; Ok(())");
    let mut policy = compile(&source).unwrap();
    assert_eq!(allowit_sdk::REGISTRY_VERSION, "1.4.0");
    assert_eq!(policy.registry_version, "1.4.0");
    assert_eq!(policy.ir.version, "1.0.0");
    let hash = policy.ir_hash.clone();
    policy.registry_version = "1.0.0".into();
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &context()).outcome,
        "pass"
    );
    assert_eq!(allowit_sdk::canonical_ir_hash(&policy.ir).unwrap(), hash);
    policy.registry_version = "1.5.0".into();
    assert_eq!(
        evaluate(&policy, Profile::Oracle, &context()).code,
        "INVALID_ARTIFACT"
    );
}

#[test]
fn qualified_preference_signature_matches_the_rust_facade() {
    for namespace in ["allowit", "jev"] {
        assert!(compile(&source(&format!(r#"{namespace}::check_preference(ctx, "Research?", true, "85", true, "40").await?; Ok(())"#))).is_err());
    }
}

#[test]
fn namespace_spacing_does_not_relax_exact_path_resolution() {
    for call in ["allowit :: set_cap", "allowit::/* comment */set_cap"] {
        assert!(compile(&source(&format!("{call}(ctx, \"5\", \"USDC\")?; Ok(())"))).is_ok());
    }
    for call in [
        "r#allowit::set_cap",
        "allowit::r#set_cap",
        "jev::jev::semantic",
    ] {
        assert!(compile(&source(&format!("{call}(ctx, \"5\", \"USDC\")?; Ok(())"))).is_err());
    }
}
