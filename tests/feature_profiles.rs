use allowit_sdk::{Expr, IR_VERSION, Program, SourceSpan, Statement, validate_program};
#[test]
fn purchase_tiers_require_the_ledger_feature_before_evaluation() {
    let program = Program {
        version: IR_VERSION.into(),
        statements: vec![
            Statement::Expression {
                span: SourceSpan::default(),
                semicolon: true,
                value: Expr::Try {
                    value: Box::new(Expr::Call {
                        name: "cap_purchase_tiers".into(),
                        args: vec![
                            Expr::Variable { name: "ctx".into() },
                            Expr::String { value: "1".into() },
                            Expr::Integer { value: 2 },
                            Expr::String {
                                value: "USDC".into(),
                            },
                        ],
                        span: SourceSpan::default(),
                    }),
                },
            },
            Statement::Expression {
                span: SourceSpan::default(),
                semicolon: false,
                value: Expr::Call {
                    name: "Ok".into(),
                    args: vec![Expr::Unit],
                    span: SourceSpan::default(),
                },
            },
        ],
    };
    #[cfg(feature = "oracle-ledger")]
    assert!(validate_program(&program).is_ok());
    #[cfg(not(feature = "oracle-ledger"))]
    assert_eq!(
        validate_program(&program).unwrap_err().code,
        "LEDGER_REQUIRED"
    );
    assert!(
        allowit_sdk::registry()
            .iter()
            .any(|f| f.name == "cap_purchase_tiers")
    );
}

#[test]
fn native_storage_fields_require_the_trusted_host_profile() {
    let program = Program {
        version: IR_VERSION.into(),
        statements: vec![
            Statement::Let {
                name: "limit".into(),
                annotation: None,
                value: Expr::Field {
                    object: Box::new(Expr::Variable { name: "ctx".into() }),
                    name: "native_daily_limit".into(),
                },
                span: SourceSpan::default(),
            },
            Statement::Expression {
                value: Expr::Call {
                    name: "Ok".into(),
                    args: vec![Expr::Unit],
                    span: SourceSpan::default(),
                },
                semicolon: false,
                span: SourceSpan::default(),
            },
        ],
    };
    #[cfg(not(feature = "std"))]
    assert!(validate_program(&program).is_err());
    #[cfg(feature = "std")]
    assert!(validate_program(&program).is_ok());
}

#[test]
fn host_only_context_is_heap_bounded_for_native_scalar_stack() {
    assert!(core::mem::size_of::<allowit_sdk::Context>() <= 768);
}

#[cfg(not(feature = "typed-workflow"))]
#[test]
fn scalar_build_rejects_host_workflow_ir_before_any_evaluation() {
    let program = allowit_sdk::Program {
        version: "1.1.0".into(),
        statements: vec![allowit_sdk::Statement::Expression {
            value: allowit_sdk::Expr::Call {
                name: "allowit::execution_request_validate".into(),
                args: Vec::new(),
                span: allowit_sdk::SourceSpan::default(),
            },
            semicolon: true,
            span: allowit_sdk::SourceSpan::default(),
        }],
    };
    let decision = allowit_sdk::evaluate_ir(
        &program,
        allowit_sdk::Profile::Oracle,
        &allowit_sdk::Context::default(),
    );
    assert_eq!(decision.outcome, "fail");
    assert_eq!(decision.code, "INVALID_POLICY");
    let serialized = serde_json::to_value(decision).unwrap();
    assert!(serialized.get("workflow_outputs").is_none());
    assert!(serialized.get("system_operations").is_none());
    let mut forged_scalar_version = program.clone();
    forged_scalar_version.version = IR_VERSION.into();
    assert!(validate_program(&forged_scalar_version).is_err());
    if let Statement::Expression {
        value: Expr::Call { name, .. },
        ..
    } = &mut forged_scalar_version.statements[0]
    {
        *name = "paysh::call".into();
    }
    assert!(validate_program(&forged_scalar_version).is_err());
}

#[cfg(not(feature = "typed-workflow"))]
#[test]
fn scalar_wire_reader_rejects_host_only_ir_nodes() {
    for value in [
        serde_json::json!({"kind":"borrow","value":{"kind":"unit"}}),
        serde_json::json!({"kind":"if_some","name":"request","value":{"kind":"unit"},"then_branch":[],"else_branch":[],"span":{"start":0,"end":0}}),
        serde_json::json!({"kind":"for_each","name":"request","values":{"kind":"unit"},"body":[],"span":{"start":0,"end":0}}),
    ] {
        if value["kind"] == "borrow" {
            assert!(serde_json::from_value::<Expr>(value).is_err());
        } else {
            assert!(serde_json::from_value::<Statement>(value).is_err());
        }
    }
}
