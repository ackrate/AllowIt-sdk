#[path = "../../test_support.rs"]
mod support;

use allowit_contract_core::{Error, prepare_execution, record_execution, validate_artifact};
use allowit_sdk::{Context, Profile, evaluate};
use support::{INPUT, SIMPLE, fixture, request};

#[test]
fn canonical_context_rejects_duplicate_keys_and_ambiguous_encoding() {
    let mut state = fixture(support::SEMANTIC);
    state.mandate.evidence_authority = Some(allowit_contract_core::EvidenceAuthority {
        key: [6; 32],
        key_id: "evidence-v1".into(),
        version: "1".into(),
    });
    for json in [
        r#"{"risk":99,"risk":2}"#,
        r#"{ "risk":2}"#,
        r#"{"z":1,"risk":2}"#,
    ] {
        let mut req = request(&state, 1_000_000);
        req.runtime_context = json.into();
        support::semantic_evidence(&state, &mut req, 9500);
        assert_eq!(
            prepare_execution(&state, &req, 1000),
            Err(Error::InvalidEvidence)
        );
    }
}

#[test]
fn chain_profile_admits_maximum_semantic_policy_and_rejects_deeper_ir() {
    let state = support::maximum_semantic_fixture();
    allowit_contract_core::validate_chain_artifact(&state.mandate, &state.artifact).unwrap();
    let deep = fixture(
        "pub async fn evaluate(ctx: &Context) -> PolicyResult { set_cap(ctx, \"100\", \"USDC\")?; if ((((((ctx.amount_units + 0) + 0) + 0) + 0) + 0) > 0) { cap_per_transaction(ctx, \"10\", \"USDC\")?; } Ok(()) }",
    );
    assert_eq!(
        allowit_contract_core::validate_chain_artifact(&deep.mandate, &deep.artifact),
        Err(Error::InvalidArtifact)
    );
}

#[test]
fn purchase_ledger_policies_cannot_activate_on_contracts_without_ledger_state() {
    let state = fixture(
        "pub async fn evaluate(ctx: &Context) -> PolicyResult { set_cap(ctx, \"100\", \"USDC\")?; cap_purchase_tiers(ctx, \"1\", 2, \"USDC\")?; Ok(()) }",
    );
    assert_eq!(
        allowit_contract_core::validate_chain_artifact(&state.mandate, &state.artifact),
        Err(Error::InvalidArtifact)
    );
    assert_eq!(
        prepare_execution(&state, &request(&state, 750_000), 1000),
        Err(Error::InvalidArtifact)
    );
}

#[test]
fn contract_and_oracle_share_exact_pass_and_failure_core() {
    let state = fixture(SIMPLE);
    let compiled = allowit_sdk::compile(SIMPLE).unwrap();
    for amount in [1, 10_000_000, 10_000_001, 100_000_001] {
        let req = request(&state, amount);
        let ctx = Context {
            amount_units: amount,
            allocation_units: 100_000_000,
            token: "USDC".into(),
            action: "research".into(),
            network: "devnet".into(),
            ..Context::default()
        };
        let oracle = evaluate(&compiled, Profile::Oracle, &ctx);
        let contract = evaluate(&compiled, Profile::Contract, &ctx);
        assert_eq!(oracle, contract);
        assert_eq!(
            prepare_execution(&state, &req, 1000).is_ok(),
            oracle.outcome == "pass"
        );
    }
}

#[test]
fn binds_every_action_field_and_enforces_nonce_budget_expiry_revoke() {
    let mut state = fixture(SIMPLE);
    let valid = request(&state, 10_000_000);
    for field in 0..9 {
        let mut bad = valid.clone();
        match field {
            0 => bad.revision += 1,
            1 => bad.asset[0] ^= 1,
            2 => bad.recipient[0] ^= 1,
            3 => bad.network = "mainnet".into(),
            4 => bad.action = "transfer".into(),
            5 => bad.merchant = "different".into(),
            6 => bad.source_hash = "0".repeat(64),
            7 => bad.ir_hash = "0".repeat(64),
            _ => bad.nonce += 1,
        }
        assert_eq!(
            prepare_execution(&state, &bad, 1000),
            Err(if field == 8 {
                Error::Replay
            } else {
                Error::BindingMismatch
            })
        );
    }
    assert_eq!(prepare_execution(&state, &valid, 2000), Err(Error::Expired));
    record_execution(&mut state, &valid).unwrap();
    assert_eq!(prepare_execution(&state, &valid, 1000), Err(Error::Replay));
    state.spent_units = 99_000_000;
    assert_eq!(
        prepare_execution(&state, &request(&state, 2_000_000), 1000),
        Err(Error::BudgetExceeded)
    );
    state.revoked = true;
    assert_eq!(
        prepare_execution(&state, &request(&state, 1), 1000),
        Err(Error::Inactive)
    );
}

#[test]
fn input_fails_without_consuming_nonce_or_budget_and_artifact_tampering_fails() {
    let state = fixture(INPUT);
    let unchanged = state.clone();
    assert_eq!(
        prepare_execution(&state, &request(&state, 1_000_000), 1000),
        Err(Error::UserInputRequired)
    );
    assert_eq!(state, unchanged);
    let compiled = allowit_sdk::compile(INPUT).unwrap();
    let mut context = Context {
        amount_units: 1_000_000,
        allocation_units: 100_000_000,
        token: "USDC".into(),
        action: "research".into(),
        network: "devnet".into(),
        ..Context::default()
    };
    let suspended = evaluate(&compiled, Profile::Oracle, &context);
    context.answers.insert(suspended.input_key.unwrap(), true);
    assert_eq!(
        evaluate(&compiled, Profile::Oracle, &context).outcome,
        "pass"
    );
    assert_eq!(
        evaluate(&compiled, Profile::Contract, &context).code,
        "USER_INPUT_REQUIRED"
    );
    let mut altered = state.artifact.clone();
    altered[20] ^= 1;
    assert_eq!(
        validate_artifact(&state.mandate, &altered).unwrap_err(),
        Error::ArtifactMismatch
    );
    let mut forged = state.clone();
    let mut artifact: allowit_contract_core::Artifact =
        serde_json::from_slice(&forged.artifact).unwrap();
    artifact.ir.version = "unrecognized".into();
    forged.artifact = serde_json::to_vec(&artifact).unwrap();
    forged.mandate.artifact_hash = allowit_sdk::digest(&forged.artifact);
    assert_eq!(
        validate_artifact(&forged.mandate, &forged.artifact).unwrap_err(),
        Error::InvalidArtifact
    );
}

#[test]
fn confidence_snapshot_is_bounded_fresh_and_bound_to_exact_request() {
    use allowit_contract_core::EvidenceAuthority;
    let mut state = fixture(support::CONFIDENCE);
    state.mandate.evidence_authority = Some(EvidenceAuthority {
        key: [6; 32],
        key_id: "merchant-oracle-v1".into(),
        version: "1".into(),
    });
    let mut req = request(&state, 1_000_000);
    assert_eq!(
        prepare_execution(&state, &req, 1000),
        Err(Error::EvidenceRequired)
    );
    support::evidence(&state, &mut req, 9200, 9800);
    assert!(prepare_execution(&state, &req, 1000).is_ok());
    for invalid in 0..5 {
        let mut bad = req.clone();
        match invalid {
            0 => bad.amount_units += 1,
            1 => bad.evidence.as_mut().unwrap().expires_at = 999,
            2 => bad.evidence.as_mut().unwrap().intervals[0].upper_bps = 10_001,
            3 => bad.evidence.as_mut().unwrap().intervals[0].lower_bps = 9900,
            _ => bad.evidence.as_mut().unwrap().key_id = "other".into(),
        }
        assert_eq!(
            prepare_execution(&state, &bad, 1000),
            Err(Error::InvalidEvidence)
        );
    }
    support::evidence(&state, &mut req, 8000, 9500);
    assert_eq!(
        prepare_execution(&state, &req, 1000),
        Err(Error::UserInputRequired)
    );
}

#[test]
fn stellar_seven_decimal_amounts_are_normalized_exactly() {
    let mut state = fixture(SIMPLE);
    state.mandate.asset_decimals = 7;
    state.mandate.allocation_units *= 10;
    state.mandate.network = "stellar-testnet".into();
    assert!(prepare_execution(&state, &request(&state, 100_000_000), 1000).is_ok());
    assert_eq!(
        prepare_execution(&state, &request(&state, 100_000_001), 1000),
        Err(Error::InvalidMandate)
    );
    assert_eq!(
        prepare_execution(&state, &request(&state, 100_000_010), 1000),
        Err(Error::PolicyDenied)
    );
}

#[test]
fn semantic_evidence_binds_original_intent_and_complete_runtime_context() {
    let mut state = fixture(support::SEMANTIC);
    state.mandate.evidence_authority = Some(allowit_contract_core::EvidenceAuthority {
        key: [6; 32],
        key_id: "semantics-v1".into(),
        version: "1".into(),
    });
    let mut req = request(&state, 1_000_000);
    req.runtime_context = "{\"risk\":3}".into();
    assert_eq!(
        prepare_execution(&state, &req, 1000),
        Err(Error::EvidenceRequired)
    );
    support::semantic_evidence(&state, &mut req, 9200);
    assert!(prepare_execution(&state, &req, 1000).is_ok());
    let mut altered_context = req.clone();
    altered_context.runtime_context = "{\"risk\":0}".into();
    assert_eq!(
        prepare_execution(&state, &altered_context, 1000),
        Err(Error::InvalidEvidence)
    );
    let mut altered_policy = state.clone();
    let mut artifact: allowit_contract_core::Artifact =
        serde_json::from_slice(&state.artifact).unwrap();
    artifact.original_intent = "Spend on anything.".into();
    altered_policy.artifact = serde_json::to_vec(&artifact).unwrap();
    altered_policy.mandate.artifact_hash = allowit_sdk::digest(&altered_policy.artifact);
    assert_eq!(
        prepare_execution(&altered_policy, &req, 1000),
        Err(Error::InvalidEvidence)
    );
    let mut ambiguous = req.clone();
    support::semantic_evidence(&state, &mut ambiguous, 8000);
    assert_eq!(
        prepare_execution(&state, &ambiguous, 1000),
        Err(Error::UserInputRequired)
    );
    let mut dangerous = req.clone();
    dangerous.runtime_context = "{\"risk\":15}".into();
    support::semantic_evidence(&state, &mut dangerous, 9200);
    assert_eq!(
        prepare_execution(&state, &dangerous, 1000),
        Err(Error::PolicyDenied)
    );
}

#[test]
fn qualified_functions_keep_chain_artifact_and_request_bindings() {
    let named = SIMPLE
        .replace("pub async fn evaluate", "async fn _execute")
        .replace("set_cap(", "allowit::set_cap(")
        .replace("cap_per_transaction(", "allowit::cap_per_transaction(")
        .replace("allow_actions(", "allowit::allow_actions(");
    assert!(named.contains("async fn _execute") && named.contains("allowit::set_cap"));
    let state = fixture(&named);
    allowit_contract_core::validate_chain_artifact(&state.mandate, &state.artifact).unwrap();
    for (amount, pass) in [(10_000_000, true), (10_000_001, false)] {
        assert_eq!(
            prepare_execution(&state, &request(&state, amount), 1000).is_ok(),
            pass
        );
    }
    let original = fixture(SIMPLE);
    assert_ne!(state.mandate.source_hash, original.mandate.source_hash);
    assert_eq!(
        prepare_execution(&state, &request(&original, 1_000_000), 1000),
        Err(Error::BindingMismatch)
    );
}

#[test]
fn source_registry_minor_version_retains_existing_artifact_acceptance() {
    let state = fixture(SIMPLE);
    let mut artifact: allowit_contract_core::Artifact =
        serde_json::from_slice(&state.artifact).unwrap();
    assert_eq!(artifact.registry_version, "1.2.0");
    assert_eq!(artifact.ir.version, "1.0.0");
    for version in ["1.0.0", "1.1.0"] {
        let mut legacy = state.clone();
        artifact.registry_version = version.into();
        legacy.mandate.registry_version = version.into();
        legacy.artifact = serde_json::to_vec(&artifact).unwrap();
        legacy.mandate.artifact_hash = allowit_sdk::digest(&legacy.artifact);
        allowit_contract_core::validate_chain_artifact(&legacy.mandate, &legacy.artifact).unwrap();
        assert!(prepare_execution(&legacy, &request(&legacy, 1_000_000), 1000).is_ok());
    }
    let mut unsupported = state;
    unsupported.mandate.registry_version = "1.3.0".into();
    assert_eq!(
        allowit_contract_core::validate_chain_artifact(&unsupported.mandate, &unsupported.artifact),
        Err(Error::InvalidMandate)
    );
}
