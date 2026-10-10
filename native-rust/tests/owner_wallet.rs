use allowit_native::{
    crypto::{Key, LocalSigner},
    error::{Error, Result},
    owner_wallet::{self, Intent, Prepared, Settlement},
    rpc::Rpc,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{collections::VecDeque, sync::Mutex};
struct Mock(Mutex<VecDeque<(String, Value, Result<Value>)>>);
impl Rpc for Mock {
    fn call(&self, m: &str, p: Value) -> Result<Value> {
        let (method, params, result) = self.0.lock().unwrap().pop_front().expect("unexpected RPC");
        assert_eq!(m, method);
        assert_eq!(p, params);
        result
    }
}
impl Mock {
    fn new(v: Vec<(&str, Value, Result<Value>)>) -> Self {
        Self(Mutex::new(
            v.into_iter().map(|(m, p, r)| (m.into(), p, r)).collect(),
        ))
    }
    fn done(&self) {
        assert!(self.0.lock().unwrap().is_empty());
    }
}
fn fixture() -> (LocalSigner, Prepared, Vec<u8>) {
    let signer = LocalSigner::from_secret(
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).to_keypair_bytes(),
    )
    .unwrap();
    let p = Prepared {
        intent: Intent {
            owner: signer.public_key(),
            beneficiary: Key([8; 32]),
            genesis: Key([9; 32]),
            lamports: 1000,
            fee_ceiling_lamports: 6000,
            context_digest: [2; 32],
        },
        blockhash: Key([3; 32]),
        last_valid_block_height: 500,
        context_slot: 100,
        observed_fee_lamports: 5000,
    };
    let t = p.transaction().unwrap();
    let wire = t.signed(signer.sign(&t.message)).unwrap();
    (signer, p, wire)
}
fn network(p: &Prepared) -> (&'static str, Value, Result<Value>) {
    (
        "getGenesisHash",
        json!([]),
        Ok(json!(p.intent.genesis.to_string())),
    )
}
#[test]
fn prepare_observes_actual_fee_and_simulates_original_message() {
    let (_, p, _) = fixture();
    let t = p.transaction().unwrap();
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getLatestBlockhash",
            json!([{"commitment":"finalized"}]),
            Ok(
                json!({"context":{"slot":99},"value":{"blockhash":p.blockhash.to_string(),"lastValidBlockHeight":500}}),
            ),
        ),
        (
            "getFeeForMessage",
            json!([STANDARD.encode(t.message),{"commitment":"finalized","minContextSlot":99}]),
            Ok(json!({"context":{"slot":100},"value":5000})),
        ),
        (
            "simulateTransaction",
            json!([STANDARD.encode(p.unsigned_bytes().unwrap()),{"encoding":"base64","commitment":"finalized","minContextSlot":100,"sigVerify":false,"replaceRecentBlockhash":false}]),
            Ok(json!({"context":{"slot":101},"value":{"err":null}})),
        ),
    ]);
    assert_eq!(owner_wallet::prepare(&rpc, p.intent.clone()).unwrap(), p);
    rpc.done();
}
#[test]
fn signing_cannot_change_source_beneficiary_or_amount() {
    let (_, p, wire) = fixture();
    assert!(p.verify_signed(&wire).is_ok());
    for field in 0..3 {
        let mut changed = p.clone();
        match field {
            0 => changed.intent.context_digest[0] ^= 1,
            1 => changed.intent.beneficiary = Key([10; 32]),
            _ => changed.intent.lamports += 1,
        };
        assert!(changed.verify_signed(&wire).is_err());
    }
    let mut invalid = wire;
    invalid[20] ^= 1;
    assert!(p.verify_signed(&invalid).is_err());
}
#[test]
fn journal_precedes_single_broadcast_and_saved_wire_never_resends() {
    let (_, p, wire) = fixture();
    let sig = p.verify_signed(&wire).unwrap();
    let height = (
        "getBlockHeight",
        json!([{"commitment":"finalized","minContextSlot":100}]),
        Ok(json!(499)),
    );
    let rpc = Mock::new(vec![
        network(&p),
        height.clone(),
        (
            "sendTransaction",
            json!([STANDARD.encode(&wire),{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","minContextSlot":100,"maxRetries":0}]),
            Ok(json!(sig)),
        ),
    ]);
    assert_eq!(
        owner_wallet::submit_initial(&rpc, &p, &wire, |original, signed, s| {
            assert_eq!(original, &p);
            assert_eq!(signed, wire);
            assert_eq!(s, sig);
            Ok(true)
        })
        .unwrap(),
        sig
    );
    rpc.done();
    let rpc = Mock::new(vec![]);
    owner_wallet::submit_initial(&rpc, &p, &wire, |_, _, _| Ok(false)).unwrap();
    rpc.done();
}
#[test]
fn expiry_journal_failure_and_rpc_failure_never_regenerate() {
    let (_, p, wire) = fixture();
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getBlockHeight",
            json!([{"commitment":"finalized","minContextSlot":100}]),
            Ok(json!(501)),
        ),
    ]);
    assert!(owner_wallet::submit_initial(&rpc, &p, &wire, |_, _, _| Ok(true)).is_err());
    rpc.done();
    let rpc = Mock::new(vec![]);
    assert!(
        owner_wallet::submit_initial(&rpc, &p, &wire, |_, _, _| Err(Error::config(
            "journal CAS refused"
        )))
        .is_err()
    );
    rpc.done();
}
#[test]
fn history_absence_is_unknown_and_recovery_never_broadcasts() {
    let (_, p, wire) = fixture();
    let sig = p.verify_signed(&wire).unwrap();
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getSignatureStatuses",
            json!([[sig],{"searchTransactionHistory":true}]),
            Ok(json!({"context":{"slot":900},"value":[null]})),
        ),
    ]);
    assert_eq!(
        owner_wallet::reconcile(&rpc, &p, &wire).unwrap(),
        Settlement::Unknown
    );
    rpc.done();
}
#[test]
fn finalized_receipt_requires_original_wire_fee_and_coherent_observation() {
    let (_, p, wire) = fixture();
    let sig = p.verify_signed(&wire).unwrap();
    for (err, slot, fee, alter) in [
        (Value::Null, 110, 5000, false),
        (json!({"InstructionError":[0,"Custom"]}), 110, 5000, false),
        (Value::Null, 110, 6001, false),
        (Value::Null, 110, 5000, true),
    ] {
        let mut txwire = wire.clone();
        if alter {
            txwire[100] ^= 1;
        }
        let rpc = Mock::new(vec![
            network(&p),
            (
                "getSignatureStatuses",
                json!([[sig],{"searchTransactionHistory":true}]),
                Ok(
                    json!({"context":{"slot":120},"value":[{"slot":slot,"confirmationStatus":"finalized","err":err}]}),
                ),
            ),
            (
                "getTransaction",
                json!([sig,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]),
                Ok(
                    json!({"slot":slot,"transaction":[STANDARD.encode(txwire),"base64"],"meta":{"fee":fee,"err":err}}),
                ),
            ),
        ]);
        let r = owner_wallet::reconcile(&rpc, &p, &wire);
        if alter || fee > 6000 {
            assert!(r.is_err());
        } else if err.is_null() {
            assert!(matches!(
                r.unwrap(),
                Settlement::Finalized {
                    slot: 110,
                    fee_lamports: 5000,
                    ..
                }
            ));
        } else {
            assert!(matches!(r.unwrap(), Settlement::FinalizedFailure { .. }));
        }
        rpc.done();
    }
}
#[test]
fn finalized_context_rollback_refuses() {
    let (_, p, wire) = fixture();
    let sig = p.verify_signed(&wire).unwrap();
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getSignatureStatuses",
            json!([[sig],{"searchTransactionHistory":true}]),
            Ok(json!({"context":{"slot":99},"value":[null]})),
        ),
    ]);
    assert!(owner_wallet::reconcile(&rpc, &p, &wire).is_err());
    rpc.done();
}

#[test]
fn simulation_refusal_fee_overrun_and_rollback_stop_before_signing() {
    let (_, p, _) = fixture();
    for (fee, slot) in [(6001, 100), (5000, 98)] {
        let rpc = Mock::new(vec![
            network(&p),
            (
                "getLatestBlockhash",
                json!([{"commitment":"finalized"}]),
                Ok(
                    json!({"context":{"slot":99},"value":{"blockhash":p.blockhash.to_string(),"lastValidBlockHeight":500}}),
                ),
            ),
            (
                "getFeeForMessage",
                json!([STANDARD.encode(p.transaction().unwrap().message),{"commitment":"finalized","minContextSlot":99}]),
                Ok(json!({"context":{"slot":slot},"value":fee})),
            ),
        ]);
        assert!(owner_wallet::prepare(&rpc, p.intent.clone()).is_err());
        rpc.done();
    }
    let sig = p.verify_signed(&fixture().2).unwrap();
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getBlockHeight",
            json!([{"commitment":"finalized","minContextSlot":100}]),
            Ok(json!(499)),
        ),
        (
            "sendTransaction",
            json!([STANDARD.encode(fixture().2),{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","minContextSlot":100,"maxRetries":0}]),
            Err(Error::uncertain("lost response")),
        ),
    ]);
    let mut journaled = false;
    assert!(
        owner_wallet::submit_initial(&rpc, &p, &fixture().2, |_, _, s| {
            assert_eq!(s, sig);
            journaled = true;
            Ok(true)
        })
        .is_err()
    );
    assert!(journaled);
    rpc.done();
}
#[test]
fn every_post_journal_error_is_uncertain() {
    let (_, p, wire) = fixture();
    for failure in [
        Error::config("already processed"),
        Error::denied("blockhash not found"),
        Error::uncertain("response lost"),
    ] {
        let rpc = Mock::new(vec![
            network(&p),
            (
                "getBlockHeight",
                json!([{"commitment":"finalized","minContextSlot":100}]),
                Ok(json!(499)),
            ),
            (
                "sendTransaction",
                json!([STANDARD.encode(&wire),{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","minContextSlot":100,"maxRetries":0}]),
                Err(failure),
            ),
        ]);
        let mut saved = false;
        let error = owner_wallet::submit_initial(&rpc, &p, &wire, |_, _, _| {
            saved = true;
            Ok(true)
        })
        .unwrap_err();
        assert!(saved);
        assert_eq!(error.code, 5);
        rpc.done();
    }
    let rpc = Mock::new(vec![(
        "getGenesisHash",
        json!([]),
        Ok(json!(Key([4; 32]).to_string())),
    )]);
    assert_eq!(
        owner_wallet::submit_initial(&rpc, &p, &wire, |_, _, _| Ok(true))
            .unwrap_err()
            .code,
        5
    );
    rpc.done();
}
#[test]
fn simulation_requires_present_null_error_and_coherent_slot() {
    let (_, p, _) = fixture();
    for value in [json!({"err":"failed"}), json!({}), json!(null)] {
        let rpc = Mock::new(vec![
            network(&p),
            (
                "getLatestBlockhash",
                json!([{"commitment":"finalized"}]),
                Ok(
                    json!({"context":{"slot":99},"value":{"blockhash":p.blockhash.to_string(),"lastValidBlockHeight":500}}),
                ),
            ),
            (
                "getFeeForMessage",
                json!([STANDARD.encode(p.transaction().unwrap().message),{"commitment":"finalized","minContextSlot":99}]),
                Ok(json!({"context":{"slot":100},"value":5000})),
            ),
            (
                "simulateTransaction",
                json!([STANDARD.encode(p.unsigned_bytes().unwrap()),{"encoding":"base64","commitment":"finalized","minContextSlot":100,"sigVerify":false,"replaceRecentBlockhash":false}]),
                Ok(json!({"context":{"slot":101},"value":value})),
            ),
        ]);
        assert!(owner_wallet::prepare(&rpc, p.intent.clone()).is_err());
        rpc.done();
    }
}
#[test]
fn inconsistent_receipt_stays_unresolved() {
    let (_, p, wire) = fixture();
    let sig = p.verify_signed(&wire).unwrap();
    for tx in [
        json!(null),
        json!({"slot":111,"transaction":[STANDARD.encode(&wire),"base64"],"meta":{"fee":5000,"err":null}}),
        json!({"slot":110,"transaction":[STANDARD.encode(&wire),"base64"],"meta":{"fee":5500,"err":null}}),
        json!({"slot":110,"transaction":[STANDARD.encode(&wire),"base64"],"meta":{"fee":5000,"err":"failed"}}),
    ] {
        let missing = tx.is_null();
        let rpc = Mock::new(vec![
            network(&p),
            (
                "getSignatureStatuses",
                json!([[sig],{"searchTransactionHistory":true}]),
                Ok(
                    json!({"context":{"slot":120},"value":[{"slot":110,"confirmationStatus":"finalized","err":null}]}),
                ),
            ),
            (
                "getTransaction",
                json!([sig,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]),
                Ok(tx),
            ),
        ]);
        let r = owner_wallet::reconcile(&rpc, &p, &wire);
        if missing {
            assert_eq!(r.unwrap(), Settlement::Unknown);
        } else {
            assert!(r.is_err());
        }
        rpc.done();
    }
    let rpc = Mock::new(vec![
        network(&p),
        (
            "getSignatureStatuses",
            json!([[sig],{"searchTransactionHistory":true}]),
            Ok(
                json!({"context":{"slot":120},"value":[{"slot":110,"confirmationStatus":"confirmed","err":null}]}),
            ),
        ),
    ]);
    assert_eq!(
        owner_wallet::reconcile(&rpc, &p, &wire).unwrap(),
        Settlement::Unknown
    );
    rpc.done();
}
