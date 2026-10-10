//! Owner-signed native transfer transport. The host authorizes source and reserves
//! budgets before using this module. Recovery never submits a transaction.
use crate::{
    crypto::Key,
    error::{Error, Result},
    rpc::Rpc,
    transaction::{Instruction, Meta, Signed, Transaction},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub owner: Key,
    pub beneficiary: Key,
    pub genesis: Key,
    pub lamports: u64,
    pub fee_ceiling_lamports: u64,
    /// SHA-256 commitment to host-verified source, grant, run and exact input.
    pub context_digest: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepared {
    pub intent: Intent,
    pub blockhash: Key,
    pub last_valid_block_height: u64,
    pub context_slot: u64,
    pub observed_fee_lamports: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settlement {
    Unknown,
    Finalized {
        signature: String,
        slot: u64,
        fee_lamports: u64,
    },
    /// Only a finalized, exact original transaction with an execution error.
    FinalizedFailure {
        signature: String,
        slot: u64,
        fee_lamports: u64,
    },
}
impl Intent {
    fn validate(&self) -> Result<()> {
        if self.owner == self.beneficiary
            || !self.owner.on_curve()
            || self.genesis.0 == [0; 32]
            || self.context_digest == [0; 32]
            || self.lamports == 0
            || self.fee_ceiling_lamports == 0
        {
            return Err(Error::config("Invalid owner transfer intent"));
        }
        Ok(())
    }
    pub fn transaction(&self, blockhash: Key, last_valid_block_height: u64) -> Result<Transaction> {
        self.validate()?;
        if blockhash.0 == [0; 32] || last_valid_block_height == 0 {
            return Err(Error::config("Invalid transfer expiry"));
        }
        let mut transfer = 2u32.to_le_bytes().to_vec();
        transfer.extend(self.lamports.to_le_bytes());
        let hex = self
            .context_digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let memo = format!("allowit-owner-run-v1:{hex}");
        Transaction::new(
            self.owner,
            blockhash,
            vec![
                Instruction {
                    program: Key([0; 32]),
                    accounts: vec![
                        Meta {
                            key: self.owner,
                            writable: true,
                            signer: true,
                        },
                        Meta {
                            key: self.beneficiary,
                            writable: true,
                            signer: false,
                        },
                    ],
                    data: transfer,
                },
                Instruction {
                    program: Key::parse("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")?,
                    accounts: vec![Meta {
                        key: self.owner,
                        writable: false,
                        signer: true,
                    }],
                    data: memo.into_bytes(),
                },
            ],
        )
    }
}
impl Prepared {
    pub fn transaction(&self) -> Result<Transaction> {
        if self.context_slot == 0
            || self.observed_fee_lamports == 0
            || self.observed_fee_lamports > self.intent.fee_ceiling_lamports
        {
            return Err(Error::config(
                "Invalid observed owner transfer fee or context",
            ));
        }
        self.intent
            .transaction(self.blockhash, self.last_valid_block_height)
    }
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>> {
        self.transaction()?.partially_signed(&[])
    }
    pub fn verify_signed(&self, wire: &[u8]) -> Result<String> {
        let proof = Signed::parse(wire)?;
        proof.matches(&self.transaction()?)?;
        Ok(bs58::encode(proof.primary_signature()?).into_string())
    }
}
fn context(response: &Value, min: u64) -> Result<u64> {
    response["context"]["slot"]
        .as_u64()
        .filter(|s| *s > 0 && *s >= min)
        .ok_or_else(|| Error::config("Incoherent finalized owner transfer context"))
}
fn check_network(rpc: &dyn Rpc, genesis: Key) -> Result<()> {
    if rpc.call("getGenesisHash", json!([]))?.as_str() != Some(genesis.to_string().as_str()) {
        return Err(Error::config("Owner transfer RPC network changed"));
    }
    Ok(())
}
/// Observe the actual complete message fee and simulate the unchanged unsigned
/// packet. No signing, journal mutation or broadcast occurs here.
pub fn prepare(rpc: &dyn Rpc, intent: Intent) -> Result<Prepared> {
    intent.validate()?;
    check_network(rpc, intent.genesis)?;
    let latest = rpc.call("getLatestBlockhash", json!([{"commitment":"finalized"}]))?;
    let slot = context(&latest, 0)?;
    let blockhash = Key::parse(
        latest["value"]["blockhash"]
            .as_str()
            .ok_or_else(|| Error::config("Missing blockhash"))?,
    )?;
    let height = latest["value"]["lastValidBlockHeight"]
        .as_u64()
        .filter(|h| *h > 0)
        .ok_or_else(|| Error::config("Missing blockhash expiry"))?;
    let transaction = intent.transaction(blockhash, height)?;
    let fee=rpc.call("getFeeForMessage",json!([STANDARD.encode(&transaction.message),{"commitment":"finalized","minContextSlot":slot}]))?;
    let fee_slot = context(&fee, slot)?;
    let fee = fee["value"]
        .as_u64()
        .filter(|f| *f > 0 && *f <= intent.fee_ceiling_lamports)
        .ok_or_else(|| {
            Error::denied("Native transfer fee is unavailable or exceeds the source bound")
        })?;
    let prepared = Prepared {
        intent,
        blockhash,
        last_valid_block_height: height,
        context_slot: fee_slot,
        observed_fee_lamports: fee,
    };
    let simulation=rpc.call("simulateTransaction",json!([STANDARD.encode(prepared.unsigned_bytes()?),{"encoding":"base64","commitment":"finalized","minContextSlot":fee_slot,"sigVerify":false,"replaceRecentBlockhash":false}]))?;
    context(&simulation, fee_slot)?;
    if !simulation["value"].is_object()
        || simulation["value"].get("err").is_none()
        || !simulation["value"]["err"].is_null()
    {
        return Err(Error::denied(
            "The unchanged owner transfer failed simulation",
        ));
    }
    Ok(prepared)
}
/// The journal callback must atomically retain the exact signed wire and source
/// reservation before returning true for its first broadcast. False means the
/// original wire was already retained; this function then performs no send.
pub fn submit_initial(
    rpc: &dyn Rpc,
    prepared: &Prepared,
    wire: &[u8],
    journal: impl FnOnce(&Prepared, &[u8], &str) -> Result<bool>,
) -> Result<String> {
    let signature = prepared.verify_signed(wire)?;
    // Retain signed liability even if the first RPC observation fails or the
    // packet arrives after expiry: the wallet may already have broadcast it.
    if !journal(prepared, wire, &signature)? {
        return Ok(signature);
    }
    let uncertain =
        || Error::uncertain("The signed owner transfer outcome is unknown; retain its journal");
    check_network(rpc, prepared.intent.genesis).map_err(|_| uncertain())?;
    let height = rpc
        .call(
            "getBlockHeight",
            json!([{"commitment":"finalized","minContextSlot":prepared.context_slot}]),
        )
        .map_err(|_| uncertain())?
        .as_u64()
        .ok_or_else(uncertain)?;
    if height > prepared.last_valid_block_height {
        return Err(uncertain());
    }
    let result=rpc.call("sendTransaction",json!([STANDARD.encode(wire),{"encoding":"base64","skipPreflight":false,"preflightCommitment":"finalized","minContextSlot":prepared.context_slot,"maxRetries":0}])).map_err(|_| uncertain())?;
    if result.as_str() != Some(signature.as_str()) {
        return Err(Error::uncertain(
            "RPC did not confirm the original transaction signature; retain its journal",
        ));
    }
    Ok(signature)
}
/// History absence and blockhash expiry are insufficient to free a simple-wallet
/// reservation. Only the finalized exact original wire supplies terminal proof.
pub fn reconcile(rpc: &dyn Rpc, prepared: &Prepared, wire: &[u8]) -> Result<Settlement> {
    let signature = prepared.verify_signed(wire)?;
    check_network(rpc, prepared.intent.genesis)?;
    let statuses = rpc.call(
        "getSignatureStatuses",
        json!([[signature],{"searchTransactionHistory":true}]),
    )?;
    context(&statuses, prepared.context_slot)?;
    let status = &statuses["value"][0];
    if status.is_null() || status["confirmationStatus"] != "finalized" {
        return Ok(Settlement::Unknown);
    }
    let slot = status["slot"]
        .as_u64()
        .filter(|s| *s >= prepared.context_slot)
        .ok_or_else(|| Error::config("Invalid finalized transfer slot"))?;
    let tx=rpc.call("getTransaction",json!([signature,{"encoding":"base64","commitment":"finalized","maxSupportedTransactionVersion":0}]))?;
    if tx.is_null() {
        return Ok(Settlement::Unknown);
    }
    if tx["slot"].as_u64() != Some(slot) || tx["transaction"][1] != "base64" {
        return Err(Error::config("Finalized transaction identity changed"));
    }
    let raw = STANDARD
        .decode(
            tx["transaction"][0]
                .as_str()
                .ok_or_else(|| Error::config("Missing finalized transaction"))?,
        )
        .map_err(|_| Error::config("Invalid finalized transaction encoding"))?;
    if raw != wire {
        return Err(Error::config(
            "Finalized transaction changed the original wire",
        ));
    }
    let meta = tx
        .get("meta")
        .filter(|v| v.is_object())
        .ok_or_else(|| Error::config("Missing finalized transfer metadata"))?;
    let fee = meta["fee"]
        .as_u64()
        .filter(|f| {
            *f == prepared.observed_fee_lamports && *f <= prepared.intent.fee_ceiling_lamports
        })
        .ok_or_else(|| Error::config("Finalized fee does not match the admitted fee"))?;
    let error = meta
        .get("err")
        .ok_or_else(|| Error::config("Missing finalized transfer outcome"))?;
    if status.get("err") != Some(error) {
        return Err(Error::config("Finalized transfer observations disagree"));
    }
    Ok(if error.is_null() {
        Settlement::Finalized {
            signature,
            slot,
            fee_lamports: fee,
        }
    } else {
        Settlement::FinalizedFailure {
            signature,
            slot,
            fee_lamports: fee,
        }
    })
}
