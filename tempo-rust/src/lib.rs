//! Offline Tempo plan verification. No keys, RPC or broadcasting live here.
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub type Result<T> = std::result::Result<T, String>;
pub const PROFILE: &str = "tempo-native-v1";
pub const TERMS: &str = "(bytes32,bytes32,uint256,uint256,uint256,uint64,address,bool)";
pub const EXECUTION: &str = "(uint256,address,address,bytes32,bytes32,bytes32,uint64,uint64,address,uint256,uint64,bytes32,bytes32,bytes32)";
pub const ZERO: &str = "0x0000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub network: String,
    pub chain_id: u64,
    pub rpc_url: String,
    pub factory: String,
    pub factory_code_hash: String,
    pub token: String,
    pub executor: String,
    pub authority: String,
    pub fee_token: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub id: String,
    pub profile: String,
    pub network: String,
    pub chain_id: u64,
    pub owner: String,
    pub token: String,
    pub executor: String,
    pub authority: String,
    pub factory: String,
    pub vault: String,
    pub policy_digest: String,
    pub requirements_digest: String,
    pub semantic_required: bool,
    pub prompt: String,
    pub daily_limit: String,
    pub action_limit: String,
    pub total_limit: String,
    #[serde(with = "u64_string")]
    pub expires_at: u64,
    pub recipient: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transaction {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub data: String,
    pub value: String,
    pub fee_token: String,
}
pub fn hex(value: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in value {
        use std::fmt::Write;
        write!(s, "{b:02x}").expect("String write");
    }
    s
}
pub fn unhex(value: &str) -> Result<Vec<u8>> {
    let s = value.strip_prefix("0x").ok_or("Missing hex prefix")?;
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid hex bytes".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "Invalid hex bytes".into()))
        .collect()
}
pub fn address(value: &str) -> Result<String> {
    let b = unhex(value)?;
    if b.len() != 20 {
        return Err("Invalid Tempo account".into());
    }
    Ok(hex(&b))
}
pub fn units(value: &str) -> Result<u64> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty()
        || parts.len() > 2
        || parts[0].is_empty()
        || parts[0].len() > 1 && parts[0].starts_with('0')
        || !parts[0].bytes().all(|b| b.is_ascii_digit())
    {
        return Err("Use an exact decimal token amount".into());
    }
    let fraction = parts.get(1).copied().unwrap_or("");
    if parts.len() == 2
        && (fraction.is_empty()
            || fraction.len() > 6
            || !fraction.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("Use at most six decimal places".into());
    }
    let whole = parts[0].parse::<u64>().map_err(|_| "Amount exceeds u64")?;
    let frac = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<6}")
            .parse::<u64>()
            .map_err(|_| "Invalid amount")?
    };
    whole
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(frac))
        .ok_or_else(|| "Amount exceeds u64".into())
}
pub fn keccak(value: impl AsRef<[u8]>) -> [u8; 32] {
    Keccak256::digest(value.as_ref()).into()
}
fn word(n: u64) -> [u8; 32] {
    let mut w = [0; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}
fn number(w: &[u8]) -> Result<u64> {
    if w.len() != 32 || w[..24].iter().any(|b| *b != 0) {
        return Err("Unsupported integer range".into());
    }
    Ok(u64::from_be_bytes(w[24..].try_into().expect("word")))
}
fn digest(s: &str) -> Result<[u8; 32]> {
    unhex(&format!("0x{}", s.strip_prefix("0x").unwrap_or(s)))?
        .try_into()
        .map_err(|_| "Invalid digest".into())
}
fn account(s: &str) -> Result<[u8; 32]> {
    let mut w = [0; 32];
    w[12..].copy_from_slice(&unhex(&address(s)?)?);
    Ok(w)
}
fn terms(p: &Policy) -> Result<Vec<[u8; 32]>> {
    Ok(vec![
        digest(&p.policy_digest)?,
        digest(&p.requirements_digest)?,
        word(units(&p.total_limit)?),
        word(units(&p.daily_limit)?),
        word(units(&p.action_limit)?),
        word(p.expires_at),
        account(&p.recipient)?,
        word(u64::from(p.semantic_required)),
    ])
}
pub fn execution_digest(chain: u64, vault: &str, words: &[[u8; 32]]) -> Result<[u8; 32]> {
    if words.len() != 14 {
        return Err("Invalid execution tuple".into());
    }
    let domain=keccak([keccak("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),keccak("AllowIt Tempo Vault"),keccak("1"),word(chain),account(vault)?].concat());
    let typehash=keccak("Execution(uint256 chainId,address vault,address token,bytes32 policyId,bytes32 policyDigest,bytes32 requirementsDigest,uint64 revision,uint64 nonce,address recipient,uint256 amount,uint64 expiresAt,bytes32 requestHash,bytes32 assessmentHash,bytes32 memo)");
    let data = keccak([typehash.to_vec(), words.concat()].concat());
    Ok(keccak(
        [vec![0x19, 0x01], domain.to_vec(), data.to_vec()].concat(),
    ))
}
pub fn validate_policy(c: &Config, p: &Policy) -> Result<()> {
    if p.profile != PROFILE
        || p.network != c.network
        || p.chain_id != c.chain_id
        || !matches!(
            (p.network.as_str(), p.chain_id),
            ("tempo:localnet", 31337 | 42431) | ("tempo:testnet", 42431)
        )
    {
        return Err("Tempo profile/network mismatch".into());
    }
    for (a, b) in [
        (&p.token, &c.token),
        (&p.executor, &c.executor),
        (&p.authority, &c.authority),
        (&p.factory, &c.factory),
    ] {
        if address(a)? != address(b)? || address(a)? == ZERO {
            return Err("Tempo custody configuration mismatch".into());
        }
    }
    for a in [&p.owner, &p.vault] {
        if address(a)? == ZERO {
            return Err("Zero Tempo account".into());
        }
    }
    if address(&p.owner)? == address(&p.executor)?
        || address(&p.owner)? == address(&p.authority)?
        || address(&p.executor)? == address(&p.authority)?
    {
        return Err("Owner, executor and authority must differ".into());
    }
    for d in [&p.id, &p.policy_digest, &p.requirements_digest] {
        if digest(d)? == [0; 32] {
            return Err("Zero policy digest".into());
        }
    }
    let limits = [
        units(&p.action_limit)?,
        units(&p.daily_limit)?,
        units(&p.total_limit)?,
    ];
    if limits[0] == 0 || limits[0] > limits[1] || limits[1] > limits[2] {
        return Err("Invalid Tempo custody limits".into());
    }
    Ok(())
}
/// Verify exact standard calldata and recover the authority for executor plans.
/// A validated plan is still prepared; this function makes no settlement claim.
pub fn validate_prepared(c: &Config, p: &Policy, tx: &Transaction) -> Result<()> {
    validate_policy(c, p)?;
    if tx.chain_id != p.chain_id
        || tx.value != "0x0"
        || address(&tx.fee_token)? != address(&c.fee_token)?
    {
        return Err("Changed Tempo transaction envelope".into());
    }
    let data = unhex(&tx.data)?;
    if data.len() < 4 || !(data.len() - 4).is_multiple_of(32) {
        return Err("Invalid Tempo calldata".into());
    }
    let selector = &data[..4];
    let words = data[4..].as_chunks::<32>().0;
    if selector == &keccak(format!("execute({EXECUTION},bytes)"))[..4] {
        if address(&tx.from)? != address(&p.executor)?
            || address(&tx.to)? != address(&p.vault)?
            || words.len() != 19
            || words[14] != word(480)
            || words[15] != word(65)
        {
            return Err("Changed executor transaction".into());
        }
        let expected = [
            word(p.chain_id),
            account(&p.vault)?,
            account(&p.token)?,
            digest(&p.id)?,
            digest(&p.policy_digest)?,
            digest(&p.requirements_digest)?,
        ];
        if words[..6] != expected {
            return Err("Changed execution policy binding".into());
        }
        if number(&words[6])? == 0
            || number(&words[7])? == 0
            || words[8] == [0; 32]
            || words[8][..12].iter().any(|b| *b != 0)
            || words[8] == account(&p.vault)?
            || p.recipient != ZERO && words[8] != account(&p.recipient)?
            || number(&words[9])? == 0
            || number(&words[9])? > units(&p.action_limit)?
            || number(&words[10])? == 0
            || number(&words[10])? > p.expires_at
            || words[11] == [0; 32]
            || p.semantic_required && words[12] == [0; 32]
        {
            return Err("Invalid executor authorization".into());
        }
        let sig_bytes = &data[4 + 16 * 32..4 + 16 * 32 + 65];
        if data[4 + 16 * 32 + 65..].iter().any(|b| *b != 0) {
            return Err("Noncanonical signature padding".into());
        }
        let sig =
            Signature::from_slice(&sig_bytes[..64]).map_err(|_| "Invalid authority signature")?;
        if sig.normalize_s().is_some() {
            return Err("Malleable authority signature".into());
        }
        let id = match sig_bytes[64] {
            27 | 28 => sig_bytes[64] - 27,
            0 | 1 => sig_bytes[64],
            _ => return Err("Invalid recovery identifier".into()),
        };
        let key = VerifyingKey::recover_from_prehash(
            &execution_digest(p.chain_id, &p.vault, &words[..14])?,
            &sig,
            RecoveryId::from_byte(id).expect("bounded"),
        )
        .map_err(|_| "Invalid authority signature")?;
        if hex(&keccak(&key.to_encoded_point(false).as_bytes()[1..])[12..])
            != address(&p.authority)?
        {
            return Err("Wrong execution authority".into());
        }
        return Ok(());
    }
    if address(&tx.from)? != address(&p.owner)? {
        return Err("Changed owner transaction".into());
    }
    if selector == &keccak("approve(address,uint256)")[..4] {
        if address(&tx.to)? != address(&p.token)?
            || words.len() != 2
            || (words[0] != account(&p.factory)? && words[0] != account(&p.vault)?)
            || number(&words[1])? == 0
        {
            return Err("Invalid exact funding approval".into());
        }
        return Ok(());
    }
    if selector
        == &keccak(format!(
            "createVault(bytes32,address,address,address,{TERMS},uint256)"
        ))[..4]
    {
        let mut expected = vec![
            digest(&p.id)?,
            account(&p.token)?,
            account(&p.executor)?,
            account(&p.authority)?,
        ];
        expected.extend(terms(p)?);
        if address(&tx.to)? != address(&p.factory)?
            || words.len() != 13
            || words[..12] != expected
            || number(&words[12])? == 0
            || number(&words[12])? > units(&p.total_limit)?
        {
            return Err("Changed Tempo deployment".into());
        }
        return Ok(());
    }
    if address(&tx.to)? != address(&p.vault)? {
        return Err("Changed vault transaction".into());
    }
    if selector == &keccak("fund(uint256)")[..4] && words.len() == 1 && number(&words[0])? > 0 {
        return Ok(());
    }
    if (selector == &keccak("revoke()")[..4] || selector == &keccak("withdrawRemaining()")[..4])
        && words.is_empty()
    {
        return Ok(());
    }
    Err("Unsupported Tempo operation".into())
}
/// Verify the authority approved the exact CLI request, including the raw JSON
/// context bytes that were submitted. Request identifiers cannot replace data binding.
#[allow(clippy::too_many_arguments)]
pub fn validate_execution_request(
    c: &Config,
    p: &Policy,
    tx: &Transaction,
    request_id: &str,
    recipient: &str,
    amount: &str,
    action: &str,
    merchant: &str,
    context: Option<&str>,
) -> Result<()> {
    validate_prepared(c, p, tx)?;
    let data = unhex(&tx.data)?;
    if data[..4] != keccak(format!("execute({EXECUTION},bytes)"))[..4] {
        return Err("Expected an executor payment".into());
    }
    let raw = context.unwrap_or("null");
    let _: serde_json::Value = serde_json::from_str(raw).map_err(|_| "Invalid request context")?;
    let amount_units = units(amount)?;
    let fraction = format!("{:06}", amount_units % 1_000_000)
        .trim_end_matches('0')
        .to_string();
    let normalized = if fraction.is_empty() {
        (amount_units / 1_000_000).to_string()
    } else {
        format!("{}.{fraction}", amount_units / 1_000_000)
    };
    let identity = serde_json::json!({"policyId":p.id,"amount":normalized,"recipient":address(recipient)?,"action":action,"merchant":merchant,"context":raw});
    let intent = format!(
        "{:x}",
        sha2::Sha256::digest(
            serde_json::to_vec(&identity).map_err(|_| "Invalid request identity")?
        )
    );
    let request_hash: [u8; 32] =
        sha2::Sha256::digest(format!("{request_id}:{intent}").as_bytes()).into();
    let memo: [u8; 32] = sha2::Sha256::digest(request_id.as_bytes()).into();
    if data[4 + 8 * 32..4 + 9 * 32] != account(recipient)?
        || data[4 + 9 * 32..4 + 10 * 32] != word(amount_units)
        || data[4 + 11 * 32..4 + 12 * 32] != request_hash
        || data[4 + 13 * 32..4 + 14 * 32] != memo
    {
        return Err("Executor plan changed the exact requested action".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    fn key_address(seed: u8) -> String {
        let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
        hex(&keccak(&key.verifying_key().to_encoded_point(false).as_bytes()[1..])[12..])
    }
    fn fixture() -> (Config, Policy, Transaction) {
        let c = Config {
            network: "tempo:localnet".into(),
            chain_id: 31337,
            rpc_url: "http://127.0.0.1:18545".into(),
            factory: hex(&[11; 20]),
            factory_code_hash: hex(&[12; 32]),
            token: hex(&[13; 20]),
            executor: key_address(6),
            authority: key_address(7),
            fee_token: hex(&[14; 20]),
        };
        let p = Policy {
            id: hex(&[15; 32])[2..].into(),
            profile: PROFILE.into(),
            network: c.network.clone(),
            chain_id: c.chain_id,
            owner: key_address(5),
            token: c.token.clone(),
            executor: c.executor.clone(),
            authority: c.authority.clone(),
            factory: c.factory.clone(),
            vault: hex(&[16; 20]),
            policy_digest: hex(&[17; 32]),
            requirements_digest: hex(&[18; 32]),
            semantic_required: true,
            prompt: "Pay for approved research".into(),
            daily_limit: "5".into(),
            action_limit: "1".into(),
            total_limit: "20".into(),
            expires_at: u64::MAX,
            recipient: ZERO.into(),
        };
        let recipient = hex(&[19; 20]);
        let identity = serde_json::json!({"policyId":p.id,"amount":"0.25","recipient":recipient,"action":"buy research","merchant":"research","context":"{\"purpose\":\"research\"}"});
        let intent = format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&identity).unwrap())
        );
        let request_hash: [u8; 32] = sha2::Sha256::digest(format!("request-1:{intent}")).into();
        let memo: [u8; 32] = sha2::Sha256::digest("request-1").into();
        let mut words = vec![
            word(p.chain_id),
            account(&p.vault).unwrap(),
            account(&p.token).unwrap(),
            digest(&p.id).unwrap(),
            digest(&p.policy_digest).unwrap(),
            digest(&p.requirements_digest).unwrap(),
            word(1),
            word(1),
            account(&recipient).unwrap(),
            word(250000),
            word(280),
            request_hash,
            [20; 32],
            memo,
        ];
        let signer = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let (sig, id) = signer
            .sign_prehash_recoverable(&execution_digest(p.chain_id, &p.vault, &words).unwrap())
            .unwrap();
        words.extend([word(480), word(65)]);
        let mut data = keccak(format!("execute({EXECUTION},bytes)"))[..4].to_vec();
        data.extend(words.concat());
        data.extend(sig.to_bytes());
        data.push(id.to_byte() + 27);
        data.resize(4 + 19 * 32, 0);
        let tx = Transaction {
            chain_id: p.chain_id,
            from: p.executor.clone(),
            to: p.vault.clone(),
            data: hex(&data),
            value: "0x0".into(),
            fee_token: c.fee_token.clone(),
        };
        (c, p, tx)
    }
    #[test]
    fn signed_executor_plan_binds_the_complete_original_request() {
        let (c, p, tx) = fixture();
        let recipient = hex(&[19; 20]);
        let verify = |id: &str,
                      recipient: &str,
                      amount: &str,
                      action: &str,
                      merchant: &str,
                      context: &str| {
            validate_execution_request(
                &c,
                &p,
                &tx,
                id,
                recipient,
                amount,
                action,
                merchant,
                Some(context),
            )
        };
        assert!(verify(
            "request-1",
            &recipient,
            "0.25",
            "buy research",
            "research",
            r#"{"purpose":"research"}"#
        )
        .is_ok());
        for (id, r, a, act, m, ctx) in [
            (
                "request-2",
                recipient.clone(),
                "0.25",
                "buy research",
                "research",
                r#"{"purpose":"research"}"#,
            ),
            (
                "request-1",
                hex(&[21; 20]),
                "0.25",
                "buy research",
                "research",
                r#"{"purpose":"research"}"#,
            ),
            (
                "request-1",
                recipient.clone(),
                "0.26",
                "buy research",
                "research",
                r#"{"purpose":"research"}"#,
            ),
            (
                "request-1",
                recipient.clone(),
                "0.25",
                "different action",
                "research",
                r#"{"purpose":"research"}"#,
            ),
            (
                "request-1",
                recipient.clone(),
                "0.25",
                "buy research",
                "different merchant",
                r#"{"purpose":"research"}"#,
            ),
            (
                "request-1",
                recipient.clone(),
                "0.25",
                "buy research",
                "research",
                r#"{"purpose":"casino"}"#,
            ),
            (
                "request-1",
                recipient.clone(),
                "0.25",
                "buy research",
                "research",
                r#"{ "purpose": "research" }"#,
            ),
        ] {
            assert!(verify(id, &r, a, act, m, ctx).is_err());
        }
    }
    #[test]
    fn changed_signatures_envelopes_padding_and_domain_are_rejected() {
        let (c, p, tx) = fixture();
        assert!(validate_prepared(&c, &p, &tx).is_ok());
        let mut changed = tx.clone();
        changed.chain_id = 42431;
        assert!(validate_prepared(&c, &p, &changed).is_err());
        changed = tx.clone();
        changed.fee_token = hex(&[99; 20]);
        assert!(validate_prepared(&c, &p, &changed).is_err());
        for index in [
            4 + 8 * 32 + 31,
            4 + 9 * 32 + 31,
            4 + 11 * 32 + 31,
            4 + 16 * 32,
            4 + 19 * 32 - 1,
        ] {
            let mut bytes = unhex(&tx.data).unwrap();
            bytes[index] ^= 1;
            changed = tx.clone();
            changed.data = hex(&bytes);
            assert!(validate_prepared(&c, &p, &changed).is_err());
        }
        let mut moved = p.clone();
        moved.vault = hex(&[99; 20]);
        assert!(validate_prepared(&c, &moved, &tx).is_err());
        let mut domain = c.clone();
        domain.network = "tempo:testnet".into();
        domain.chain_id = 42431;
        moved = p.clone();
        moved.network = domain.network.clone();
        moved.chain_id = 42431;
        changed = tx;
        changed.chain_id = 42431;
        assert!(validate_prepared(&domain, &moved, &changed).is_err());
    }
    #[test]
    fn exact_amounts() {
        assert_eq!(units("0.25").unwrap(), 250000);
        assert_eq!(units("18446744073709.551615").unwrap(), u64::MAX);
        for amount in ["0.0000001", "01", "1e3", "-1", "18446744073709.551616"] {
            assert!(units(amount).is_err());
        }
    }
    #[test]
    fn digest_domains_differ() {
        let words = vec![word(1); 14];
        assert_ne!(
            execution_digest(31337, ZERO, &words).unwrap(),
            execution_digest(42431, ZERO, &words).unwrap()
        );
    }
}

mod u64_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u64, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty()
            || s.len() > 1 && s.starts_with('0')
            || !s.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(serde::de::Error::custom("Use an exact decimal string"));
        }
        s.parse().map_err(serde::de::Error::custom)
    }
}
