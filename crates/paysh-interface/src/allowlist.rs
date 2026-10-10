//! Versioned service membership, scoped to the policy's network, token and payee.
use sha2::{Digest, Sha256};

pub const MAX_SERVICES: usize = 8;
pub const MAX_PROOF_DEPTH: usize = 3;

pub fn service_hash(id: &str) -> Option<[u8; 32]> {
    if id.is_empty()
        || id.len() > 200
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return None;
    }
    Some(digest(&[b"allowit-paysh-service-v2\0", id.as_bytes()]))
}
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}
pub fn leaf(
    network: &[u8; 32],
    mint: &[u8; 32],
    recipient: &[u8; 32],
    service: &[u8; 32],
) -> [u8; 32] {
    digest(&[
        b"allowit-paysh-leaf-v2\0",
        network,
        mint,
        recipient,
        service,
    ])
}
fn pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (a, b) = if a <= b { (a, b) } else { (b, a) };
    digest(&[b"allowit-paysh-node-v2\0", &a, &b])
}
fn leaves(
    ids: &[String],
    network: &[u8; 32],
    mint: &[u8; 32],
    recipient: &[u8; 32],
) -> Option<Vec<[u8; 32]>> {
    if ids.len() > MAX_SERVICES {
        return None;
    }
    let mut values = ids
        .iter()
        .map(|id| Some(leaf(network, mint, recipient, &service_hash(id)?)))
        .collect::<Option<Vec<_>>>()?;
    values.sort_unstable();
    if values.windows(2).any(|v| v[0] == v[1]) {
        return None;
    }
    Some(values)
}
fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    level
        .chunks(2)
        .map(|p| pair(p[0], *p.get(1).unwrap_or(&p[0])))
        .collect()
}
pub fn root(
    ids: &[String],
    network: &[u8; 32],
    mint: &[u8; 32],
    recipient: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut level = leaves(ids, network, mint, recipient)?;
    if level.is_empty() {
        return Some([0; 32]);
    }
    while level.len() > 1 {
        level = next_level(&level);
    }
    Some(level[0])
}
pub fn proof(
    ids: &[String],
    service: &str,
    network: &[u8; 32],
    mint: &[u8; 32],
    recipient: &[u8; 32],
) -> Option<Vec<[u8; 32]>> {
    let mut level = leaves(ids, network, mint, recipient)?;
    let value = leaf(network, mint, recipient, &service_hash(service)?);
    let mut index = level.iter().position(|h| h == &value)?;
    let mut proof = Vec::new();
    while level.len() > 1 {
        proof.push(*level.get(index ^ 1).unwrap_or(&level[index]));
        index /= 2;
        level = next_level(&level);
    }
    Some(proof)
}
pub fn verify(root: &[u8; 32], value: [u8; 32], proof: &[[u8; 32]]) -> bool {
    *root != [0; 32]
        && proof.len() <= MAX_PROOF_DEPTH
        && proof.iter().fold(value, |h, sibling| pair(h, *sibling)) == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_independent_browser_sha256_vector() {
        let r = root(
            &[
                "api/service-0".into(),
                "api/service-1".into(),
                "api/service-2".into(),
            ],
            &[1; 32],
            &[2; 32],
            &[3; 32],
        )
        .unwrap();
        assert_eq!(
            r.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "9c57710e1365ed2325f169c0cd464af63e495c6bc04ecae197a8a75de9665627"
        );
    }
    #[test]
    fn every_subset_size_and_service_is_bound_to_payee_token_network() {
        for n in 1..=MAX_SERVICES {
            let ids = (0..n)
                .map(|i| format!("api/service-{i}"))
                .collect::<Vec<_>>();
            let r = root(&ids, &[1; 32], &[2; 32], &[3; 32]).unwrap();
            let mut reverse = ids.clone();
            reverse.reverse();
            assert_eq!(Some(r), root(&reverse, &[1; 32], &[2; 32], &[3; 32]));
            for id in &ids {
                let s = service_hash(id).unwrap();
                let p = proof(&ids, id, &[1; 32], &[2; 32], &[3; 32]).unwrap();
                assert!(verify(&r, leaf(&[1; 32], &[2; 32], &[3; 32], &s), &p));
                for (network, mint, recipient) in [
                    ([9; 32], [2; 32], [3; 32]),
                    ([1; 32], [9; 32], [3; 32]),
                    ([1; 32], [2; 32], [9; 32]),
                ] {
                    assert!(!verify(&r, leaf(&network, &mint, &recipient, &s), &p));
                }
                assert!(!verify(
                    &r,
                    leaf(
                        &[1; 32],
                        &[2; 32],
                        &[3; 32],
                        &service_hash("other").unwrap()
                    ),
                    &p
                ));
            }
        }
    }
    #[test]
    fn empty_duplicates_invalid_and_oversized_fail_closed() {
        assert_eq!(root(&[], &[1; 32], &[2; 32], &[3; 32]), Some([0; 32]));
        assert!(!verify(&[0; 32], [0; 32], &[]));
        assert!(root(&["a".into(), "a".into()], &[1; 32], &[2; 32], &[3; 32]).is_none());
        assert!(root(
            &(0..9).map(|i| i.to_string()).collect::<Vec<_>>(),
            &[1; 32],
            &[2; 32],
            &[3; 32]
        )
        .is_none());
        for bad in ["", "a b", "a\n", "*", "а"] {
            assert!(service_hash(bad).is_none());
        }
        assert!(!verify(&[1; 32], [1; 32], &[[1; 32]; 4]));
    }
}
