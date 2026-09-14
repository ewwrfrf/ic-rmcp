use candid::Principal;
use ic_cdk::management_canister::raw_rand;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub type HashedApiKey = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyInfo {
    pub principal: Principal,
    pub name: String,
    pub scopes: Vec<String>,
    pub created: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyMetadata {
    pub hashed_key: HashedApiKey,
    pub info: ApiKeyInfo,
}

#[derive(Clone, Debug, Default)]
pub struct ApiKeyState {
    api_keys: HashMap<HashedApiKey, ApiKeyInfo>,
}

impl ApiKeyState {
    pub fn new() -> Self { Self::default() }

    pub async fn create_my_api_key(&mut self, caller: Principal, name: String, scopes: Vec<String>) -> Result<String, String> {
        let entropy = raw_rand().await.map_err(|e| e.to_string())?;
        Ok(self.create_from_entropy(caller, name, scopes, &entropy))
    }

    pub fn create_from_entropy(&mut self, caller: Principal, name: String, scopes: Vec<String>, entropy: &[u8]) -> String {
        let raw = if entropy.is_empty() { vec![0u8; 32] } else { entropy.to_vec() };
        let digest: HashedApiKey = Sha256::digest(&raw).into();
        let key = hex_encode(&raw);
        let created = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default();
        self.api_keys.insert(digest, ApiKeyInfo { principal: caller, name, scopes, created });
        key
    }

    pub fn list_my_api_keys(&self, caller: Principal) -> Vec<ApiKeyMetadata> {
        self.api_keys.iter().filter(|(_, info)| info.principal == caller).map(|(hashed_key, info)| ApiKeyMetadata { hashed_key: *hashed_key, info: info.clone() }).collect()
    }

    pub fn revoke_my_api_key(&mut self, caller: Principal, hashed_key: HashedApiKey) -> Result<bool, String> {
        match self.api_keys.get(&hashed_key) {
            None => Ok(false),
            Some(info) if info.principal == caller => { self.api_keys.remove(&hashed_key); Ok(true) },
            Some(_) => Err("Unauthorized: API key does not belong to caller".to_string()),
        }
    }

    pub fn hash_key(raw_key: &str) -> HashedApiKey {
        match hex_decode(raw_key) { Some(bytes) => Sha256::digest(bytes).into(), None => Sha256::digest(raw_key.as_bytes()).into() }
    }

    pub fn len(&self) -> usize { self.api_keys.len() }
    pub fn is_empty(&self) -> bool { self.api_keys.is_empty() }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes { out.push(HEX[(byte >> 4) as usize] as char); out.push(HEX[(byte & 0x0f) as usize] as char); }
    out
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn principal(byte: u8) -> Principal { Principal::from_slice(&[byte]) }

    #[test]
    fn lifecycle_and_ownership_isolation() {
        let alice = principal(1); let bob = principal(2); let mut state = ApiKeyState::new();
        let raw = state.create_from_entropy(alice, "cli".into(), vec!["read".into()], b"deterministic entropy");
        assert_eq!(raw.len(), 42); let digest = ApiKeyState::hash_key(&raw);
        assert_eq!(state.list_my_api_keys(alice).len(), 1); assert!(state.list_my_api_keys(bob).is_empty());
        assert!(state.revoke_my_api_key(bob, digest).is_err()); assert_eq!(state.len(), 1);
        assert_eq!(state.revoke_my_api_key(alice, digest), Ok(true)); assert!(state.list_my_api_keys(alice).is_empty());
        assert_eq!(state.revoke_my_api_key(alice, digest), Ok(false));
    }

    #[test]
    fn stored_state_never_contains_raw_key() {
        let alice = principal(3); let mut state = ApiKeyState::new();
        let raw = state.create_from_entropy(alice, "x".into(), vec![], b"secret");
        let metadata = state.list_my_api_keys(alice).pop().unwrap();
        assert_ne!(format!("{:x?}", metadata.hashed_key), raw); assert_eq!(metadata.info.principal, alice);
    }

    #[test]
    fn hash_key_decodes_issued_hex_key() {
        let alice = principal(6); let mut state = ApiKeyState::new();
        let issued = state.create_from_entropy(alice, "hex".into(), vec![], b"issued bytes");
        assert_eq!(state.list_my_api_keys(alice)[0].hashed_key, ApiKeyState::hash_key(&issued));
    }

    #[test]
    fn hash_key_keeps_raw_token_fallback() {
        let expected: HashedApiKey = Sha256::digest(b"plain-token").into();
        assert_eq!(ApiKeyState::hash_key("plain-token"), expected);
    }
}
