//! Server side of the quantum-resistant PSK exchange. The client sends one public key per KEM,
//! we encapsulate a fresh secret to each and XOR the secrets into the WireGuard PSK, exactly as
//! described in `proto/ephemeralpeer.proto`.

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::proto::KemPubkeyV1;

pub struct Encapsulated {
    pub ciphertexts: Vec<Vec<u8>>,
    pub psk: Zeroizing<[u8; 32]>,
}

pub fn encapsulate_all(pubkeys: &[KemPubkeyV1]) -> Result<Encapsulated> {
    if pubkeys.is_empty() {
        bail!("post-quantum request without KEM public keys");
    }
    let mut psk = Zeroizing::new([0u8; 32]);
    let mut ciphertexts = Vec::with_capacity(pubkeys.len());
    for key in pubkeys {
        let (ciphertext, secret) = match key.algorithm_name.as_str() {
            "ML-KEM-1024" => ml_kem_1024(&key.key_data)?,
            "HQC-256" => hqc_256(&key.key_data)?,
            other => bail!("unsupported KEM algorithm {other}"),
        };
        for (p, s) in psk.iter_mut().zip(secret.iter()) {
            *p ^= s;
        }
        ciphertexts.push(ciphertext);
    }
    Ok(Encapsulated { ciphertexts, psk })
}

fn ml_kem_1024(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, kem::Encapsulate};
    type EncapsulationKey = <MlKem1024 as KemCore>::EncapsulationKey;

    let encoded = <Encoded<EncapsulationKey>>::try_from(public_key)
        .ok()
        .context("ML-KEM-1024 public key has the wrong length")?;
    let key = EncapsulationKey::from_bytes(&encoded);
    let (ciphertext, secret) = key
        .encapsulate(&mut rand_core::OsRng)
        .map_err(|_| anyhow::anyhow!("ML-KEM-1024 encapsulation failed"))?;
    Ok((ciphertext.to_vec(), Zeroizing::new(secret.into())))
}

fn hqc_256(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    use pqcrypto_hqc::hqc256;
    use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
    use sha2::{Digest, Sha256};

    let key = hqc256::PublicKey::from_bytes(public_key)
        .ok()
        .context("HQC-256 public key has the wrong length")?;
    let (secret, ciphertext) = hqc256::encapsulate(&key);
    // KEM outputs that are not 32 bytes are hashed to 32 bytes (see the proto file).
    let secret = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(secret.as_bytes())));
    Ok((ciphertext.as_bytes().to_vec(), secret))
}
