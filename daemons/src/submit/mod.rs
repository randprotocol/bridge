//! Where attestations go. A submitter reports one of three things: the
//! attestation landed, it had already landed (someone else relayed it — the
//! bridge is permissionless), or it failed and is worth another try.

pub mod evm;
pub mod process;
pub mod tron;

use bridge_codec::Attestation;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Outcome {
    /// Landed; the chain's own identifier for the transaction.
    Submitted(String),
    /// The destination had consumed this digest before we got there.
    AlreadyDone,
}

/// `abi.encode(bytes)`: what `release(bytes)` takes after its selector.
pub fn abi_encode_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + data.len().div_ceil(32) * 32);
    let mut word = [0u8; 32];
    word[31] = 0x20;
    out.extend_from_slice(&word);
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(data.len() as u64).to_be_bytes());
    out.extend_from_slice(&len);
    out.extend_from_slice(data);
    out.resize(64 + data.len().div_ceil(32) * 32, 0);
    out
}

pub fn selector(signature: &str) -> [u8; 4] {
    crate::crypto::keccak256(signature.as_bytes())[..4]
        .try_into()
        .expect("4")
}

/// `release(bytes)` calldata for an encoded attestation.
pub fn release_calldata(attestation: &Attestation) -> Vec<u8> {
    let mut data = selector("release(bytes)").to_vec();
    data.extend_from_slice(&abi_encode_bytes(&attestation.encode()));
    data
}

/// `consumed(bytes32)` calldata.
pub fn consumed_calldata(digest: &[u8; 32]) -> Vec<u8> {
    let mut data = selector("consumed(bytes32)").to_vec();
    data.extend_from_slice(digest);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_bytes_are_padded_to_a_word() {
        let enc = abi_encode_bytes(&[0xaa; 33]);
        assert_eq!(enc.len(), 32 + 32 + 64);
        assert_eq!(enc[31], 0x20);
        assert_eq!(enc[63], 33);
        assert_eq!(&enc[64..97], &[0xaa; 33]);
        assert!(enc[97..].iter().all(|b| *b == 0));
        assert_eq!(abi_encode_bytes(&[]).len(), 64);
    }

    #[test]
    fn selectors() {
        // cast sig "release(bytes)" / "consumed(bytes32)"
        assert_eq!(
            hex::encode(selector("transfer(address,uint256)")),
            "a9059cbb"
        );
    }
}
