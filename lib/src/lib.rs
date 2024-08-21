use alloy_sol_types::sol;
use std::convert::TryFrom;
use rand::thread_rng;
use ed25519_consensus::*;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 n;
        uint32 a;
        uint32 b;
    }
}

fn sig_verify() {
    let msg = b"ed25519-consensus";

    // Signer's context
    let (vk_bytes, sig_bytes) = {
        // Generate a signing key and sign the message
        let sk = SigningKey::new(thread_rng());
        let sig = sk.sign(msg);

        // Types can be converted to raw byte arrays with From/Into
        let sig_bytes: [u8; 64] = sig.into();
        let vk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

        (vk_bytes, sig_bytes)
    };

    // Verify the signature
    assert!(
        VerificationKey::try_from(vk_bytes)
            .and_then(|vk| vk.verify(&sig_bytes.into(), msg))
            .is_ok()
    );
}

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    /*
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    */
    sig_verify();
    (a, b)
}
