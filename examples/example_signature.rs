use symbol_crypto_core::prelude::{KeyPairSchema, Keypair, KpNis1, KpSym};

fn main() {
    let data = b"NEM is awesome !";
    let private_key: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    println!("Sign/Verify from Symbol.");
    sign_verify::<KpSym>(private_key, data);

    println!("Sign/Verify from Nis1.");
    sign_verify::<KpNis1>(private_key, data)
}

fn sign_verify<S: KeyPairSchema>(private_key: &str, data: &[u8]) {
    let keypair = Keypair::<S>::from_hex_private_key(private_key).unwrap();
    println!("keypair: {}", keypair);

    let sign_sym = keypair.sign(data);
    println!("signature: {:x}", sign_sym);

    let verify_sym = keypair.verify(data, sign_sym);
    println!("verify: {:?}\n", verify_sym);
}
