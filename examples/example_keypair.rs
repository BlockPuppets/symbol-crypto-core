use std::str::FromStr;

use symbol_crypto_core::{Keypair, Nis1, PrivateKey, Sym};

fn main() {
    let private_key_hex: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    let private_key = PrivateKey::from_str(private_key_hex).unwrap();
    println!("private_key: {:x}", private_key);

    let keypair_one_sym = Keypair::<Sym>::random();
    println!("sym random: {}", keypair_one_sym);

    let keypair_two_sym = Keypair::<Sym>::from_hex_private_key(private_key_hex).unwrap();
    println!("sym from_private_key_hex: {}", keypair_two_sym);

    let keypair_two_sym = Keypair::<Sym>::from_private_key(private_key);
    println!("sym from_private_key: {}\n", keypair_two_sym);

    let keypair_one_nis1 = Keypair::<Nis1>::random();
    println!("nis1 random: {}", keypair_one_nis1);

    let keypair_two_nis1 = Keypair::<Nis1>::from_hex_private_key(private_key_hex).unwrap();
    println!("nis1 from_private_key_hex: {}", keypair_two_nis1);

    let keypair_two_nis1 = Keypair::<Nis1>::from_private_key(private_key);
    println!("nis1 from_private_key: {}", keypair_two_nis1);
}
