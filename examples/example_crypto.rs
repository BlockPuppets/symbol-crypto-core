use symbol_crypto_core::{Keypair, KeyPairSchema, Nis1, Sym};

fn main() {
    let sender_pk = "E1C8521608F4896CA26A0C2DE739310EA4B06861D126CF4D6922064678A1969B";
    let recipient_key = "A22A4BBF126A2D7D7ECE823174DFD184C5DE0FDE4CB2075D30CFA409F7EF8908";

    let msg = b"Nem is awesome from Rust!";

    println!("Encrypt/Decrypt from Symbol.");
    encrypt_decrypt::<Sym>(sender_pk, recipient_key, msg);

    println!("Encrypt/Decrypt from Nis1.");
    encrypt_decrypt::<Nis1>(sender_pk, recipient_key, msg);
}

fn encrypt_decrypt<S: KeyPairSchema>(sender_pk: &str, recipient_key: &str, msg: &[u8]) {
    let sender_keypair = Keypair::<S>::from_hex_private_key(sender_pk).unwrap();
    println!("sender_keypair: {}", sender_keypair);

    let recipient_keypair = Keypair::<S>::from_hex_private_key(recipient_key).unwrap();
    println!("recipient_keypair: {}", recipient_keypair);

    let encrypt_msg = sender_keypair
        .encrypt_message(&recipient_keypair.public_key().to_fixed_bytes(), msg)
        .unwrap();

    println!("encrypt_text: {}", hex::encode(&encrypt_msg));

    let decrypt_msg = recipient_keypair
        .decrypt_message(&sender_keypair.public_key().to_fixed_bytes(), &encrypt_msg)
        .unwrap();

    println!(
        "decrypt_message: {}\n",
        String::from_utf8(decrypt_msg).unwrap()
    );
}
