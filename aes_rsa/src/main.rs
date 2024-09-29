use std::fs::File;
use std::io::{Read, Write};
use std::env;

use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use aes_gcm_siv::aead::{Aead, OsRng};


fn main() {

    // Read the file to be encrypted
    //let mut file = File::open("pic.jpg").unwrap();
    let args: Vec<String> = env::args().collect();

    if args.len() < 1 {
        println!("Usage: {} <filename path>", args[0]);
    }
    let mut file = File::open(&args[1]).unwrap();
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext).unwrap();

    //generate a random key and nonce for AES-GCM-SIV
    let key = Aes256GcmSiv::generate_key(&mut OsRng);
    //generate a random nonce of 12 bytes (96 bits)
    let nonce = Nonce::from_slice(&[0; 12]);

    //generate an RSA key pair
    let mut rng = rand::thread_rng();
    let bits = 4096;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);


    //encrypt the AES key using the RSA public key
    let padding = Oaep::new::<sha2::Sha256>();
    let encrypted_key = public_key.encrypt(&mut rng, padding, &key).unwrap();

    //write the encrypted key to a file
    let mut encrypted_aes_key = File::create("aes_key.encrypted").unwrap();
    encrypted_aes_key.write_all(&encrypted_key).unwrap();

    //encrypt the plaintext using aes-gcm-siv mode
    let ciphertext = Aes256GcmSiv::new(&key).encrypt(&nonce, plaintext.as_ref()).unwrap();

    //write the encrypted data to a file
    let mut output = File::create("Crynow.encrypted").unwrap();
    output.write_all(&ciphertext).unwrap();

}


