use crate::errors::DrawBridgeError::*;
use openssl::rsa::Rsa;
use ring::{digest, rand, signature};
use std::error::Error;
use std::io::{Read, Write};

/**
 * Private method to read in a file
 */
fn read_file(path: &std::path::Path) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = std::fs::File::open(path).map_err(|e| Io(e))?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| Io(e))?;
    Ok(contents)
}

/**
 * Private method to write to a file
 */
fn write_file(contents: Vec<u8>, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    let mut file = std::fs::File::create(path).map_err(|e| Io(e))?;
    file.write_all(&contents).map_err(|e| Io(e))?;
    Ok(())
}

/**
 * Private method to convert a DER public key
 * to a C header
 */
fn public_key_to_c_header(contents: &Vec<u8>) -> String {
    let mut res = String::from("void * public_key = \n\"");
    let mut count = 1;
    for i in contents[24..].iter() {
        res.push_str("\\x");
        res.push_str(format!("{:02X}", i).as_str());
        if count % 16 == 0 {
            res.push_str("\"\n\"");
            count = 0;
        }
        count += 1;
    }
    res.push_str("\";\n");
    return res;
}

/**
 * Generate a SHA256 digest
 */
pub fn sha256_digest<'a>(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let res = digest::digest(&digest::SHA256, data);
    return Ok(res.as_ref().to_vec());
}

/**
 * Sign data with an RSA private key
 */
pub fn sign_rsa<'a>(
    data: &[u8],
    private_key_path: &std::path::Path,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Create an `RsaKeyPair` from the DER-encoded bytes.
    let private_key_der = read_file(private_key_path)?;
    let key_pair = signature::RsaKeyPair::from_der(&private_key_der).map_err(|_| BadPrivateKey)?;

    // Sign the data, using PKCS#1 v1.5 padding and the SHA256 digest
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public_modulus_len()];
    key_pair
        .sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut signature)
        .map_err(|_| OutOfMemory)?;

    return Ok(signature);
}

/**
 * Generate a new RSA key pair
 *
 * Currently relies on openssl, because Ring hasn't
 * implemented RSA key generation yet
 */
pub fn gen_rsa(
    bits: u32,
    private_path: &std::path::Path,
    public_path: &std::path::Path,
) -> Result<(), Box<dyn Error>> {
    let key_path = std::path::Path::new("key.h");
    let rsa = Rsa::generate(bits).or(Err(CryptoError))?;

    let private = match rsa.private_key_to_der() {
        Ok(res) => res,
        Err(e) => {
            println!("[-] Could not convert private key to DER format: {}", e);
            return Err(CryptoError.into());
        }
    };

    let public = match rsa.public_key_to_der() {
        Ok(res) => res,
        Err(e) => {
            println!("[-] Could not convert public key to DER format: {}", e);
            return Err(CryptoError.into());
        }
    };

    // create the public key C-header for Drawbridge
    let mut header = public_key_to_c_header(&public);
    header.push_str(format!("\n#define KEY_LEN {}\n", public[24..].len()).as_str());

    // Write private key to file
    write_file(private, private_path)?;
    println!("\t[+] created {}", private_path.display());

    // Write public key to file
    write_file(public, public_path)?;
    println!("\t[+] created {}", public_path.display());

    // Write public key to file
    write_file(header.as_bytes().to_vec(), key_path)?;
    println!("\t[+] created ./key.h");

    Ok(())
}
