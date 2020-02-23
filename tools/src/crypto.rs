use failure::{Error,bail};
use ring::{rand, signature,digest};
use openssl::rsa::Rsa;
use std::io::{Read,Write};

#[derive(Debug)]
pub enum CryptoError {
   IO(std::io::Error),
   BadPrivateKey,
   OOM,
}


// crypto callback prototype, can be used to implement multiple types in the future
//type GenericSignMethod = fn(data: &mut [u8], private_key_path: &std::path::Path) -> Result<Vec<u8>, CryptoError>;

/**
 * Private method to read in a file
 */
fn read_file(path: &std::path::Path) -> Result<Vec<u8>, CryptoError> {
    let mut file = std::fs::File::open(path).map_err(|e| CryptoError::IO(e))?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| CryptoError::IO(e))?;
    Ok(contents)
}

/**
 * Public method to write to a file
 */
fn write_file(contents: Vec<u8>, path: &std::path::Path) -> Result<(), CryptoError> {
    let mut file = std::fs::File::create(path).map_err(|e| CryptoError::IO(e))?;
    file.write_all(&contents).map_err(|e| CryptoError::IO(e))?;
    Ok(())
}

/**
 * Generate a SHA256 digest
 */
pub fn sha256_digest<'a>(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let res = digest::digest(&digest::SHA256, data);
    return Ok(res.as_ref().to_vec());
}

/**
 * Sign data with an RSA private key
 */
pub fn sign_rsa<'a>(data: &[u8], private_key_path: &std::path::Path) 
                        -> Result<Vec<u8>, CryptoError> 
{
    // Create an `RsaKeyPair` from the DER-encoded bytes. 
    let private_key_der = read_file(private_key_path)?;
    let key_pair = signature::RsaKeyPair::from_der(&private_key_der).map_err(|_| CryptoError::BadPrivateKey)?;

    // Sign the data, using PKCS#1 v1.5 padding and the SHA256 digest 
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; key_pair.public_modulus_len()];
    key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, data, &mut signature).map_err(|_| CryptoError::OOM)?;

    return Ok(signature);
} 

/**
 * Generate a new RSA key pair
 *
 * Currently relies on openssl, because Ring hasn't
 * implemented RSA key generation yet
 */
pub fn gen_rsa(bits: u32, private_path: &std::path::Path, public_path: &std::path::Path) -> Result<(), Error> {
    
    let rsa = match Rsa::generate(bits) {
        Ok(key) => key,
        Err(e) => {bail!(e)},
    };

    let private = match rsa.private_key_to_der() {
        Ok(res) => res,
        Err(e) => {bail!("[-] Could not convert private key to DER format: {}", e)},
    };

    let public = match rsa.public_key_to_der() {
        Ok(res) => res,
        Err(e) => {bail!("[-] Could not convert public key to DER format: {}", e)},
    };

    // Write private key to file
    match write_file(private,private_path) {
        Ok(_res) => (),
        Err(e) => {bail!("[-] Could not write private key to file. {:?}",e)},
    }

    println!("\t[+] created {}",private_path.display());

    // Write public key to file
    match write_file(public,public_path) {
        Ok(_res) => (),
        Err(e) => {bail!("[-] Could not write public key to file. {:?}",e)},
    }

    println!("\t[+] created {}",public_path.display());
    Ok(())
}