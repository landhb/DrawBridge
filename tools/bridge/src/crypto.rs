use ring::{rand, signature,digest};


#[derive(Debug)]
//#[derive(Fail, Debug)]
pub enum CryptoError {
   IO(std::io::Error),
   BadPrivateKey,
   OOM,
   //BadSignature,
}


// crypto callback prototype, can be used to implement multiple types in the future
//type GenericSignMethod = fn(data: &mut [u8], private_key_path: &std::path::Path) -> Result<Vec<u8>, CryptoError>;


fn read_file(path: &std::path::Path) -> Result<Vec<u8>, CryptoError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| CryptoError::IO(e))?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents).map_err(|e| CryptoError::IO(e))?;
    Ok(contents)
}


pub fn sha256_digest<'a>(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let res = digest::digest(&digest::SHA256, data);
    return Ok(res.as_ref().to_vec());
}

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



