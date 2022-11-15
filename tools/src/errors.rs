use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum DrawBridgeError {
    #[error("The file does not exist.")]
    DoesNoteExist,
    #[error("An underlying crypto error occurred.")]
    CryptoError,
    #[error("The provided path is invalid.")]
    InvalidPath,
    #[error("Ports must be between 1-65535.")]
    InvalidPort,
    #[error("IP address invalid, must be IPv4 or IPv6.")]
    InvalidIP,
    #[error("Could not determine source IP for interface.")]
    InvalidInterface,
    #[error("The provided number of bits is invalid.")]
    InvalidBits,
    #[error("An underlying network error occured.")]
    NetworkingError,
    #[error("The provided protocol is unsupported.")]
    UnsupportedProtocol,
    #[error("The provided algorithm is unsupported.")]
    UnsupportedAlgorithm,
    #[error("An underlying I/O error occured.")]
    Io(#[from] std::io::Error),
    #[error("The platform is out of memory.")]
    OutOfMemory,
    #[error("The provided private key is invalid.")]
    BadPrivateKey,
}
