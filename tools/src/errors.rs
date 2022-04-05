use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;
use std::error::Error;
/*
#[derive(Debug, Clone)]
pub enum CryptoError {
    IO(std::io::Error),
    BadPrivateKey,
    OOM,
}*/

#[allow(dead_code)]
#[derive(Debug)]
pub enum DrawBridgeError {
    DoesNoteExist,
    CryptoError,
    InvalidPath,
    InvalidPort,
    InvalidIP,
    InvalidInterface,
    InvalidBits,
    NetworkingError,
    UnsupportedProtocol,
    IO(std::io::Error),
    OutOfMemory,
    BadPrivateKey,
}

impl Display for DrawBridgeError {
    #[inline(always)]
    fn fmt(&self, f: &mut Formatter) -> Result {
        <DrawBridgeError as Debug>::fmt(self, f)
    }
}

impl Error for DrawBridgeError {}
