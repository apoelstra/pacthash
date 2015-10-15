// PactHash
// Written in 2015 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Contracts
//! Support for Elements Alpha contracts
//!

use bitcoin::network::constants::Network;
use bitcoin::util::address::{self, Address};
use bitcoin::util::base58::{self, FromBase58};
use serialize::hex::{self, FromHex};

use std::fmt;

/// Total length of a contract in bytes
pub const CONTRACT_LEN: usize = 40;
/// Length of the data portion of the contract in bytes
pub const DATA_LEN: usize = 20;

/// Type of contract encoding
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Type {
    /// Plain text
    Text,
    /// Pay-to-pubkeyhash Bitcoin script
    PubkeyHash,
    /// P2SH Bitcoin script
    ScriptHash
}

impl Type {
    /// Serialize the type in a way that can be used for contracthash key tweaking
    pub fn serialize(&self) -> &'static [u8; 4] {
        match *self {
            Type::Text => b"TEXT",
            Type::PubkeyHash => b"P2PH",
            Type::ScriptHash => b"P2SH"
        }
    }

    /// Interpret a 4-byte sequence as a type
    pub fn deserialize(data: &[u8]) -> Result<Type, Error> {
        match data {
            b"TEXT" => Ok(Type::Text),
            b"P2PH" => Ok(Type::PubkeyHash),
            b"P2SH" => Ok(Type::ScriptHash),
            x => Err(Error::BadType(x.to_owned()))
        }
    }
}

/// Nonce length in bytes
pub const NONCE_LEN: usize = 16;
/// Nonce
pub struct Nonce([u8; NONCE_LEN]);
impl_array_newtype!(Nonce, u8, NONCE_LEN);

impl Nonce {
    /// Serialize the contract in a way that can be used for contracthash key tweaking
    #[inline]
    pub fn serialize(&self) -> Vec<u8> {
        self[..].to_owned()
    }

    /// Decode a hex string as a Nonce
    pub fn from_hex(data: &str) -> Result<Nonce, Error> {
        let bytes = try!(data.from_hex().map_err(Error::Hex));
        if bytes.len() != NONCE_LEN {
            return Err(Error::BadLength(bytes.len()));
        }
        unsafe {
            use std::{mem, ptr};
            let mut ret: [u8; NONCE_LEN] = mem::uninitialized();
            ptr::copy_nonoverlapping(bytes.as_ptr(), ret.as_mut_ptr(), NONCE_LEN);
            Ok(Nonce(ret))
        }
    }

    /// Parse a Nonce out of a contract
    pub fn from_contract(contract: &Contract) -> Nonce {
        contract.nonce
    }
}

impl fmt::LowerHex for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            try!(write!(f, "{:02x}", *ch));
        }
        Ok(())
    }
}

/// Contract
#[derive(Clone, PartialEq, Eq)]
pub struct Contract {
    ty: Type,
    nonce: Nonce,
    data: Vec<u8>
}

/// Contract-related error
#[derive(Clone, Debug)]
pub enum Error {
    /// Base58 decoding error
    Base58(base58::Error),
    /// Hex decoding error
    Hex(hex::FromHexError),
    /// Network did not match our expectation (got, expected)
    WrongNetwork(Network, Network),
    /// Contract was invalid length
    BadLength(usize),
    /// Unknown contract type
    BadType(Vec<u8>)
}

impl Contract {
    /// Serialize the contract in a way that can be used for contracthash key tweaking
    pub fn serialize(&self) -> Vec<u8> {
        let ty = self.ty.serialize();
        let mut ret = Vec::with_capacity(ty.len() + self.nonce.len() + self.data.len());
        ret.extend(&ty[..]);
        ret.extend(&self.nonce[..]);
        ret.extend(&self.data[..]);
        ret
    }

    /// Decode a hex string as a contract
    pub fn from_hex(data: &str) -> Result<Contract, Error> {
        let bytes = try!(data.from_hex().map_err(Error::Hex));
        if bytes.len() != CONTRACT_LEN {
            return Err(Error::BadLength(bytes.len()));
        }
        let ty = try!(Type::deserialize(&bytes[0..4]));

        Ok(Contract {
            ty: ty,
            nonce: Nonce::from(&bytes[4..20]),
            data: bytes[20..].to_owned()
        })
    }

    /// Decode a P2SH address as a contract
    pub fn from_p2sh_base58_str(s: &str, nonce: Nonce, expected_network: Network) -> Result<Contract, Error> {
        let addr: Address = try!(FromBase58::from_base58check(s).map_err(Error::Base58));
        if addr.network != expected_network {
            return Err(Error::WrongNetwork(addr.network, expected_network));
        }
        Ok(Contract {
            ty: match addr.ty {
                address::Type::PubkeyHash => Type::PubkeyHash,
                address::Type::ScriptHash => Type::ScriptHash
            },
            nonce: nonce,
            data: addr.hash[..].to_owned()
        })
    }

    /// Decode an ASCII string as a contract
    pub fn from_ascii_str(s: &str, nonce: Nonce) -> Result<Contract, Error> {
        let bytes = s.as_bytes();
        if bytes.len() != DATA_LEN {
            Err(Error::BadLength(bytes.len()))
        } else {
            Ok(Contract {
                ty: Type::Text,
                nonce: nonce,
                data: bytes.to_owned()
            })
        }
    }
}

