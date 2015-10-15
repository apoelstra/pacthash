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

//! # PactHash
//!
//! This is a rewrite of Matt Corallo's compacthashtool in Rust, designed to be
//! API compatible.
//!

#![crate_name = "pacthash"]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

#[cfg(not(test))]
use std::env;

extern crate bitcoin;
extern crate getopts;
extern crate rand;
extern crate rustc_serialize as serialize;
extern crate secp256k1;

use bitcoin::blockdata::script::Script;
use bitcoin::network::constants::Network;
use bitcoin::util::address::{Privkey, Address};
use bitcoin::util::base58::{FromBase58, ToBase58};
use bitcoin::util::contracthash::{tweak_keys, tweak_secret_key, untemplate};
use rand::{Rng, OsRng};
use secp256k1::Secp256k1;
use serialize::hex::FromHex;

use contract::{Contract, Nonce};

#[macro_use] pub mod macros;
pub mod contract;

/// Modes that the program can run in
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Generate a redeem script and corresponding P2SH address
    GenAddress,
    /// Generate a private key
    GenPrivkey
}

#[cfg(not(test))]
fn main() {
    let prog = env::args().next().unwrap();
    let args: Vec<_> = env::args().skip(1).collect();
    let mut rng = OsRng::new().unwrap(); // panic immediately if we can't get a RNG

    // Parse options
    let mut opts = getopts::Options::new();
    opts.optflag("c", "gen-address", "Generate a redemption script and corresponding address");
    opts.optflag("g", "gen-privkey", "Generate a private key");
    opts.optopt("r", "redeem-script", "Specify a hex-encode redemption script for -g mode.", "redemption script");
    opts.optopt("p", "private-key", "Specify a base58-encoded private key for -c mode.", "redemption script");
    opts.optopt("d", "p2sh-address", "Specify a contract as a P2SH address.", "P2SH address");
    opts.optopt("a", "ascii-contract", "Specify a contract as an ASCII string.", "text");
    opts.optopt("f", "hex-contract", "Specify a contract as an hexadecimal string.", "hex");
    opts.optopt("n", "nonce", "Specify a hex-encoded nonce.", "nonce");
    opts.optflag("h", "help", "Print this help message and exit.");
    opts.optflag("t", "testnet", "Set the tool to testnet mode (defaults to main)");

    let short_usage = format!("{} [-t] <-c|-g> <-f contract|-d p2sh -n nonce|-a ascii -n nonce>", prog);
    let full_usage = opts.usage(&short_usage);

    let matches = match opts.parse(&args[..]) {
        Ok(m) => m,
        Err(e) => {
            println!("Argument error: {}", e);
            println!("{}", full_usage);
            return;
        }
    };

    if matches.opt_present("h") {
        println!("{}", full_usage);
        return;
    }

    // ** Validate command-line options **
    let network = if matches.opt_present("t") { Network::Testnet } else { Network::Bitcoin };

    // Mode
    let mode = match (matches.opt_present("c"), matches.opt_present("g")) {
        (false, false) => {
            println!("One of -g or -c must be specified.");
            println!("{}", full_usage);
            return;
        }
        (true, true) => {
            println!("At most one of -g or -c may be specified.");
            println!("{}", full_usage);
            return;
        }
        (true, false) => Mode::GenPrivkey,
        (false, true) => Mode::GenAddress,
    };

    // Redeem script (required for -g, not allowed for -c)
    let redeem_script = match (mode, matches.opt_str("r")) {
        (Mode::GenAddress, Some(x)) => {
            match x.from_hex() {
                Ok(data) => Some(Script::from(data)),
                Err(e) => {
                    println!("option to -r could not be parsed as hex: {}.", e);
                    return;
                }
            }
        }
        (Mode::GenAddress, None) => {
            println!("-r must be specified in -g mode.");
            println!("{}", full_usage);
            return;
        }
        (Mode::GenPrivkey, None) => None,
        (Mode::GenPrivkey, Some(_)) => {
            println!("-r may only be used in -g mode.");
            println!("{}", full_usage);
            return;
        }
    };

    // Privkey (required for -c, not allowed for -g)
    let private_key = match (mode, matches.opt_str("p")) {
        (Mode::GenPrivkey, Some(x)) => {
            let decode: Result<Privkey, _> = FromBase58::from_base58check(&x[..]);
            match decode {
                Ok(key) => {
                    if key.network != network {
                        println!("Private key network did not match tool mode (did you forget -t?).");
                        return;
                    }
                    Some(key)
                }
                Err(e) => {
                    println!("option to -p could not be parsed as a private key: {:?}.", e);
                    return;
                }
            }
        }
        (Mode::GenPrivkey, None) => {
            println!("-p must be specified in -c mode.");
            println!("{}", full_usage);
            return;
        }
        (Mode::GenAddress, None) => None,
        (Mode::GenAddress, Some(_)) => {
            println!("-p may only be used in -c mode.");
            println!("{}", full_usage);
            return;
        }
    };

    // mode, full contract, nonce, p2sh-address contract, ascii contract
    let contract = match (mode, matches.opt_str("f"), matches.opt_str("n"), matches.opt_str("d"), matches.opt_str("a")) {
        // Full contract obviates everything else
        (_, Some(hex), None, None, None) => {
            match Contract::from_hex(&hex) {
                Ok(data) => data,
                Err(e) => {
                    println!("option to -f could not be parsed as a contract: {:?}.", e);
                    return;
                }
            }
        }
        // P2SH requires a nonce, but in generate mode we may make one
        (mode, None, nonce, Some(hex), None) => {
            if mode == Mode::GenPrivkey && nonce.is_none() {
                println!("-n is required when using -c and -d");
                println!("{}", full_usage);
                return;
            }
            // Now we know if we're missing a nonce we're allowed to generate it
            let nonce = match nonce {
                Some(hex) => {
                    match Nonce::from_hex(&hex) {
                        Ok(data) => data,
                        Err(e) => {
                            println!("option to -n could not be parsed as a nonce: {:?}.", e);
                            return;
                        }
                    }
                }
                None => rng.gen()
            };
            match Contract::from_p2sh_base58_str(&hex, nonce, network) {
                Ok(contract) => contract,
                Err(e) => {
                    println!("option to -d could not be parsed as a P2SH contract: {:?}.", e);
                    return;
                }
            }
        }
        // ASCII requires a nonce, but in generate mode we may make one
        (mode, None, nonce, None, Some(ascii)) => {
            if mode == Mode::GenPrivkey && nonce.is_none() {
                println!("-n is required when using -c and -a");
                println!("{}", full_usage);
                return;
            }
            // Now we know if we're missing a nonce we're allowed to generate it
            let nonce = match nonce {
                Some(hex) => {
                    match Nonce::from_hex(&hex) {
                        Ok(data) => data,
                        Err(e) => {
                            println!("option to -n could not be parsed as a nonce: {:?}.", e);
                            return;
                        }
                    }
                }
                None => rng.gen()
            };
            match Contract::from_ascii_str(&ascii, nonce) {
                Ok(contract) => contract,
                Err(e) => {
                    println!("option to -a could not be parsed as a contract: {:?}.", e);
                    return;
                }
            }
        }
        // Every other usage is illegal
        _ => {
            println!("Must specify exactly one of: -f; -a -n; or -d -n");
            println!("{}", full_usage);
            return;
        }
    };

    // OKAY. At this point we have actually parsed everything and can be assured that we have what we need.
    // ** Actual program starts now **
    let secp = Secp256k1::new();
    match mode {
        Mode::GenAddress => {
            let redeem_script = redeem_script.unwrap();

            match untemplate(&redeem_script) {
                Ok((template, keys)) => {
                    let keys = match tweak_keys(&secp, &keys, &contract.serialize()[..]) {
                        Ok(keys) => keys,
                        Err(e) => {
                            println!("Unable to tweak keys: {:?}", e);
                            return;
                        }
                    };
                    let new_script = match template.to_script(&keys) {
                        Ok(script) => script,
                        Err(e) => {
                            println!("Unable to put tweaked keys back into the redemption script: {:?}", e);
                            return;
                        }
                    };
                    match network {
                        Network::Bitcoin => println!("Using mainnet!"),
                        Network::Testnet => println!("Using testnet!"),
                    }
                    println!("Nonce: {:x}", Nonce::from_contract(&contract));
                    println!("Modified redeem script: {:x}", new_script);
                    println!("Modified redeem script as P2SH address: {}", Address::from_script(network, &new_script).to_base58check());
                }
                Err(e) => {
                    println!("Unable to extract keys from redemption script: {:?}", e);
                    return;
                }
            }
        }
        Mode::GenPrivkey => {
            let private_key = private_key.unwrap();

            // Compute tweaked key
            let tweaked_key = match tweak_secret_key(&secp, &private_key.key, &contract.serialize()[..]) {
                Ok(key) => key,
                Err(e) => {
                    println!("Failed to tweak private key: {:?}", e);
                    return;
                }
            };
            // Turn it into a WIF privkey
            let tweaked_privkey = Privkey {
                compressed: true,
                network: network,
                key: tweaked_key
            };

            match network {
                Network::Bitcoin => println!("Using mainnet!"),
                Network::Testnet => println!("Using testnet!"),
            }
            println!("New secret key: {}", tweaked_privkey.to_base58check());
        }
    }
}



