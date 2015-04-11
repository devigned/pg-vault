#![feature(plugin)]
#![feature(custom_attribute)]
#![plugin(postgres_extension)]
#![feature(libc)]
#[macro_use] extern crate postgres_extension;
extern crate vault;
extern crate libc;
extern crate rustc_serialize;

use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::Path;
use std::slice;
use std::str;

use libc::{c_int};

use rustc_serialize::json;
use rustc_serialize::json::DecodeResult;
use rustc_serialize::Decodable;

use postgres_extension::{Text, Bytea, Varlena, PgConvert};
use vault::http::client::{Vault, AzureVault};

pg_module!(version: 90400);

#[derive(RustcEncodable, RustcDecodable, Debug, Clone, PartialEq)]
pub struct VaultAuth {
  pub vault_name: String,
  pub client_id: String,
  pub secret: String
}


#[pg_export]
pub fn encrypt(pg_key_name: *mut Text, pg_data: *mut Bytea) -> *mut Bytea {
    let path = Path::new("vault.json");
    let display = path.display();

    log_to_file(format!("I'm starting...\n"));
    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => {
            log_to_file(format!("couldn't open {}: {}", display,Error::description(&why)));
            panic!("couldn't open {}: {}", display,Error::description(&why))
        },
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => {
            log_to_file(format!("couldn't read {}: {}", display, Error::description(&why)));
            panic!("couldn't read {}: {}", display, Error::description(&why))
        },
        Ok(_) => print!("{} contains:\n{}", display, s),
    }

    log_to_file(format!("I'm decoding...\n"));
    let auth_result: DecodeResult<VaultAuth> = json::decode(&s[..]);
    let auth = match auth_result {
        Ok(auth) => auth,
        Err(why) => {
            log_to_file(format!("json read: {}", s));
            log_to_file(format!("bad format for vault.json: {}", Error::description(&why)));
            panic!("bad format for vault.json: {}", Error::description(&why))
        }
    };

    unsafe{
        log_to_file(format!("First unsafe...\n"));
        log_to_file(format!("the key data... {:?}\n", (*pg_key_name).p.to_string()));

        log_to_file(format!("Second unsafe...\n"));
        log_to_file(format!("the msg data... {:?}\n", (*pg_data).p.to_string()));
    }

    // let mut client: AzureVault = Vault::new(&auth.vault_name[..], &auth.client_id[..], &auth.secret[..]);
    // let encrypt_result = client.encrypt(key_name, data);
    // let encrypted = match encrypt_result {
    //     Ok(bits) => bits,
    //     Err(why) => panic!("failed to encrypt with key: {} {}", key_name, Error::description(&why))
    // };


    //log_to_file(format!("Returning...\n"));

    return pg_data;
}

#[pg_export]
pub fn decrypt(key_name: *mut Text, data: *mut Bytea) -> *mut Bytea {
    let path = Path::new("vault.json");
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                                                   Error::description(&why)),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display,
                                                   Error::description(&why)),
        Ok(_) => print!("{} contains:\n{}", display, s),
    }


    data
}


fn log_to_file(text: String){
    let path = Path::new("test.txt");
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match OpenOptions::new().write(true).create(true).append(true).open("test.txt") {
        Err(why) => panic!("couldn't create {}: {}",
                           display,
                           Error::description(&why)),
        Ok(file) => file,
    };

    // Write the `LOREM_IPSUM` string to `file`, returns `io::Result<()>`
    match file.write_all(text.as_bytes()) {
        Err(why) => {
            panic!("couldn't write to {}: {}", display,
                                               Error::description(&why))
        },
        Ok(_) => println!("successfully wrote to {}", display),
    }
}


#[pg_export]
pub fn is_zero(a: c_int) -> c_int {
    if a == 0 {
        5
    } else {
        41
    }
}

// pub struct Varlena {
//     len: [i8; 4],
//     data: *mut i8
// }
