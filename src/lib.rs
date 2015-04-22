#![feature(plugin)]
#![feature(custom_attribute)]
#![plugin(postgres_extension)]
#![feature(libc)]
#![feature(core)]
#![allow(plugin_as_library)]
#[macro_use] extern crate postgres_extension;
extern crate vault;
extern crate libc;
extern crate rustc_serialize;

use std::env;
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::mem;
use std::path::Path;
use std::ptr;
use std::raw::Slice;
use std::string::String;

use libc::{c_int, size_t};

use rustc_serialize::json;
use rustc_serialize::json::DecodeResult;

use postgres_extension::*;
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
    let auth = read_vault_creds();
    log_key_and_data(pg_key_name, pg_data);

    let key_name = string_from_pg_text(pg_key_name);
    let data_bytes = bytes_from_pg_bytes(pg_data);

    let mut client: AzureVault = Vault::new(&auth.vault_name[..], &auth.client_id[..], &auth.secret[..]);
    let encrypt_result = client.encrypt(&key_name[..], data_bytes);
    let encrypted_string = match encrypt_result {
        Ok(bits) => bits,
        Err(why) => panic!("failed to encrypt with key: {} {}", key_name, Error::description(&why))
    };

    let mut into_bytes = encrypted_string.into_bytes();
    let mut mut_encrypted = &mut into_bytes[..];
    let pg_result = build_pg_data(mut_encrypted);

    // log_to_file(format!("string: {}\n", key_name));
    // log_to_file(format!("raw_bytes: {:?}\n", data_bytes));
    unsafe {
        log_to_file(format!("upper pg_result: {:?}\n", (*pg_result)));
    };

    return pg_result;
}


#[pg_export]
pub fn decrypt(pg_key_name: *mut Text, pg_data: *mut Bytea) -> *mut Bytea {
    let auth = read_vault_creds();
    log_key_and_data(pg_key_name, pg_data);

    let key_name = string_from_pg_text(pg_key_name);
    let data_bytes = bytes_from_pg_bytes(pg_data);

    let mut client: AzureVault = Vault::new(&auth.vault_name[..], &auth.client_id[..], &auth.secret[..]);
    let decrypt_result = client.decrypt(&key_name[..], data_bytes);
    let decrypted_string = match decrypt_result {
        Ok(bits) => bits,
        Err(why) => panic!("failed to decrypt with key: {} {}", key_name, Error::description(&why))
    };

    let mut into_bytes = decrypted_string.into_bytes();
    let mut mut_decrypted = &mut into_bytes[..];
    let pg_result = build_pg_data(mut_decrypted);

    // log_to_file(format!("string: {}\n", key_name));
    // log_to_file(format!("raw_bytes: {:?}\n", data_bytes));
    unsafe {
        log_to_file(format!("upper pg_result: {:?}\n", (*pg_result)));
    };

    return pg_result;
}

fn build_pg_data(bytes: &mut [u8]) -> *mut Bytea{
    let pg_bytes = unsafe {
        let total_len = bytes.len() + 4;
        let pg_bytes = pg_malloc(total_len as size_t) as *mut Bytea;
        ptr::write_bytes(pg_bytes, 0, total_len as usize);
        (*pg_bytes).p.len = (total_len as u32) << 2;
        ptr::copy(bytes.as_mut_ptr(), (*pg_bytes).p.data.as_mut_ptr(), bytes.len());

        log_to_file(format!("the pg_bytes data... {:?}\n", (*pg_bytes)));
        log_to_file(format!("the bytes data... {:?}\n", bytes.len()));
        pg_bytes
    };

    return pg_bytes;
}

fn log_key_and_data(pg_key_name: *mut Text, pg_data: *mut Bytea) {
    unsafe {
        log_to_file(format!("the key data... {:?}\n", (*pg_key_name)));
        log_to_file(format!("the msg data... {:?}\n", (*pg_data)));
    };
}

fn read_vault_creds() -> VaultAuth {
    let mut path_buf = env::current_dir().unwrap();
    path_buf.push("vault");
    path_buf.set_extension("json");
    let path = path_buf.as_path();
    let display = path.display();

    let mut s = String::new();
    {
        // log_to_file(format!("I'm starting...\n"));
        // Open the path in read-only mode, returns `io::Result<File>`
        let mut file = match File::open(&path) {
            // The `description` method of `io::Error` returns a string that
            // describes the error
            Err(why) => {
                log_to_file(format!("couldn't open {}: {}\n", display, why));
                panic!("couldn't open {}: {}", display, why)
            },
            Ok(file) => file,
        };

        // Read the file contents into a string, returns `io::Result<usize>`
        match file.read_to_string(&mut s) {
            Err(why) => {
                log_to_file(format!("couldn't read {}: {}\n", display, why));
                panic!("couldn't read {}: {}", display, why)
            },
            Ok(_) => print!("{} contains:\n{}", display, s),
        };
    }

    // log_to_file(format!("json read 1: {}", s));
    // log_to_file(format!("I'm decoding...\n"));
    let auth_result: DecodeResult<VaultAuth> = json::decode(&s[..]);
    match auth_result {
        Ok(auth) => auth,
        Err(why) => {
            // log_to_file(format!("json read 2: {}\n", s));
            log_to_file(format!("error: {:?}\n", why));
            log_to_file(format!("bad format for vault.json: {}\n", why));
            panic!("bad format for vault.json: {}", why)
        }
    }
}

fn string_from_pg_text(pg_text: *mut Text) -> String{
    let string = unsafe {
        let total_len = (*pg_text).p.len as u64;
        let data_size = total_len - 20; // determined from observation of min struct size
        let ptr = (*pg_text).p.data.as_mut_ptr();
        String::from_raw_parts(ptr, (data_size/4 + 1) as usize, (data_size/4 + 1) as usize)
    };
    return string;
}

fn bytes_from_pg_bytes<'a>(pg_bytes: *mut Bytea) -> &'a [u8]{
    let some_bytes: &[u8] = unsafe {
        let total_len = (*pg_bytes).p.len as u64;
        let data_size = total_len - 20; // determined from observation of min struct size
        let ptr = (*pg_bytes).p.data.as_mut_ptr();
        let raw_bytes: Slice<u8> = Slice {
            data: ptr,
            len: (data_size/4 + 1) as usize
        };
        mem::transmute(raw_bytes)
    };
    return some_bytes;
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
