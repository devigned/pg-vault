#![feature(plugin)]
#![feature(custom_attribute)]
#![plugin(postgres_extension)]
#![feature(libc)]
#![feature(core)]
#![allow(plugin_as_library)]
#[macro_use] extern crate postgres_extension;
#[macro_use] extern crate lazy_static;
extern crate vault;
extern crate libc;
extern crate rustc_serialize;

use std::collections::HashMap;
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
use std::sync::{Mutex};

use rustc_serialize::base64::FromBase64;

use libc::{c_int, size_t};

use rustc_serialize::json;
use rustc_serialize::json::DecodeResult;

use postgres_extension::*;
use vault::http::client::{Vault, AzureVault};

pg_module!(version: 90400);

lazy_static! {
    static ref CACHE: Mutex<HashMap<&'static str, VaultAuth>> =
        Mutex::new(HashMap::new());
}

#[derive(RustcEncodable, RustcDecodable, Debug, Clone, PartialEq)]
pub struct VaultAuth {
  pub vault_name: String,
  pub client_id: String,
  pub secret: String
}


#[pg_export]
pub fn encrypt(pg_key_name: *mut Text, pg_data: *mut Bytea) -> *mut Bytea {
    log_to_file(format!("ENTERING ENCRYPT...\n"));
    read_vault_creds();
    let lock = CACHE.lock().unwrap();
    let auth = lock.get("auth").unwrap();
    log_key_and_data(pg_key_name, pg_data);

    let key_name = string_from_pg_text(pg_key_name);
    let data_bytes = bytes_from_pg_bytes(pg_data);

    let mut client: AzureVault = Vault::new(&auth.vault_name[..], &auth.client_id[..], &auth.secret[..]);
    let encrypt_result = client.encrypt(&key_name[..], data_bytes);
    let encrypted_string = match encrypt_result {
        Ok(bits) => bits,
        Err(why) => {
            log_to_file(format!("Encrypt Error: {:?}...\n", why));
            panic!("failed to encrypt with key: {} {}\n", key_name, Error::description(&why));
        }
    };

    let un_base64 = encrypted_string[..].from_base64();
    log_to_file(format!("encrypted string: {:?}\n", encrypted_string));
    let mut into_bytes =  un_base64.unwrap();
    let mut mut_encrypted = &mut into_bytes[..];
    let pg_result = build_pg_data(mut_encrypted);

    // log_to_file(format!("string: {}\n", key_name));
    // log_to_file(format!("raw_bytes: {:?}\n", data_bytes));
    unsafe {
        log_to_file(format!("upper pg_result: {:?}\n", (*pg_result)));
    };

    log_to_file(format!("EXITING ENCRYPT...\n"));

    return pg_result;
}


#[pg_export]
pub fn decrypt(pg_key_name: *mut Text, pg_data: *mut Bytea) -> *mut Bytea {
    log_to_file(format!("ENTERING DECRYPT...\n"));
    read_vault_creds();
    let lock = CACHE.lock().unwrap();
    let auth = lock.get("auth").unwrap();
    log_key_and_data(pg_key_name, pg_data);

    let key_name = string_from_pg_text(pg_key_name);
    let data_bytes = bytes_from_pg_bytes(pg_data);

    let mut client: AzureVault = Vault::new(&auth.vault_name[..], &auth.client_id[..], &auth.secret[..]);

    log_to_file(format!("callin decrypt\n"));
    let decrypt_result = client.decrypt(&key_name[..], data_bytes);
    let decrypted_string = match decrypt_result {
        Ok(bits) => {
            log_to_file(format!("got some bits...\n"));
            bits
        },
        Err(why) => {
            log_to_file(format!("Decrypt Error: {:?}...\n", why));
            panic!("failed to decrypt with key: {} {}", key_name, Error::description(&why));
        }
    };

    let un_base64 = decrypted_string[..].from_base64();
    let mut into_bytes = un_base64.unwrap();
    log_to_file(format!("decrypted string: {:?}\n", String::from_utf8(into_bytes.clone())));
    let mut mut_decrypted = &mut into_bytes[..];
    let pg_result = build_pg_data(mut_decrypted);

    // log_to_file(format!("string: {}\n", key_name));
    // log_to_file(format!("raw_bytes: {:?}\n", data_bytes));
    // unsafe {
    //     log_to_file(format!("upper pg_result: {:?}\n", (*pg_result)));
    // };

    log_to_file(format!("EXITING DECRYPT...\n"));

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

fn read_vault_creds() {
    let mut path_buf = env::current_dir().unwrap();
    path_buf.push("vault");
    path_buf.set_extension("json");
    let path = path_buf.as_path();
    let display = path.display();

    // Locking block where cache is used to not require reopening the file
    let auth = {
        log_to_file(format!("Locking...\n"));
        let lock_result = CACHE.lock();
        let cache = lock_result.unwrap();
        log_to_file(format!("Unwrapped...\n"));
        let result = cache.get("auth").clone();
        match result {
            Some(auth) => {
                log_to_file(format!("auth: {:?}...\n", auth));
                auth.clone()
            },
            None => {
                log_to_file(format!("no auth...\n"));
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

                let mut file_string = String::new();
                // Read the file contents into a string, returns `io::Result<usize>`
                match file.read_to_string(&mut file_string) {
                    Err(why) => {
                        log_to_file(format!("couldn't read {}: {}\n", display, why));
                        panic!("couldn't read {}: {}", display, why)
                    },
                    Ok(_) => print!("{} contains:\n{}", display, file_string),
                };

                // log_to_file(format!("json read 1: {}", s));
                // log_to_file(format!("I'm decoding...\n"));
                let auth_result: DecodeResult<VaultAuth> = json::decode(&file_string[..]);
                match auth_result {
                    Ok(auth) => {
                        auth
                    },
                    Err(why) => {
                        // log_to_file(format!("json read 2: {}\n", s));
                        log_to_file(format!("error: {:?}\n", why));
                        log_to_file(format!("bad format for vault.json: {}\n", why));
                        panic!("bad format for vault.json: {}", why)
                    }
                }
            }
        }
    };
    log_to_file(format!("Locking again...\n"));
    let lock_result = CACHE.lock();
    let mut cache = lock_result.unwrap();
    log_to_file(format!("Inserting auth...\n"));
    cache.insert("auth", auth.clone());
}

fn string_from_pg_text(pg_text: *mut Text) -> String{
    log_to_file(format!("String from pg_text...\n"));
    let string = unsafe {
        log_to_file(format!("pg_text org size: {:?}...\n", (*pg_text).p.len));
        let total_len = ((*pg_text).p.len as u32 >> 2) & 0x3FFFFFFF;
        let data_size = total_len - 4; // subtract the 4 byte header
        log_to_file(format!("pg_text shrunk size: {:?}...\n", data_size));
        let ptr = (*pg_text).p.data.as_mut_ptr();
        String::from_raw_parts(ptr, data_size as usize, data_size as usize)
    };
    return string;
}

fn bytes_from_pg_bytes<'a>(pg_bytes: *mut Bytea) -> &'a [u8]{
    log_to_file(format!("Bytes from pg_bytes...\n"));
    let some_bytes: &[u8] = unsafe {
        log_to_file(format!("pg_bytes org size: {:?}...\n", (*pg_bytes).p.len));
        let total_len = ((*pg_bytes).p.len as u32 >> 2) & 0x3FFFFFFF;
        let data_size = total_len - 4; // subtract the 4 byte header
        log_to_file(format!("pg_bytes shrunk size: {:?}...\n", data_size));
        let ptr = (*pg_bytes).p.data.as_mut_ptr();
        let raw_bytes: Slice<u8> = Slice {
            data: ptr,
            len: data_size as usize
        };
        log_to_file(format!("pg_bytes got the raw...\n"));
        mem::transmute(raw_bytes)
    };
    log_to_file(format!("pg_bytes transmuted, len: {}...\n", some_bytes.len()));
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
