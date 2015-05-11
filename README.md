# pg-vault
PostgreSQL extension which exposes the functionality of the Rust vault crypto library. Specifically, <b>Encrypt and Decrypt</b> via a key stored in Azure Key Vault may be used to encrypt or decrypt a single block of data, the size of which is determined by the key type and the default encryption algorithm (RSA_OAEP).

This is a prototype and will fail randomly. Do not use this code for production use.

There are couple assumptions being made with this repo. All of which are required to run or build this code.
- You are running OSX
- You have PostgreSQL 9.0.5 installed

The src directory contains the source for the library. The library depends on libpgcommon, which is included in the lib directory for x86_64-apple-darwin. The other dependencies are listed in the Cargo.toml file ([postgres-extension](https://github.com/devigned/postgres-extension.rs), [rust-key-vault](https://github.com/devigned/rust-key-vault), lazy-static and rustc-serialize).

## Installation

- Clone the repo
- Run `cargo build`
- Update the vault.json.example with your vault details and copy it into your PostgreSQL with the name vault.json
- Update the pg-funcs.sql to point to your libpg_vault...dylib
- Execute the pg-funcs.sql script and cross your fingers. If all is well, you should see "hello world!!" selected twice and one lovely byte array which contains the encrypted value of "hello world!!".

## Usage

After registering the following in PostgreSQL:
```sql
CREATE FUNCTION encrypt(text, bytea) RETURNS bytea AS '{path to libpg_vault...dylib}' LANGUAGE c volatile;
CREATE FUNCTION decrypt(text, bytea) RETURNS bytea AS '{path to libpg_vault...dylib}' LANGUAGE c volatile;
```

You should be able to use encrypt and decrypt as normal SQL functions.

## Development

After checking out the repo, run `cargo build` to install dependencies and compile. Then, follow the installation instructions.

## Contributing

1. Fork it ( https://github.com/devigned/pg-vault/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
