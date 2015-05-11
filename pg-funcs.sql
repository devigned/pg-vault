
CREATE FUNCTION encrypt(text, bytea) RETURNS bytea AS '{path to libpg_vault...dylib}' LANGUAGE c volatile;
CREATE FUNCTION decrypt(text, bytea) RETURNS bytea AS '{path to libpg_vault...dylib}' LANGUAGE c volatile;

select 'hello world!!'::bytea

select decrypt('mynewkey1', encrypt('mynewkey1', 'hello world!!'));

select encrypt('mynewkey1', 'hello world!!');

Drop Function encrypt(text, bytea);
Drop Function decrypt(text, bytea);
