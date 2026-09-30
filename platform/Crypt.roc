import Host

## Cryptography primitives that Roc's builtin `Crypto` module does not provide:
## SHA-1 hashing and AES-256-GCM encryption. For SHA-256 use the builtin
## `Crypto.SHA256`. Random bytes for keys and nonces come from
## [Random.seed_u64!].
##
## All operations run synchronously in the calling handler and occupy one
## bounded Roc execution slot for their full duration.
Crypt := [].{

	## Hash algorithms supported by [Crypt.hash!]. SHA-256 is in the builtin
	## `Crypto.SHA256`.
	Algorithm : [Sha1]

	## Hash bytes with the given algorithm, returning a lowercase hex digest.
	##
	## ```roc
	## digest = Crypt.hash!(Str.to_utf8("hello"), Sha1)
	## ```
	hash! : List(U8), Algorithm => Str
	hash! = |bytes, algorithm|
		match algorithm {
			Sha1 => Host.crypt_sha1!(bytes)
		}

	## Encrypt with AES-256-GCM. `key` must be 32 bytes; `nonce` must be 12
	## bytes and NEVER reused with the same key. Returns the ciphertext and a
	## 16-byte authentication tag.
	encrypt_aes256_gcm! : { plaintext : List(U8), key : List(U8), nonce : List(U8) } => Try({ auth_tag : List(U8), ciphertext : List(U8) }, [CryptoErr(Str)])
	encrypt_aes256_gcm! = |{ plaintext, key, nonce }|
		widen_crypto_err(Host.crypt_encrypt_aes256_gcm!(plaintext, key, nonce))

	## Decrypt AES-256-GCM ciphertext. Fails if the key, nonce, or tag is
	## wrong (including tampered ciphertext).
	decrypt_aes256_gcm! : { ciphertext : List(U8), key : List(U8), nonce : List(U8), auth_tag : List(U8) } => Try(List(U8), [CryptoErr(Str)])
	decrypt_aes256_gcm! = |{ ciphertext, key, nonce, auth_tag }|
		widen_crypto_err(Host.crypt_decrypt_aes256_gcm!(ciphertext, key, nonce, auth_tag))
}

# ---- internal helpers (module-private) -----------------------------------------

## Rebuild the error union so it is open at call sites.
## Passing a hosted function's result straight through leaves the union closed,
## which stops `?` from combining it with other error types.
widen_crypto_err : Try(v, [CryptoErr(Str)]) -> Try(v, [CryptoErr(Str)])
widen_crypto_err = |result|
	match result {
		Ok(value) => Ok(value)
		Err(CryptoErr(err)) => Err(CryptoErr(err))
	}
