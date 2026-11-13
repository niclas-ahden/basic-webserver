import Host

## Cryptography primitives that Roc's builtin `Crypto` module does not provide:
## SHA-1 hashing, AES-256-GCM encryption, and ES256 and RS256 signature
## checks. For SHA-256 use the builtin `Crypto.SHA256`. Random bytes for keys
## and nonces come from [Random.seed_u64!].
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

	## Whether `signature` is an ES256 signature (ECDSA on P-256 with
	## SHA-256) of `message` by `public_key`. ES256 is what most WebAuthn
	## passkeys and many JWTs and signed webhooks use. `message` is the signed
	## bytes themselves, which the check hashes with SHA-256.
	##
	## `public_key` is an uncompressed SEC1 point on P-256: `0x04` followed by
	## the 32-byte x and y coordinates, 65 bytes in all. Compressed points and
	## every other encoding are refused. A JWK's `x` and `y` give this point.
	## `signature` is DER-encoded, as WebAuthn sends it. A JWS signature is
	## the raw 64-byte `r` and `s` instead, and has to be DER-encoded first.
	## A signature with a high S value holds, since ECDSA does not require
	## signers to normalise it.
	##
	## A key or signature that breaks these rules is a signature that does not
	## hold.
	##
	## ```roc
	## holds = Crypt.verify_es256!({ public_key, message, signature })
	## ```
	verify_es256! : { public_key : List(U8), message : List(U8), signature : List(U8) } => Bool
	verify_es256! = |{ public_key, message, signature }|
		Host.crypt_verify_es256!(public_key, message, signature)

	## Whether `signature` is an RS256 signature (RSA PKCS#1 v1.5 with
	## SHA-256) of `message` by the key `modulus` and `exponent`. RS256 is
	## what many JWTs and some WebAuthn passkeys, Windows Hello's among them,
	## use. `message` is the signed bytes themselves, which the check hashes
	## with SHA-256.
	##
	## `modulus` and `exponent` are big-endian unsigned integers, as a COSE RSA
	## key or a JWK's `n` and `e` hold them, and leading zero bytes are
	## ignored. The modulus is odd and 256 to 1024 bytes long (2048 to 8192
	## bits). 2048 bits is a security floor: shorter keys can be factored
	## with feasible effort, so they are refused even with a correct
	## signature. The exponent is odd and
	## from 3 to 2^33 - 1. `signature` is exactly as long as the modulus.
	##
	## A key or signature that breaks these rules is a signature that does not
	## hold.
	##
	## ```roc
	## holds = Crypt.verify_rs256!({ modulus, exponent, message, signature })
	## ```
	verify_rs256! : { modulus : List(U8), exponent : List(U8), message : List(U8), signature : List(U8) } => Bool
	verify_rs256! = |{ modulus, exponent, message, signature }|
		Host.crypt_verify_rs256!(modulus, exponent, message, signature)

	## Whether [Crypt.verify_es256!] takes `public_key`, by the same rules it
	## checks keys with. Check a key when it is stored, a passkey's for
	## example, so a key that can never verify is refused then and not at its
	## first use.
	valid_es256_key! : List(U8) => Bool
	valid_es256_key! = |public_key| Host.crypt_valid_es256_key!(public_key)

	## Whether [Crypt.verify_rs256!] takes the key `modulus` and `exponent`,
	## by the same rules it checks keys with.
	valid_rs256_key! : { modulus : List(U8), exponent : List(U8) } => Bool
	valid_rs256_key! = |{ modulus, exponent }| Host.crypt_valid_rs256_key!(modulus, exponent)
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
