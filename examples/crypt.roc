## Hashes request bodies, encrypts round trips, and serves random tokens
## and seeds.
app [Context, program] {
	pf: platform "https://github.com/roc-lang/basic-webserver/releases/download/0.16.0/42jC1JT3auhHSmv2Ah8mW5F2MXiAakq1UQQ4NQceQjXw.tar.zst",
	http: "https://github.com/roc-lang/http/releases/download/1.0.0/6ZUwqYhCS8PU9Mo6MF7oV82ET2o7KYb57CLKDq4cq4sS.tar.zst",
	roc: "nightly-2026-09-29-7f11a82",
}

import pf.Crypt
import pf.Random
import pf.Server
import http.Response

Context : {}

program = { init!, respond!, shutdown! }

init! : () => Try({ config : Server.Config, context : Context }, [Exit(I64)])
init! = || Ok({ config: Server.default_config, context: {} })

respond! : Server.Request, Context => Try(Server.Outcome, [ServerErr(Str)])
respond! = |request, _context| {
	response =
		match raw_path(request) {
			"/hash" => hash_route!(request)
			"/encrypt" => encrypt_route!(request)
			"/token" => token_route!({})
			"/seed" => seed_route!({})
			_ => Ok(text_response(404, "URL Not Found (404)"))
		}

	match response {
		Ok(ok_response) => Ok(Server.respond(ok_response))
		Err(err) => Err(ServerErr(Str.inspect(err)))
	}
}

## SHA-1 and SHA-256 of the request body as lowercase hex. SHA-256 comes from
## Roc's builtin `Crypto` module, the platform's `Crypt` adds the algorithms
## the builtin lacks.
hash_route! : Server.Request => Try(Response, _)
hash_route! = |request| {
	body = request.body().with_limit(64 * 1024).read_all!() ? |err| BodyReadFailed(err)
	sha1 = Crypt.hash!(body, Sha1)
	sha256 = Crypto.SHA256.hash(body).to_hex()
	Ok(text_response(200, "SHA-1: ${sha1}\nSHA-256: ${sha256}"))
}

## Round trip the body through AES-256-GCM with a random 32-byte key and a
## fresh random 12-byte nonce. Never reuse a nonce with the same key.
encrypt_route! : Server.Request => Try(Response, _)
encrypt_route! = |request| {
	plaintext = request.body().with_limit(64 * 1024).read_all!() ? |err| BodyReadFailed(err)
	key = random_bytes!(32)?
	nonce = random_bytes!(12)?
	{ ciphertext, auth_tag } = Crypt.encrypt_aes256_gcm!({ plaintext, key, nonce })?
	decrypted = Crypt.decrypt_aes256_gcm!({ ciphertext, key, nonce, auth_tag })?
	decrypted_text = Str.from_utf8(decrypted) ? |_| DecryptedBodyWasNotUtf8
	Ok(text_response(200, "decrypted: ${decrypted_text}, tag bytes: ${U64.to_str(auth_tag.len())}"))
}

## A 16-byte random token as lowercase hex.
token_route! : {} => Try(Response, _)
token_route! = |{}| {
	token = random_bytes!(16)?
	Ok(text_response(200, "token: ${to_hex(token)}"))
}

## `count` bytes from the operating system's entropy source, eight per
## `Random.seed_u64!` call.
random_bytes! : U64 => Try(List(U8), _)
random_bytes! = |count| fill_random!(count, [])

fill_random! : U64, List(U8) => Try(List(U8), _)
fill_random! = |count, acc|
	if acc.len() >= count {
		Ok(acc.take_first(count))
	} else {
		seed = Random.seed_u64!()?
		fill_random!(count, acc.concat(u64_bytes(seed)))
	}

u64_bytes : U64 -> List(U8)
u64_bytes = |value| [0, 8, 16, 24, 32, 40, 48, 56].map(|shift| value.shr_zf_wrap(shift).to_u8_wrap())

## A seed for pseudorandom generation in application code.
seed_route! : {} => Try(Response, _)
seed_route! = |{}| {
	seed = Random.seed_u64!()?
	Ok(text_response(200, "seed: ${U64.to_str(seed)}"))
}

text_response : U16, Str -> Response
text_response = |status, body|
	Response.from_status(status).with_body(Str.to_utf8(body))

to_hex : List(U8) -> Str
to_hex = |bytes|
	Str.join_with(
		bytes.map(
			|byte| {
				digits = Str.to_utf8("0123456789abcdef")
				high = digits.get(U8.to_u64(byte // 16)) ?? '0'
				low = digits.get(U8.to_u64(byte % 16)) ?? '0'
				Str.from_utf8_lossy([high, low])
			},
		),
		"",
	)

shutdown! : Server.ShutdownReason, Context => Try({}, [Exit(I64)])
shutdown! = |_reason, _context| Ok({})

## The path of an ordinary request target, or "" for CONNECT and `OPTIONS *`.
raw_path : Server.Request -> Str
raw_path = |request|
	match request.target() {
		Resource({ raw_path: path, .. }) => path
		_ => ""
	}
