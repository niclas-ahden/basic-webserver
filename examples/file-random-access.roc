## Maintains a fixed-slot record file with positional writes and seeked reads.
app [Context, program] {
	pf: platform "https://github.com/roc-lang/basic-webserver/releases/download/0.16.0/42jC1JT3auhHSmv2Ah8mW5F2MXiAakq1UQQ4NQceQjXw.tar.zst",
	http: "https://github.com/roc-lang/http/releases/download/1.0.0/6ZUwqYhCS8PU9Mo6MF7oV82ET2o7KYb57CLKDq4cq4sS.tar.zst",
	roc: "nightly-2026-09-29-7f11a82",
}

import pf.Env
import pf.File
import pf.Path
import pf.Server
import http.Response

# Each record occupies a fixed 64-byte slot, so a record can be read or
# replaced in place without rewriting the file. POST a body to `/slot/N` to
# store it (padded with zeroes), GET `/slot/N` to read it back, and GET
# `/checksum` for a SHA-256 of the whole file.

slot_size : U64
slot_size = 64

slot_count : U64
slot_count = 16

Context : Path

program = { init!, respond!, shutdown! }

# Set `SLOT_FILE` to override the default slot file path in the system
# temporary directory.

init! : () => Try({ config : Server.Config, context : Context }, [Exit(I64), FailedToCreateSlotFile(_)])
init! = || {
	file =
		match Env.var!("SLOT_FILE") {
			Ok(path) => Path.from_os_str(path)
			Err(_) => Path.join(Env.temp_dir!(), "basic-webserver-slots.bin")
		}
	# Allocate every slot up front, filled with zeroes.
	Path.set_len!(file, slot_size * slot_count) ? |err| FailedToCreateSlotFile(err)
	Ok({ config: Server.default_config, context: file })
}

respond! : Server.Request, Context => Try(Server.Outcome, [ServerErr(Str)])
respond! = |request, file| {
	response =
		match Str.split_on(raw_path(request), "/") {
			["", "slot", index_str] => slot_route!(request, file, index_str)
			["", "checksum"] => checksum_route!(file)
			_ => Ok(text_response(404, "URL Not Found (404)"))
		}

	match response {
		Ok(ok_response) => Ok(Server.respond(ok_response))
		Err(err) => Err(ServerErr(Str.inspect(err)))
	}
}

slot_route! : Server.Request, Path, Str => Try(Response, _)
slot_route! = |request, file, index_str|
	match U64.from_str(index_str) {
		Err(_) => Ok(text_response(400, "Slot index must be a decimal number"))
		Ok(index) if index >= slot_count => Ok(text_response(404, "Slot index must be below ${U64.to_str(slot_count)}"))
		Ok(index) => {
			offset = index * slot_size
			match request.method() {
				GET => {
					reader = File.open_reader!(file)?
					_ = reader.seek!(Start(offset))?
					slot = reader.read_exactly!(slot_size)?
					Ok(text_response(200, "slot ${U64.to_str(index)}: ${Str.from_utf8_lossy(trim_padding(slot))}"))
				}
				POST =>
					match request.body().with_limit(slot_size).read_all!() {
						Ok(body) => {
							padded = body.concat(List.repeat(0.U8, slot_size - body.len()))
							Path.write_bytes_at!(file, offset, padded)?
							Ok(text_response(200, "stored ${U64.to_str(body.len())} bytes in slot ${U64.to_str(index)}"))
						}
						Err(RequestBodyErr(TooLarge(_))) => Ok(text_response(413, "A record holds at most ${U64.to_str(slot_size)} bytes"))
						Err(err) => Err(BodyReadFailed(err))
					}
				_ => Ok(text_response(405, "Only GET and POST are supported"))
			}
		}
	}

## A SHA-256 of the whole slot file, hashed from a stream of bounded chunks so
## memory use does not depend on the file size.
checksum_route! : Path => Try(Response, _)
checksum_route! = |file| {
	reader = File.open_reader!(file)?
	var $chunks = reader.chunks(16 * 1024)?
	var $hasher = Crypto.SHA256.Hasher.empty()
	while Bool.True {
		match Stream.next!($chunks) {
			Done => {
				break
			}
			Skip({ rest }) => {
				$chunks = rest
			}
			One({ item, rest }) => {
				$hasher = $hasher.write(item?)
				$chunks = rest
			}
		}
	}
	Ok(text_response(200, "sha256: ${$hasher.finish().to_hex()}"))
}

## A stored record without the zeroes that pad it to the slot size.
trim_padding : List(U8) -> List(U8)
trim_padding = |bytes|
	match bytes.last() {
		Ok(0) => trim_padding(bytes.drop_last(1))
		_ => bytes
	}

text_response : U16, Str -> Response
text_response = |status, body|
	Response.from_status(status).with_body(Str.to_utf8(body))

shutdown! : Server.ShutdownReason, Context => Try({}, [Exit(I64)])
shutdown! = |_reason, _context| Ok({})

## The path of an ordinary request target, or "" for CONNECT and `OPTIONS *`.
raw_path : Server.Request -> Str
raw_path = |request|
	match request.target() {
		Resource({ raw_path: path, .. }) => path
		_ => ""
	}
