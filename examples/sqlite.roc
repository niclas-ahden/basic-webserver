## Queries completed todos from SQLite and serves their inspected records.
app [Context, program] {
	pf: platform "https://github.com/roc-lang/basic-webserver/releases/download/0.16.0/42jC1JT3auhHSmv2Ah8mW5F2MXiAakq1UQQ4NQceQjXw.tar.zst",
	http: "https://github.com/roc-lang/http/releases/download/1.0.0/6ZUwqYhCS8PU9Mo6MF7oV82ET2o7KYb57CLKDq4cq4sS.tar.zst",
	roc: "nightly-2026-09-29-7f11a82",
}

import pf.Server
import pf.Sqlite
import pf.Env
import pf.Path
import http.Response

# Set `DB_PATH` to choose a database; otherwise this uses
# `./examples/todos.db`. The database must already contain this table:
#
# CREATE TABLE todos (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     task TEXT NOT NULL,
#     status TEXT NOT NULL
# );

# The database pool is opened once during `init!` and retained in immutable context.
Context : { db : Sqlite.Db }

program = { init!, respond!, shutdown! }

init! : () => Try({ config : Server.Config, context : Context }, [Exit(I64)])
init! = || {
	db_path =
		match Env.var!("DB_PATH") {
			Ok(path) => Path.from_os_str(path)
			Err(_) => Path.utf8("./examples/todos.db")
		}
	db = Sqlite.open!(Sqlite.default_config(db_path)) ? |_| Exit(2)
	Ok({ config: Server.default_config, context: { db: db } })
}

respond! : Server.Request, Context => Try(Server.Outcome, [ServerErr(Str)])
respond! = |_request, { db }| {
	match query_todos_by_status!(db, Completed) {
		Ok(todos) => {
			lines = todos.map(|todo| Str.inspect(todo))
			body = Str.join_with(lines, "\n")
			response =
				Response.from_status(200)
					.with_headers([{ name: "Content-Type", value: "text/html; charset=utf-8" }])
					.with_body(Str.to_utf8(body))
			Ok(Server.respond(response))
		}
		Err(err) => Err(ServerErr("Failed to query Sqlite: ${Str.inspect(err)}"))
	}
}

shutdown! : Server.ShutdownReason, Context => Try({}, [Exit(I64)])
shutdown! = |_reason, _context| Ok({})

Todo : { id : I64, status : TodoStatus, task : Str }

query_todos_by_status! : Sqlite.Db, TodoStatus => Try(List(Todo), Sqlite.QueryError)
query_todos_by_status! = |db, status| {
	transaction = Sqlite.begin!(db, Deferred)?
	todos : List(Todo)
	todos = transaction.query_many!({
		query: "SELECT id, task, status FROM todos WHERE status = :status;",
		params: { status },
		limits: Sqlite.default_query_limits,
	})?
	transaction.commit!()?

	Ok(todos)
}

TodoStatus := [Todo, Planned, Completed, InProgress].{
	parser_for : encoding -> (state -> Try({ value : TodoStatus, rest : state }, err))
		where [
			encoding.parse_str : encoding, state -> Try({ value : Str, rest : state }, err),
			encoding.invalid_value : encoding, state -> err,
		]
	parser_for = |encoding| {
		Encoding : encoding

		|state| {
			parsed = Encoding.parse_str(encoding, state)?

			match parse_todo_status(parsed.value) {
				Ok(status) => Ok({ value: status, rest: parsed.rest })
				Err(_) => Err(Encoding.invalid_value(encoding, state))
			}
		}
	}

	encoder_for : encoding -> (TodoStatus, state -> Try(state, err))
		where [
			encoding.encode_str : Str, state -> Try(state, err),
		]
	encoder_for = |_encoding| {
		Encoding : encoding

		|status, state| Encoding.encode_str(todo_status_to_str(status), state)
	}
}

todo_status_to_str : TodoStatus -> Str
todo_status_to_str = |status|
	match status {
		Todo => "todo"
		Planned => "planned"
		Completed => "completed"
		InProgress => "in-progress"
	}

parse_todo_status : Str -> Try(TodoStatus, [InvalidTodoStatus])
parse_todo_status = |status_str|
	match status_str {
		"todo" => Ok(Todo)
		"planned" => Ok(Planned)
		"completed" => Ok(Completed)
		"in-progress" => Ok(InProgress)
		_ => Err(InvalidTodoStatus)
	}
