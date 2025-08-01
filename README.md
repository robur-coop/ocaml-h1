# ocaml-h1

`ocaml-h1` is a high-performance, memory-efficient, and scalable web server for
OCaml. It implements the HTTP 1.1 specification with respect to parsing,
serialization, and connection pipelining as a state machine that is agnostic to
the underlying IO mechanism, and is therefore portable across many platform.
It uses the [Angstrom][angstrom] and [Faraday][faraday] libraries to implement
the parsing and serialization layers of the HTTP standard, hence the name.

[angstrom]: https://github.com/inhabitedtype/angstrom
[faraday]: https://github.com/inhabitedtype/faraday

## Installation

Install the library and its dependencies via [OPAM][opam]:

[opam]: http://opam.ocaml.org/

```bash
opam install h1
```

## Usage

Here is a Hello, World! program written using h1. It only responds to `GET`
requests to the `/hello/*` target. As it does not itself do any IO, it can be
used with both the Async and Lwt runtimes. See the [`examples`][examples] directory for
usage of the individual runtimes.

[examples]: https://github.com/robur-coop/ocaml-h1/tree/master/examples

```ocaml
open H1
module String = Stdlib.String

let invalid_request reqd status body =
  (* Responses without an explicit length or transfer-encoding are
     close-delimited. *)
  let headers = Headers.of_list [ "Connection", "close" ] in
  Reqd.respond_with_string reqd (Response.create ~headers status) body
;;

let request_handler reqd =
  let { Request.meth; target; _ } = Reqd.request reqd in
  match meth with
  | `GET ->
    begin match String.split_on_char '/' target with
    | "" :: "hello" :: rest ->
      let who =
        match rest with
        | [] -> "world"
        | who :: _ -> who
      in
      let response_body = Printf.sprintf "Hello, %s!\n" who in
      (* Specify the length of the response. *)
      let headers =
        Headers.of_list
          [ "Content-length", string_of_int (String.length response_body) ]
      in
      Reqd.respond_with_string reqd (Response.create ~headers `OK) response_body
    | _ ->
      let response_body = Printf.sprintf "%S not found\n" target in
      invalid_request reqd `Not_found response_body
    end
  | meth ->
    let response_body =
      Printf.sprintf "%s is not an allowed method\n" (Method.to_string meth)
    in
    invalid_request reqd `Method_not_allowed response_body
;;
```

## Performance

The reason for http/af's existence is [mirage/ocaml-cohttp#328][328], which
highlights the poor scalability of cohttp. This is due to a number of factors,
including poor scheduling, excessive allocation, and starvation of the server's
accept loop. Here is a comparison chart of the data from that issue, along with
data from an async-based http/af server. This server was run on a VM with 3
virtual cores, the host being circa 2015 MacBook Pro:

[328]: https://github.com/mirage/ocaml-cohttp/issues/328

![h1 comparsion to cohttp](https://raw.githubusercontent.com/robur-coop/h1/master/images/h1-comparison.png)

The http/af latency histogram, relative to the cohttp histograms, is pretty
much flat along the x-axis. Here are some additional statistics from that run
(with latencies in milliseconds):

```
#[Mean    =       27.719, StdDeviation   =       31.570]
#[Max     =      263.424, Total count    =      1312140]
#[Buckets =           27, SubBuckets     =         2048]
----------------------------------------------------------
  1709909 requests in 1.00m, 3.33GB read
```

## Development

To install development dependencies, pin the package from the root of the
repository:

```bash
opam pin add -n h1 .
opam install --deps-only h1
```

After this, you may install a development version of the library using the
install command as usual.

Tests can be run via dune:

```bash
dune runtest
```

## `ocaml-h1` & `httpaf`

`ocaml-h1` is a _hard_ fork of [httpaf][httpaf]. It was created after asking
the author and official maintainer of httpaf if we could make such a fork.

`ocaml-h1` is **not** intended to be a continuation of `httpaf`, which
continues to evolve and exist. However, some pull requests were/are awaiting
integration, and we wanted them to be included.

After discussing it with the author, he gave us permission to make this fork,
which includes all the PRs we wanted as well as additions such as the
implementation of websockets.

We would therefore like to thank the original author of `httpaf` for his work,
for his trust in our cooperative, and for his permission to fork `httpaf`.

## License

BSD3, see LICENSE files for its text.

[httpaf]: https://github.com/inhabitedtype/httpaf
