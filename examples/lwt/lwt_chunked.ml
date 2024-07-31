open Base
open Lwt.Infix
module Arg = Stdlib.Arg

open H1_lwt_unix

let request_handler (_ : Unix.sockaddr) reqd =
  let body = H1.Reqd.respond_with_streaming reqd (H1.Response.create ~headers:(H1.Headers.of_list ["connection", "close"]) `OK) in
  let rec respond_loop i =
    H1.Body.Writer.write_string body (Printf.sprintf "Chunk %i\n" i);
    H1.Body.Writer.flush_with_reason body (function
    | `Closed  -> Stdio.print_endline "closed"
    | `Written -> Stdio.print_endline "written"; Lwt.bind (Lwt_unix.sleep 5.) (fun () -> respond_loop (i+1)) |> ignore
    );
    Lwt.return_unit
  in ignore (respond_loop 0)

let error_handler (_ : Unix.sockaddr) = H1_examples.Server.error_handler

let main port =
  let listen_address = Unix.(ADDR_INET (inet_addr_loopback, port)) in
  Lwt.async (fun () ->
    Lwt_io.establish_server_with_client_socket
      listen_address
      (Server.create_connection_handler ~upgrade_handler:None ~request_handler ~error_handler)
    >|= fun _server ->
      Stdio.printf "Listening on port %i.\n" port);
  let forever, _ = Lwt.wait () in
  Lwt_main.run forever
;;

let () =
  Stdlib.Sys.set_signal Stdlib.Sys.sigpipe Stdlib.Sys.Signal_ignore;
  let port = ref 8080 in
  Arg.parse
    ["-p", Arg.Set_int port, " Listening port number (8080 by default)"]
    ignore
    "Echoes POST requests. Runs forever.";
  main !port
;;
