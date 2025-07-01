open Httpun_types
module H1_client_connection = Client_connection.Oneshot

module Opcode = struct
  type standard_non_control = [ `Continuation | `Text | `Binary ]
  type standard_control = [ `Connection_close | `Ping | `Pong ]
  type standard = [ standard_non_control | standard_control ]
  type t = [ standard | `Other of int ]

  let code = function
    | `Continuation -> 0x0
    | `Text -> 0x1
    | `Binary -> 0x2
    | `Connection_close -> 0x8
    | `Ping -> 0x9
    | `Pong -> 0xa
    | `Other code -> code

  let code_table : t array =
    [|
      `Continuation;
      `Text;
      `Binary;
      `Other 0x3;
      `Other 0x4;
      `Other 0x5;
      `Other 0x6;
      `Other 0x7;
      `Connection_close;
      `Ping;
      `Other 0xb;
      `Other 0xc;
      `Other 0xd;
      `Other 0xe;
      `Other 0xf;
    |]

  let unsafe_of_code code = Array.unsafe_get code_table code

  let of_code code =
    if code > 0xf then None else Some (Array.unsafe_get code_table code)

  let of_code_exn code =
    if code > 0xf then
      failwith "Opcode.of_code_exn: value can't fit in four bits";
    Array.unsafe_get code_table code

  let to_int = code
  let of_int = of_code
  let of_int_exn = of_code_exn

  let pp_hum fmt = function
    | `Continuation -> Format.fprintf fmt "`Continuation"
    | `Text -> Format.fprintf fmt "`Text"
    | `Binary -> Format.fprintf fmt "`Binary"
    | `Connection_close -> Format.fprintf fmt "`Connection_close"
    | `Ping -> Format.fprintf fmt "`Ping"
    | `Pong -> Format.fprintf fmt "`Pong"
    | `Other code -> Format.fprintf fmt "`Other %#x" code
end

module Close_code = struct
  type standard =
    [ `Normal_closure
    | `Going_away
    | `Protocol_error
    | `Unsupported_data
    | `No_status_rcvd
    | `Abnormal_closure
    | `Invalid_frame_payload_data
    | `Policy_violation
    | `Message_too_big
    | `Mandatory_ext
    | `Internal_server_error
    | `TLS_handshake ]

  type t = [ standard | `Other of int ]

  let code = function
    | `Normal_closure -> 1000
    | `Going_away -> 1001
    | `Protocol_error -> 1002
    | `Unsupported_data -> 1003
    | `No_status_rcvd -> 1005
    | `Abnormal_closure -> 1006
    | `Invalid_frame_payload_data -> 1007
    | `Policy_violation -> 1008
    | `Message_too_big -> 1009
    | `Mandatory_ext -> 1010
    | `Internal_server_error -> 1011
    | `TLS_handshake -> 1015
    | `Other code -> code

  let code_table : t array =
    [|
      `Normal_closure;
      `Going_away;
      `Protocol_error;
      `Unsupported_data;
      `Other 1004;
      `No_status_rcvd;
      `Abnormal_closure;
      `Invalid_frame_payload_data;
      `Policy_violation;
      `Message_too_big;
      `Mandatory_ext;
      `Internal_server_error;
      `Other 1012;
      `Other 1013;
      `Other 1014;
      `TLS_handshake;
    |]

  let unsafe_of_code code = Array.unsafe_get code_table code

  let of_code code =
    if code > 0xffff || code < 1000 then None
    else if code < 1016 then Some (unsafe_of_code (code land 0b1111))
    else Some (`Other code)

  let of_code_exn code =
    if code > 0xffff then
      failwith "Close_code.of_code_exn: value can't fit in two bytes";
    if code < 1000 then
      failwith "Close_code.of_code_exn: value in invalid range 0-999";
    if code < 1016 then unsafe_of_code (code land 0b1111) else `Other code

  let to_int = code
  let of_int = of_code
  let of_int_exn = of_code_exn
end

module Frame = struct
  type t = Bigstringaf.t

  let is_fin t =
    let bits = Bigstringaf.unsafe_get t 0 |> Char.code in
    bits land (1 lsl 7) = 1 lsl 7

  let rsv t =
    let bits = Bigstringaf.unsafe_get t 0 |> Char.code in
    (bits lsr 4) land 0b0111

  let opcode t =
    let bits = Bigstringaf.unsafe_get t 0 |> Char.code in
    bits land 0b1111 |> Opcode.unsafe_of_code

  let payload_length_of_offset t off =
    let bits = Bigstringaf.unsafe_get t (off + 1) |> Char.code in
    let length = bits land 0b01111111 in
    if length = 126 then Bigstringaf.unsafe_get_int16_be t (off + 2)
    else if
      (* This is technically unsafe, but if somebody's asking us to read 2^63
       * bytes, then we're already screwd. *)
      length = 127
    then Bigstringaf.unsafe_get_int64_be t (off + 2) |> Int64.to_int
    else length

  let payload_length t = payload_length_of_offset t 0

  let has_mask t =
    let bits = Bigstringaf.unsafe_get t 1 |> Char.code in
    bits land (1 lsl 7) = 1 lsl 7

  let mask t =
    if not (has_mask t) then None
    else
      Some
        (let bits = Bigstringaf.unsafe_get t 1 |> Char.code in
         if bits = 254 then Bigstringaf.unsafe_get_int32_be t 4
         else if bits = 255 then Bigstringaf.unsafe_get_int32_be t 10
         else Bigstringaf.unsafe_get_int32_be t 2)

  let mask_exn t =
    let bits = Bigstringaf.unsafe_get t 1 |> Char.code in
    if bits = 254 then Bigstringaf.unsafe_get_int32_be t 4
    else if bits = 255 then Bigstringaf.unsafe_get_int32_be t 10
    else if bits >= 127 then Bigstringaf.unsafe_get_int32_be t 2
    else failwith "Frame.mask_exn: no mask present"

  let payload_offset_of_bits bits =
    let initial_offset = 2 in
    let mask_offset = (bits land (1 lsl 7)) lsr (7 - 2) in
    let length_offset =
      let length = bits land 0b01111111 in
      if length < 126 then 0 else 2 lsl (length land 0b1) lsl 2
    in
    initial_offset + mask_offset + length_offset

  let payload_offset t =
    let bits = Bigstringaf.unsafe_get t 1 |> Char.code in
    payload_offset_of_bits bits

  let with_payload t ~f =
    let len = payload_length t in
    let off = payload_offset t in
    f t ~off ~len

  let copy_payload t = with_payload t ~f:Bigstringaf.copy

  let copy_payload_bytes t =
    with_payload t ~f:(fun bs ~off:src_off ~len ->
        let bytes = Bytes.create len in
        Bigstringaf.blit_to_bytes bs ~src_off bytes ~dst_off:0 ~len;
        bytes)

  let length_of_offset t off =
    let bits = Bigstringaf.unsafe_get t (off + 1) |> Char.code in
    let payload_offset = payload_offset_of_bits bits in
    let payload_length = payload_length_of_offset t off in
    payload_offset + payload_length

  let length t = length_of_offset t 0

  let apply_mask mask bs ~off ~len =
    for i = off to off + len - 1 do
      let j = (i - off) mod 4 in
      let c = Bigstringaf.unsafe_get bs i |> Char.code in
      let c =
        c lxor Int32.(logand (shift_right mask (8 * (3 - j))) 0xffl |> to_int)
      in
      Bigstringaf.unsafe_set bs i (Char.unsafe_chr c)
    done

  let apply_mask_bytes mask bs ~off ~len =
    for i = off to off + len - 1 do
      let j = (i - off) mod 4 in
      let c = Bytes.unsafe_get bs i |> Char.code in
      let c =
        c lxor Int32.(logand (shift_right mask (8 * (3 - j))) 0xffl |> to_int)
      in
      Bytes.unsafe_set bs i (Char.unsafe_chr c)
    done

  let unmask_inplace t =
    if has_mask t then
      let mask = mask_exn t in
      let len = payload_length t in
      let off = payload_offset t in
      apply_mask mask t ~off ~len

  let mask_inplace = unmask_inplace

  let parse =
    let open Angstrom in
    Unsafe.peek 2 (fun bs ~off ~len:_ -> length_of_offset bs off) >>= fun len ->
    Unsafe.take len Bigstringaf.sub

  let serialize_headers faraday ~mask ~is_fin ~opcode ~payload_length =
    let opcode = Opcode.to_int opcode in
    let is_fin = if is_fin then 1 lsl 7 else 0 in
    let is_mask = match mask with None -> 0 | Some _ -> 1 lsl 7 in
    Faraday.write_uint8 faraday (is_fin lor opcode);
    if payload_length <= 125 then
      Faraday.write_uint8 faraday (is_mask lor payload_length)
    else if payload_length <= 0xffff then (
      Faraday.write_uint8 faraday (is_mask lor 126);
      Faraday.BE.write_uint16 faraday payload_length)
    else (
      Faraday.write_uint8 faraday (is_mask lor 127);
      Faraday.BE.write_uint64 faraday (Int64.of_int payload_length));
    match mask with
    | None -> ()
    | Some mask -> Faraday.BE.write_uint32 faraday mask

  let serialize_control faraday ~mask ~opcode =
    let opcode = (opcode :> Opcode.t) in
    serialize_headers faraday ~mask ~is_fin:true ~opcode ~payload_length:0

  let schedule_serialize faraday ~mask ~is_fin ~opcode ~payload ~off ~len =
    serialize_headers faraday ~mask ~is_fin ~opcode ~payload_length:len;
    (match mask with
    | None -> ()
    | Some mask -> apply_mask mask payload ~off ~len);
    Faraday.schedule_bigstring faraday payload ~off ~len

  let serialize_bytes faraday ~mask ~is_fin ~opcode ~payload ~off ~len =
    serialize_headers faraday ~mask ~is_fin ~opcode ~payload_length:len;
    (match mask with
    | None -> ()
    | Some mask -> apply_mask_bytes mask payload ~off ~len);
    Faraday.write_bytes faraday payload ~off ~len

  let schedule_serialize_bytes faraday ~mask ~is_fin ~opcode ~payload ~off ~len
      =
    serialize_headers faraday ~mask ~is_fin ~opcode ~payload_length:len;
    (match mask with
    | None -> ()
    | Some mask -> apply_mask_bytes mask payload ~off ~len);
    Faraday.write_bytes faraday payload ~off ~len
end

type frame_handler =
  opcode:Opcode.t -> is_fin:bool -> Bigstringaf.t -> off:int -> len:int -> unit

type input_handlers = { frame_handler : frame_handler; eof : unit -> unit }

module Wsd = struct
  type mode = [ `Client of unit -> int32 | `Server ]

  type t = {
    faraday : Faraday.t;
    mode : mode;
    mutable when_ready_to_write : unit -> unit;
  }

  let default_ready_to_write = Sys.opaque_identity (fun () -> ())

  let create mode =
    {
      faraday = Faraday.create 0x1000;
      mode;
      when_ready_to_write = default_ready_to_write;
    }

  let mask t = match t.mode with `Client m -> Some (m ()) | `Server -> None

  let ready_to_write t =
    let callback = t.when_ready_to_write in
    t.when_ready_to_write <- default_ready_to_write;
    callback ()

  let schedule t ~kind ~is_fin payload ~off ~len =
    let opcode :> Opcode.t = kind in
    let mask = mask t in
    Frame.schedule_serialize t.faraday ~mask ~is_fin ~opcode ~payload
      ~off ~len;
    ready_to_write t

  let send_bytes t ~kind ~is_fin payload ~off ~len =
    let opcode :> Opcode.t = kind in
    let mask = mask t in
    Frame.schedule_serialize_bytes t.faraday ~mask ~is_fin ~opcode
      ~payload ~off ~len;
    ready_to_write t

  let send_ping t =
    Frame.serialize_control t.faraday ~mask:None ~opcode:`Ping;
    ready_to_write t

  let send_pong t =
    Frame.serialize_control t.faraday ~mask:None ~opcode:`Pong;
    ready_to_write t

  let flushed t f = Faraday.flush t.faraday f

  let close t =
    Frame.serialize_control t.faraday ~mask:None
      ~opcode:`Connection_close;
    Faraday.close t.faraday;
    ready_to_write t

  let next t =
    match Faraday.operation t.faraday with
    | `Close -> `Close 0 (* XXX(andreas): should track unwritten bytes *)
    | `Yield -> `Yield
    | `Writev iovecs -> `Write iovecs

  let report_result t result =
    match result with
    | `Closed -> close t
    | `Ok len -> Faraday.shift t.faraday len

  let is_closed t = Faraday.is_closed t.faraday

  let when_ready_to_write t callback =
    if not (t.when_ready_to_write == default_ready_to_write) then
      failwith
        "Wsd.when_ready_to_write: only one callback can be registered at a time"
    else if is_closed t then callback ()
    else t.when_ready_to_write <- callback
end

module Reader = struct
  module AU = Angstrom.Unbuffered

  type 'error parse_state =
    | Done
    | Fail of 'error
    | Partial of (Bigstringaf.t -> off:int -> len:int -> AU.more -> unit AU.state)

  type 'error t = {
    parser : unit Angstrom.t;
    mutable parse_state : 'error parse_state;
    mutable closed : bool;
  }

  let create frame_handler =
    let parser =
      let open Angstrom in
      Frame.parse >>| fun frame ->
      let is_fin = Frame.is_fin frame in
      let opcode = Frame.opcode frame in
      Frame.unmask_inplace frame;
      Frame.with_payload frame ~f:(frame_handler ~opcode ~is_fin)
    in
    { parser; parse_state = Done; closed = false }

  let transition t state =
    match state with
    | AU.Done (consumed, ()) | AU.Fail ((0 as consumed), _, _) ->
        t.parse_state <- Done;
        consumed
    | AU.Fail (consumed, marks, msg) ->
        t.parse_state <- Fail (`Parse (marks, msg));
        consumed
    | AU.Partial { committed; continue } ->
        t.parse_state <- Partial continue;
        committed

  and start t state =
    match state with
    | AU.Done _ -> failwith "Websocket.Reader.unable to start parser"
    | AU.Fail (0, marks, msg) -> t.parse_state <- Fail (`Parse (marks, msg))
    | AU.Partial { committed = 0; continue } -> t.parse_state <- Partial continue
    | _ -> assert false

  let next t =
    match t.parse_state with
    | Done -> if t.closed then `Close else `Read
    | Fail _ -> `Close
    | Partial _ -> `Read

  let rec read_with_more t bs ~off ~len more =
    let consumed =
      match t.parse_state with
      | Fail _ -> 0
      | Done ->
          start t (AU.parse t.parser);
          read_with_more t bs ~off ~len more
      | Partial continue -> transition t (continue bs more ~off ~len)
    in
    (match more with Complete -> t.closed <- true | Incomplete -> ());
    consumed
end

module Connection = struct
  type t = {
    wsd : Wsd.t;
    reader : [ `Parse of string list * string ] Reader.t;
    eof : unit -> unit;
  }

  let create ~mode ~websocket_handler =
    let wsd = Wsd.create mode in
    let { frame_handler; eof } = websocket_handler wsd in
    { wsd; reader = Reader.create frame_handler; eof }

  let next_read_operation t = Reader.next t.reader
  let next_write_operation t = Wsd.next t.wsd
  let read t bs ~off ~len = Reader.read_with_more t.reader bs ~off ~len Incomplete

  let read_eof t bs ~off ~len =
    let len = Reader.read_with_more t.reader bs ~off ~len Complete in
    t.eof ();
    len

  let is_closed t = Wsd.is_closed t.wsd
  let close t = Wsd.close t.wsd

  let yield_writer t k =
    if is_closed t then (
      close t;
      k ())
    else Wsd.when_ready_to_write t.wsd k

  let report_write_result t result = Wsd.report_result t.wsd result
end

module Handshake = struct
  let compute_accept ~sha1 nonce = sha1 (nonce ^ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

  let get_nonce request = Headers.get request.Request.headers "sec-websocket-key"

  let server_headers ~sha1 ~nonce =
    Headers.of_list
      [ ("connection", "upgrade"); ("upgrade", "websocket")
      ; ("sec-websocket-accept", compute_accept ~sha1 nonce ) ]

  let is_valid_accept_headers ~sha1 ~nonce headers =
    let sec_websocket_accept = Headers.get headers "sec-websocket-accept" in
    let upgrade = Headers.get headers "upgrade" |> Option.map String.lowercase_ascii in
    let connection = Headers.get headers "connection" |> Option.map String.lowercase_ascii in
    (sec_websocket_accept = Some (compute_accept ~sha1 nonce))
    && (upgrade = Some "websocket")
    && (connection = Some "upgrade")
end

module Client_handshake = struct
  type t = { connection : H1_client_connection.t; body : Body.Writer.t }

  (* assumes [nonce] is base64 encoded *)
  let create ~nonce ~host ~port ~resource ~error_handler ~response_handler =
    let headers = Headers.of_list
      [ ("upgrade", "websocket");
        ("connection", "upgrade");
        ("host", String.concat ":" [ host; string_of_int port ]);
        ("sec-websocket-version", "13");
        ("sec-websocket-key", nonce); ]
    in
    let body, connection =
       H1_client_connection.request
        (Request.create ~headers `GET resource)
        ~error_handler ~response_handler
    in
    { connection; body }

  let next_read_operation t =
     H1_client_connection.next_read_operation t.connection

  let next_write_operation t =
     H1_client_connection.next_write_operation t.connection

  let read t = H1_client_connection.read t.connection

  let report_write_result t =
     H1_client_connection.report_write_result t.connection

  let yield_writer t = H1_client_connection.yield_writer t.connection
  let close t = Body.Writer.close t.body

end

module Client_connection = struct
  type state =
    | Uninitialized
    | Handshake of Client_handshake.t
    | Websocket of Connection.t

  type t = state ref

  type error =
    [ H1_client_connection.error
    | `Handshake_failure of Response.t * Body.Reader.t ]

  let handshake_exn t =
    match !t with
    | Handshake handshake -> handshake
    | Uninitialized | Websocket _ -> assert false

  let create ~nonce ~host ~port ~resource ~sha1 ~error_handler ~websocket_handler
      =
    let t = ref Uninitialized in
    let nonce = Base64.encode_exn nonce in
    let response_handler response response_body =
      match response.Response.status with
      | `Switching_protocols when Handshake.is_valid_accept_headers ~sha1 ~nonce response.headers ->
          Body.Reader.close response_body;
          let handshake = handshake_exn t in
          t :=
            Websocket
              (Connection.create
                 ~mode:(`Client (fun () -> Random.int32 Int32.max_int))
                 ~websocket_handler);
          Client_handshake.close handshake
      | _ -> error_handler (`Handshake_failure (response, response_body))
    in
    let handshake =
      let error_handler = (error_handler :> H1_client_connection.error_handler) in
      Client_handshake.create ~nonce ~host ~port ~resource ~error_handler
        ~response_handler
    in
    t := Handshake handshake;
    t

  let next_read_operation t =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.next_read_operation handshake
    | Websocket websocket -> Connection.next_read_operation websocket

  let read t bs ~off ~len =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.read handshake bs ~off ~len
    | Websocket websocket -> Connection.read websocket bs ~off ~len

  let read_eof t bs ~off ~len =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.read handshake bs ~off ~len
    | Websocket websocket -> Connection.read_eof websocket bs ~off ~len

  let next_write_operation t =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.next_write_operation handshake
    | Websocket websocket -> Connection.next_write_operation websocket

  let report_write_result t result =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.report_write_result handshake result
    | Websocket websocket -> Connection.report_write_result websocket result

  let yield_writer t f =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.yield_writer handshake f
    | Websocket websocket -> Connection.yield_writer websocket f

  let close t =
    match !t with
    | Uninitialized -> assert false
    | Handshake handshake -> Client_handshake.close handshake
    | Websocket websocket -> Connection.close websocket
end

module Server_connection = struct
  type t = Connection.t
  type error = [ `Exn of exn ]

  let create ~websocket_handler =
    let t = Connection.create ~mode:`Server ~websocket_handler in
    t

  let next_read_operation = Connection.next_read_operation
  let next_write_operation = Connection.next_write_operation
  let read t bs ~off ~len = Connection.read t bs ~off ~len
  let read_eof t bs ~off ~len = Connection.read_eof t bs ~off ~len
  let report_write_result t result = Connection.report_write_result t result
  let yield_writer t f = Connection.yield_writer t f
  let is_closed t = Connection.is_closed t
  let close t = Connection.close t
end
