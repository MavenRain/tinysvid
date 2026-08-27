(* M28: a one-shot fake Workload API agent for the end-to-end demo.
   It binds a Unix-domain socket, serves exactly one connection, then
   exits. It holds the client to what a real spire-agent requires at
   the door: the HTTP/2 preface, a HEADERS frame whose block decodes
   through the HPACK decoder and carries the FetchX509SVID path and
   the workload.spiffe.io security header, and the request
   half-close. Only a verified request gets the response. Mode bad
   serves a truncated protobuf body: the client must fail closed, and
   the demo script uses that as one negative control. Mode
   emptybundle serves an SVID whose bundle field is empty: the
   client-side bundle parse must reject it. *)

open Tinysvid
open Tinysvid_io

type mode = Good | Truncated | No_bundle

(* --- response bytes (the same builders the engine suite pins) ------- *)

let ok_s r = Result.fold ~error:(fun _ -> "") ~ok:Fun.id r
let frame f = H2.encode_frame f |> ok_s
let envelope body = H2.encode_envelope ~flag:0 body |> ok_s

let ld field s =
  ok_s (Pb.encode_key field Pb.Length_delimited)
  ^ ok_s (Pb.encode_varint (String.length s))
  ^ s

(* --- a real DER root (the test_x509 shape) -------------------------- *)

(* H2.byte is the total byte-to-string lookup the whole library
   uses; no local table. *)
let byte = H2.byte

let len_bytes n =
  match () with
  | () when n < 0x80 -> byte n
  | () when n < 0x100 -> "\x81" ^ byte n
  | () when n < 0x10000 -> "\x82" ^ byte (n lsr 8) ^ byte (n land 0xff)
  | () -> "POISON"

let tlv tag body = tag ^ len_bytes (String.length body) ^ body
let der_seq parts = tlv "\x30" (String.concat "" parts)
let octets body = tlv "\x04" body
let oid body = tlv "\x06" body
let alg_ed = der_seq [ oid "\x2b\x65\x70" ]

let root_der =
  der_seq
    [
      der_seq
        [
          tlv "\xa0" (tlv "\x02" "\x02");
          tlv "\x02" "\x01";
          alg_ed;
          der_seq [ tlv "\x0c" "root" ];
          der_seq [ tlv "\x17" "250101000000Z"; tlv "\x17" "260101000000Z" ];
          der_seq [ tlv "\x0c" "root" ];
          der_seq [ alg_ed; tlv "\x03" "\x00K_ROOT" ];
          tlv "\xa3"
            (der_seq
               [
                 der_seq
                   [ oid "\x55\x1d\x13"; octets (der_seq [ tlv "\x01" "\xff" ]) ];
                 der_seq [ oid "\x55\x1d\x0f"; octets (tlv "\x03" "\x02\x04") ];
               ]);
        ];
      alg_ed;
      tlv "\x03" "\x00SIG";
    ]

let demo_id = "spiffe://example.org/demo"

let svid_msg ~bundle =
  ld 1 demo_id ^ ld 2 root_der ^ ld 3 (String.make 32 'K') ^ ld 4 bundle

let truncate_last s =
  String.to_seq s |> Seq.take (max 0 (String.length s - 1)) |> String.of_seq

let body_of_mode mode =
  match mode with
  | Good -> ld 1 (svid_msg ~bundle:root_der)
  | Truncated -> truncate_last (ld 1 (svid_msg ~bundle:root_der))
  | No_bundle -> ld 1 (svid_msg ~bundle:"")

let s_settings = frame H2.settings_initial

let s_headers =
  frame
    {
      H2.typ = H2.Headers;
      flags = 0x4;
      stream_id = 1;
      payload =
        H2.encode_header_block
          [ (":status", "200"); ("content-type", "application/grpc") ];
    }

let s_data body =
  frame { H2.typ = H2.Data; flags = 0; stream_id = 1; payload = envelope body }

let s_trailers =
  frame
    {
      H2.typ = H2.Headers;
      flags = 0x5;
      stream_id = 1;
      payload = H2.encode_header_block [ ("grpc-status", "0") ];
    }

let response_script mode =
  s_settings ^ s_headers ^ s_data (body_of_mode mode) ^ s_trailers

(* --- request verification ------------------------------------------- *)

let rpc_path = "/SpiffeWorkloadAPI/FetchX509SVID"
let has name value hs = List.exists (fun (n, v) -> n = name && v = value) hs

let verify_headers hs =
  match () with
  | () when not (has ":path" rpc_path hs) -> Error "request missing rpc path"
  | () when not (has "workload.spiffe.io" "true" hs) ->
      Error "request missing security header"
  | () -> Ok ()

type request_state = { verified : bool; closed : bool }

let end_stream (f : H2.frame) = f.H2.stream_id = 1 && f.H2.flags land 0x1 <> 0

let step st (f : H2.frame) =
  match f.H2.typ with
  | H2.Headers ->
      Result.bind
        (Hpack.decode_header_block ~max_cap:4096
           (Hpack.empty_dyn ~cap:4096)
           f.H2.payload
        |> Result.map_error (fun e -> "hpack:" ^ Hpack.error_to_string e))
        (fun (hs, _) ->
          verify_headers hs
          |> Result.map (fun () ->
                 { verified = true; closed = st.closed || end_stream f }))
  | H2.Data -> Ok { st with closed = st.closed || end_stream f }
  | H2.Priority | H2.Rst_stream | H2.Settings | H2.Push_promise | H2.Ping
  | H2.Goaway | H2.Window_update | H2.Continuation | H2.Unknown _ ->
      Ok st

let rec parse_frames st buf =
  H2.decode_frame buf
  |> Result.fold
       ~ok:(fun (f, rest) ->
         Result.bind (step st f) (fun st -> parse_frames st rest))
       ~error:(fun e ->
         match e with
         | H2.Incomplete _ -> Ok (st, buf)
         | H2.Payload_too_long _ | H2.Bad_stream_id _ | H2.Bad_flags _
         | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
             Error ("frame:" ^ H2.error_to_string e))

let rec await_request conn st buf =
  match () with
  | () when st.verified && st.closed -> Ok ()
  | () ->
      Result.bind
        (Uds.read_some conn ~max:16384
        |> Result.map_error (fun e -> "read:" ^ Uds.error_to_string e))
        (fun chunk ->
          Result.bind
            (parse_frames st (buf ^ chunk))
            (fun (st, buf) -> await_request conn st buf))

(* Keep reading until the client closes, so its last writes (the
   SETTINGS ack) never hit a closed socket. Any error ends the drain. *)
let rec drain conn =
  Uds.read_some conn ~max:4096
  |> Result.fold ~ok:(fun _ -> drain conn) ~error:(fun _ -> ())

let serve listener mode =
  Result.bind
    (Uds.accept listener
    |> Result.map_error (fun e -> "accept:" ^ Uds.error_to_string e))
    (fun conn ->
      let outcome =
        Result.bind
          (Uds.read_exactly conn ~len:(String.length H2.client_preface)
          |> Result.map_error (fun e -> "read:" ^ Uds.error_to_string e))
          (fun preface ->
            match () with
            | () when not (String.equal preface H2.client_preface) ->
                Error "bad client preface"
            | () ->
                Result.bind
                  (await_request conn { verified = false; closed = false } "")
                  (fun () ->
                    Result.bind
                      (Uds.write_all conn (response_script mode)
                      |> Result.map_error (fun e ->
                             "write:" ^ Uds.error_to_string e))
                      (fun () ->
                        Uds.shutdown_send conn
                        |> Result.map_error (fun e ->
                               "shutdown:" ^ Uds.error_to_string e)
                        |> Result.map (fun () -> drain conn))))
      in
      Uds.close conn;
      outcome)

let mode_of_string s =
  match s with
  | "bad" -> Some Truncated
  | "emptybundle" -> Some No_bundle
  | _ -> None

let usage = "usage: fake_agent SOCKET_PATH [bad|emptybundle]"

let config () =
  match Array.to_list Sys.argv with
  | [ _; p ] -> Ok (p, Good)
  | [ _; p; m ] ->
      mode_of_string m
      |> Option.to_result ~none:usage
      |> Result.map (fun m -> (p, m))
  | _ -> Error usage

let () =
  Uds.ignore_sigpipe ();
  config ()
  |> Result.fold
       ~error:(fun msg ->
         prerr_endline msg;
         exit 2)
       ~ok:(fun (path, mode) ->
         Result.bind
           (Uds.listen ~path ~backlog:1
           |> Result.map_error (fun e -> "listen:" ^ Uds.error_to_string e))
           (fun listener ->
             let r = serve listener mode in
             Uds.close_listener listener;
             r)
         |> Result.fold
              ~ok:(fun () -> exit 0)
              ~error:(fun msg ->
                prerr_endline ("fake_agent: " ^ msg);
                exit 1))
