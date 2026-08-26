(* M24 stage B: pure Workload API client engine. One gRPC call:
   FetchX509SVID on the SPIFFE Workload API, a server-streaming RPC, so
   one HTTP/2 stream (id 1) carries one request message and then a
   stream of X509SVIDResponse messages until the trailers. The engine
   is a step machine: request_bytes builds everything the client sends
   first; feed consumes received bytes and returns the new state, the
   decoded events in order, and the bytes to write back (SETTINGS ack,
   PING ack, WINDOW_UPDATE). feed is total: a protocol failure moves
   the connection into the Failed phase instead of dropping the events
   already decoded from the same read, so a response followed by a
   GOAWAY in one read still delivers the response. No IO here; the io
   library owns the socket. *)

type error =
  | Frame of H2.error
  | Field of Hpack.error
  | Message of Pb.error
  | Goaway of { last_stream : int; code : int }
  | Stream_reset of int
  | Continuation_unsupported
  | Compressed_unsupported
  | Push_unsupported
  | Unexpected_stream of int
  | Bad_response of string
  | Bad_trailers
  | Bad_frame_padding
  | No_trailers
  | Truncated_message
  | Grpc_error of { status : int; message : string }

let error_to_string e =
  match e with
  | Frame f -> "frame:" ^ H2.error_to_string f
  | Field f -> "field:" ^ Hpack.error_to_string f
  | Message m -> "message:" ^ Pb.error_to_string m
  | Goaway { last_stream; code } ->
      Printf.sprintf "goaway:%d:%d" last_stream code
  | Stream_reset code -> Printf.sprintf "stream_reset:%d" code
  | Continuation_unsupported -> "continuation_unsupported"
  | Compressed_unsupported -> "compressed_unsupported"
  | Push_unsupported -> "push_unsupported"
  | Unexpected_stream sid -> Printf.sprintf "unexpected_stream:%d" sid
  | Bad_response s -> "bad_response:" ^ s
  | Bad_trailers -> "bad_trailers"
  | Bad_frame_padding -> "bad_frame_padding"
  | No_trailers -> "no_trailers"
  | Truncated_message -> "truncated_message"
  | Grpc_error { status; message } ->
      Printf.sprintf "grpc_error:%d:%s" status message

(* Failed is terminal: feed stops parsing and later input is dropped. *)
type phase = Awaiting_headers | Streaming | Closed | Failed of error

type conn = {
  buf : string;      (* received bytes not yet parsed as frames *)
  dyn : Hpack.dyn;   (* HPACK decoder table for received header blocks *)
  phase : phase;
  partial : string;  (* DATA bytes not yet a whole gRPC envelope *)
}

type event =
  | Opened of (string * string) list
  | Response of Pb.x509_svid_response
  | Finished

let string_of_chars = Der.string_of_chars

(* --- the request ----------------------------------------------------- *)

let rpc_path = "/SpiffeWorkloadAPI/FetchX509SVID"

(* The workload.spiffe.io header is the Workload API security header:
   the agent rejects a call without it. *)
let request_headers ~authority =
  [
    (":method", "POST");
    (":scheme", "http");
    (":path", rpc_path);
    (":authority", authority);
    ("content-type", "application/grpc");
    ("te", "trailers");
    ("workload.spiffe.io", "true");
  ]

let flag_end_stream = 0x1
let flag_end_headers = 0x4
let flag_ack = 0x1
let flag_padded = 0x8
let flag_priority = 0x20

(* SETTINGS_ENABLE_PUSH = 0: the engine rejects PUSH_PROMISE, so the
   peer must not be allowed to open pushed streams (their header
   blocks would have to run through our HPACK state). *)
let client_settings =
  {
    H2.typ = H2.Settings;
    flags = 0;
    stream_id = 0;
    payload = H2.encode_settings [ (0x2, 0) ];
  }

(* Everything the client sends up front: connection preface, SETTINGS
   with push disabled, the request headers (END_HEADERS), and the one
   request message (an empty X509SVIDRequest in a plain envelope,
   END_STREAM: the client half-closes and then only reads). *)
let request_bytes ~authority =
  Result.map_error
    (fun e -> Frame e)
    (Result.bind (H2.encode_frame client_settings) (fun sf ->
         Result.bind
           (H2.encode_frame
              {
                H2.typ = H2.Headers;
                flags = flag_end_headers;
                stream_id = 1;
                payload = H2.encode_header_block (request_headers ~authority);
              })
           (fun hf ->
             Result.bind
               (H2.encode_envelope ~flag:0 (Pb.encode_x509_svid_request ()))
               (fun env ->
                 H2.encode_frame
                   {
                     H2.typ = H2.Data;
                     flags = flag_end_stream;
                     stream_id = 1;
                     payload = env;
                   }
                 |> Result.map (fun df -> H2.client_preface ^ sf ^ hf ^ df)))))

let initial =
  { buf = ""; dyn = Hpack.empty_dyn ~cap:4096; phase = Awaiting_headers; partial = "" }

(* --- small total helpers --------------------------------------------- *)

let find_header name headers =
  List.find_opt (fun (n, _) -> String.equal n name) headers
  |> Option.map (fun (_, v) -> v)

(* Decimal digits only, at least one; None otherwise. *)
let dec_int s =
  match () with
  | () when String.length s = 0 -> None
  | () ->
      String.fold_left
        (fun acc c ->
          Option.bind acc (fun n ->
              match () with
              | () when c >= '0' && c <= '9' ->
                  Some ((n * 10) + (Char.code c - 48))
              | () -> None))
        (Some 0) s

(* Strip the PADDED layout: one pad-length byte first, that many bytes
   of padding last (RFC 9113 section 6.1). *)
let strip_pad ~flags cs =
  match () with
  | () when flags land flag_padded = 0 -> Ok cs
  | () -> (
      match cs with
      | [] -> Error Bad_frame_padding
      | p :: rest ->
          let n = List.length rest - Char.code p in
          Result.bind
            (match () with
            | () when n < 0 -> Error Bad_frame_padding
            | () -> Ok n)
            (fun n ->
              Der.take n rest
              |> Option.to_result ~none:Bad_frame_padding
              |> Result.map (fun (body, _) -> body)))

(* A HEADERS payload may also carry the PRIORITY layout: five bytes of
   dependency and weight before the fragment (RFC 9113 section 6.2). *)
let headers_fragment ~flags payload =
  Result.bind (strip_pad ~flags (Der.bytes_of_string payload)) (fun cs ->
      match () with
      | () when flags land flag_priority <> 0 ->
          Der.take 5 cs
          |> Option.to_result ~none:Bad_frame_padding
          |> Result.map (fun (_, rest) -> string_of_chars rest)
      | () -> Ok (string_of_chars cs))

let window_update ~stream n =
  H2.encode_frame
    { H2.typ = H2.Window_update; flags = 0; stream_id = stream; payload = H2.be32 n }
  |> Result.map_error (fun e -> Frame e)

(* --- received header blocks ------------------------------------------ *)

let check_response headers =
  Result.bind
    (find_header ":status" headers |> Option.to_result ~none:(Bad_response "no_status"))
    (fun status ->
      match () with
      | () when not (String.equal status "200") -> Error (Bad_response status)
      | () ->
          Result.bind
            (find_header "content-type" headers
            |> Option.to_result ~none:(Bad_response "no_content_type"))
            (fun ct ->
              if String.starts_with ~prefix:"application/grpc" ct then Ok ()
              else Error (Bad_response ct)))

let close_of headers =
  Result.bind
    (find_header "grpc-status" headers |> Option.to_result ~none:Bad_trailers)
    (fun v ->
      Result.bind (dec_int v |> Option.to_result ~none:Bad_trailers) (fun status ->
          match () with
          | () when status = 0 -> Ok ()
          | () ->
              Error
                (Grpc_error
                   {
                     status;
                     message =
                       find_header "grpc-message" headers
                       |> Option.fold ~none:"" ~some:Fun.id;
                   })))

(* --- gRPC envelopes out of DATA -------------------------------------- *)

(* Total: whatever fails, the responses already decoded from this
   buffer survive. Events come back newest first. *)
let rec drain_envelopes partial events =
  H2.decode_envelope partial
  |> Result.fold
       ~ok:(fun (flag, body, rest) ->
         match () with
         | () when flag <> 0 -> (partial, events, Some Compressed_unsupported)
         | () ->
             Pb.decode_x509_svid_response body
             |> Result.fold
                  ~ok:(fun r -> drain_envelopes rest (Response r :: events))
                  ~error:(fun e -> (partial, events, Some (Message e))))
       ~error:(fun e ->
         match e with
         | H2.Incomplete _ -> (partial, events, None)
         | H2.Payload_too_long _ | H2.Bad_stream_id _ | H2.Bad_flags _
         | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
             (partial, events, Some (Frame e)))

(* --- one frame ------------------------------------------------------- *)

let fail conn e = ({ conn with phase = Failed e; buf = "" }, [], "")
let ok3 conn = (conn, [], "")

(* handle : conn -> H2.frame -> conn * event list * string. Total; a
   protocol failure lands in the Failed phase. The event list is in
   arrival order. *)
let handle conn (f : H2.frame) =
  match f.H2.typ with
  | H2.Settings -> (
      match () with
      | () when f.H2.flags land flag_ack <> 0 -> ok3 conn
      | () ->
          H2.decode_settings f.H2.payload
          |> Result.fold
               ~error:(fun e -> fail conn (Frame e))
               ~ok:(fun _ ->
                 H2.encode_frame H2.settings_ack
                 |> Result.fold
                      ~error:(fun e -> fail conn (Frame e))
                      ~ok:(fun ack -> (conn, [], ack))))
  | H2.Ping -> (
      match () with
      | () when f.H2.flags land flag_ack <> 0 -> ok3 conn
      | () ->
          H2.encode_frame
            { H2.typ = H2.Ping; flags = flag_ack; stream_id = 0; payload = f.H2.payload }
          |> Result.fold
               ~error:(fun e -> fail conn (Frame e))
               ~ok:(fun ack -> (conn, [], ack)))
  | H2.Goaway -> (
      (* after a clean close a GOAWAY is the normal end of the
         connection, not a failure *)
      match () with
      | () when conn.phase = Closed -> ok3 conn
      | () ->
          let cs = Der.bytes_of_string f.H2.payload in
          Option.bind (H2.take_be 4 cs) (fun (last, r) ->
              H2.take_be 4 r |> Option.map (fun (code, _) -> (last, code)))
          |> Option.fold
               ~none:(Frame (H2.Incomplete { need = 8; have = List.length cs }))
               ~some:(fun (last, code) ->
                 Goaway { last_stream = last land H2.max_stream_id; code })
          |> fail conn)
  | H2.Rst_stream -> (
      match () with
      | () when f.H2.stream_id <> 1 -> ok3 conn
      | () when conn.phase = Closed -> ok3 conn
      | () ->
          let cs = Der.bytes_of_string f.H2.payload in
          H2.take_be 4 cs
          |> Option.fold
               ~none:(Frame (H2.Incomplete { need = 4; have = List.length cs }))
               ~some:(fun (code, _) -> Stream_reset code)
          |> fail conn)
  | H2.Headers -> (
      match () with
      | () when f.H2.stream_id <> 1 ->
          (* push is disabled and the client opened only stream 1, so
             another stream id is a protocol violation; skipping its
             header block would also desynchronise the HPACK state *)
          fail conn (Unexpected_stream f.H2.stream_id)
      | () when f.H2.flags land flag_end_headers = 0 -> fail conn Continuation_unsupported
      | () ->
          headers_fragment ~flags:f.H2.flags f.H2.payload
          |> Result.fold
               ~error:(fail conn)
               ~ok:(fun block ->
                 Hpack.decode_header_block ~max_cap:4096 conn.dyn block
                 |> Result.fold
                      ~error:(fun e -> fail conn (Field e))
                      ~ok:(fun (headers, dyn) ->
                        let conn = { conn with dyn } in
                        match conn.phase with
                        | Failed _ -> ok3 conn
                        | Closed ->
                            (* HPACK state is connection-wide: the block
                               above went through the decoder to keep it
                               in step, but nothing is delivered *)
                            ok3 conn
                        | Streaming -> (
                            (* the trailers; in gRPC the only HEADERS
                               after the response headers *)
                            match () with
                            | () when not (String.equal conn.partial "") ->
                                fail conn Truncated_message
                            | () ->
                                close_of headers
                                |> Result.fold ~error:(fail conn)
                                     ~ok:(fun () ->
                                       ({ conn with phase = Closed }, [ Finished ], "")))
                        | Awaiting_headers -> (
                            match () with
                            | () when f.H2.flags land flag_end_stream <> 0 ->
                                (* trailers-only response: the status
                                   arrives without response headers *)
                                close_of headers
                                |> Result.fold ~error:(fail conn)
                                     ~ok:(fun () ->
                                       ({ conn with phase = Closed }, [ Finished ], ""))
                            | () ->
                                check_response headers
                                |> Result.fold ~error:(fail conn)
                                     ~ok:(fun () ->
                                       ( { conn with phase = Streaming },
                                         [ Opened headers ],
                                         "" ))))))
  | H2.Data -> (
      match () with
      | () when f.H2.stream_id <> 1 ->
          (* also covers flow control: unlike an ignored frame, a
             rejected one cannot leak connection window *)
          fail conn (Unexpected_stream f.H2.stream_id)
      | () when conn.phase = Closed -> ok3 conn
      | () when conn.phase = Awaiting_headers ->
          (* a message before the response headers would bypass the
             :status and content-type checks *)
          fail conn (Bad_response "data_before_headers")
      | () when f.H2.flags land flag_end_stream <> 0 ->
          (* gRPC ends a stream in the trailers, never in DATA *)
          fail conn No_trailers
      | () ->
          strip_pad ~flags:f.H2.flags (Der.bytes_of_string f.H2.payload)
          |> Result.fold
               ~error:(fail conn)
               ~ok:(fun body ->
                 let partial, events_rev, erro =
                   drain_envelopes (conn.partial ^ string_of_chars body) []
                 in
                 let conn = { conn with partial } in
                 let events = List.rev events_rev in
                 let consumed = String.length f.H2.payload in
                 (* an increment of zero is itself a protocol error on
                    the receiving side (RFC 9113 section 6.9) *)
                 let updates =
                   match () with
                   | () when consumed = 0 -> Ok ""
                   | () ->
                       Result.bind (window_update ~stream:0 consumed) (fun w0 ->
                           window_update ~stream:1 consumed
                           |> Result.map (fun w1 -> w0 ^ w1))
                 in
                 Option.fold erro
                   ~none:
                     (updates
                     |> Result.fold
                          ~error:(fun e ->
                            ({ conn with phase = Failed e; buf = "" }, events, ""))
                          ~ok:(fun out -> (conn, events, out)))
                   ~some:(fun e ->
                     ({ conn with phase = Failed e; buf = "" }, events, ""))))
  | H2.Continuation -> fail conn Continuation_unsupported
  | H2.Push_promise -> fail conn Push_unsupported
  | H2.Priority | H2.Window_update | H2.Unknown _ -> ok3 conn

(* feed : conn -> string -> conn * event list * string. Total. Parse
   whole frames out of the buffer; an Incomplete frame stays buffered
   for the next feed; a failure stops parsing but keeps every event
   decoded so far (the Failed phase carries the error). The handle
   event lists are in order, so rev_append onto the newest-first
   accumulator keeps global order and one List.rev finishes. *)
let feed conn input =
  let rec go conn events out =
    match conn.phase with
    | Failed _ -> (conn, List.rev events, out)
    | Awaiting_headers | Streaming | Closed ->
        H2.decode_frame conn.buf
        |> Result.fold
             ~error:(fun e ->
               match e with
               | H2.Incomplete _ -> (conn, List.rev events, out)
               | H2.Payload_too_long _ | H2.Bad_stream_id _ | H2.Bad_flags _
               | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
                   ({ conn with phase = Failed (Frame e); buf = "" },
                    List.rev events, out))
             ~ok:(fun (f, rest) ->
               let conn, ev, out' = handle { conn with buf = rest } f in
               go conn (List.rev_append ev events) (out ^ out'))
  in
  go { conn with buf = conn.buf ^ input } [] ""
