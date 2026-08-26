open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let string_of_chars l = List.to_seq l |> String.of_seq

let drop n s =
  Der.take n (Der.bytes_of_string s)
  |> Option.map (fun (_, rest) -> string_of_chars rest)

(* --- server-side byte builders (the peer the engine talks to) -------- *)

let frame f = H2.encode_frame f |> Result.fold ~error:(fun _ -> "") ~ok:Fun.id

let envelope body =
  H2.encode_envelope ~flag:0 body |> Result.fold ~error:(fun _ -> "") ~ok:Fun.id

let ok_s r = Result.fold ~error:(fun _ -> "") ~ok:Fun.id r

let ld field s =
  ok_s (Pb.encode_key field Pb.Length_delimited)
  ^ ok_s (Pb.encode_varint (String.length s))
  ^ s

let svid_msg =
  ld 1 "spiffe://example.org/wl" ^ ld 2 "CERT" ^ ld 3 "KEY" ^ ld 4 "BUNDLE"

let resp_msg = ld 1 svid_msg

let hb = H2.encode_header_block

let s_settings = frame H2.settings_initial

let s_headers =
  frame
    {
      H2.typ = H2.Headers;
      flags = 0x4;
      stream_id = 1;
      payload = hb [ (":status", "200"); ("content-type", "application/grpc") ];
    }

let s_data =
  frame { H2.typ = H2.Data; flags = 0; stream_id = 1; payload = envelope resp_msg }

let s_trailers ?(status = "0") ?(extra = []) () =
  frame
    {
      H2.typ = H2.Headers;
      flags = 0x5;
      stream_id = 1;
      payload = hb ((( "grpc-status", status )) :: extra);
    }

let script = s_settings ^ s_headers ^ s_data ^ s_trailers ()

(* --- helpers over the engine ----------------------------------------- *)

let ok_feed f t = f t

let failed_with s conn =
  match conn.Wl_client.phase with
  | Wl_client.Failed e -> String.equal (Wl_client.error_to_string e) s
  | Wl_client.Awaiting_headers | Wl_client.Streaming | Wl_client.Closed -> false

let err_is s (conn, _, _) = failed_with s conn

let tag ev =
  match ev with
  | Wl_client.Opened _ -> "O"
  | Wl_client.Response _ -> "R"
  | Wl_client.Finished -> "F"

let tags evs = String.concat "" (List.map tag evs)

let opened = Wl_client.feed Wl_client.initial (s_settings ^ s_headers)
let streaming = (fun (conn, _, _) -> conn) opened

let stepwise s =
  String.fold_left
    (fun (conn, evs, out) c ->
      let conn, ev, out' = Wl_client.feed conn (String.make 1 c) in
      (conn, evs @ ev, out ^ out'))
    (Wl_client.initial, [], "")
    s

let response_ok evs =
  List.exists
    (fun ev ->
      match ev with
      | Wl_client.Response r ->
          List.length r.Pb.svids = 1
          && List.for_all
               (fun s ->
                 String.equal s.Pb.spiffe_id "spiffe://example.org/wl"
                 && String.equal s.Pb.x509_svid "CERT"
                 && String.equal s.Pb.x509_svid_key "KEY"
                 && String.equal s.Pb.bundle "BUNDLE")
               r.Pb.svids
      | Wl_client.Opened _ | Wl_client.Finished -> false)
    evs

(* both window updates for n consumed bytes: stream 0 then stream 1 *)
let window_updates_are n out =
  H2.decode_frame out
  |> Result.fold ~error:(fun _ -> false)
       ~ok:(fun (w0, rest) ->
         H2.decode_frame rest
         |> Result.fold ~error:(fun _ -> false)
              ~ok:(fun (w1, rest2) ->
                w0.H2.typ = H2.Window_update && w0.H2.stream_id = 0
                && String.equal w0.H2.payload (H2.be32 n)
                && w1.H2.typ = H2.Window_update && w1.H2.stream_id = 1
                && String.equal w1.H2.payload (H2.be32 n)
                && String.equal rest2 ""))

let () =
  let failures =
    List.fold_left
      (fun acc (name, ok) -> acc + check name ok)
      0
      [
        ( "request starts with preface and three frames",
          Wl_client.request_bytes ~authority:"localhost"
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun bytes ->
                 String.starts_with ~prefix:H2.client_preface bytes
                 && (drop (String.length H2.client_preface) bytes
                    |> Option.fold ~none:false ~some:(fun rest ->
                           H2.decode_frame rest
                           |> Result.fold ~error:(fun _ -> false)
                                ~ok:(fun (f1, rest) ->
                                  f1.H2.typ = H2.Settings
                                  && H2.decode_frame rest
                                     |> Result.fold ~error:(fun _ -> false)
                                          ~ok:(fun (f2, rest) ->
                                            f2.H2.typ = H2.Headers
                                            && f2.H2.flags = 0x4
                                            && f2.H2.stream_id = 1
                                            && H2.decode_frame rest
                                               |> Result.fold
                                                    ~error:(fun _ -> false)
                                                    ~ok:(fun (f3, rest) ->
                                                      f3.H2.typ = H2.Data
                                                      && f3.H2.flags = 0x1
                                                      && f3.H2.stream_id = 1
                                                      && String.equal f3.H2.payload
                                                           "\x00\x00\x00\x00\x00"
                                                      && String.equal rest "")))))) );
        ( "request headers decode back through hpack",
          Wl_client.request_bytes ~authority:"agent"
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun bytes ->
                 drop (String.length H2.client_preface) bytes
                 |> Option.fold ~none:false ~some:(fun rest ->
                        Result.bind
                          (H2.decode_frame rest |> Result.map_error (fun _ -> ()))
                          (fun (_, rest) ->
                            Result.bind
                              (H2.decode_frame rest
                              |> Result.map_error (fun _ -> ()))
                              (fun (hf, _) ->
                                Hpack.decode_header_block ~max_cap:4096
                                  (Hpack.empty_dyn ~cap:4096) hf.H2.payload
                                |> Result.map_error (fun _ -> ())
                                |> Result.map (fun (hs, _) -> hs)))
                        |> Result.fold ~error:(fun _ -> false)
                             ~ok:(fun hs ->
                               List.equal
                                 (fun (a, b) (c, d) ->
                                   String.equal a c && String.equal b d)
                                 hs
                                 (Wl_client.request_headers ~authority:"agent")))) );
        ( "server settings gets one ack",
          Wl_client.feed Wl_client.initial s_settings
          |> ok_feed (fun (_, evs, out) ->
                 evs = []
                 && H2.decode_frame out
                    |> Result.fold ~error:(fun _ -> false)
                         ~ok:(fun (a, rest) ->
                           a.H2.typ = H2.Settings && a.H2.flags = 0x1
                           && String.equal a.H2.payload ""
                           && String.equal rest "")) );
        ( "settings ack from server needs no reply",
          Wl_client.feed Wl_client.initial (frame H2.settings_ack)
          |> ok_feed (fun (_, evs, out) -> evs = [] && String.equal out "") );
        ( "response headers open the stream",
          opened
          |> ok_feed (fun (conn, evs, _) ->
                 String.equal (tags evs) "O" && conn.Wl_client.phase = Wl_client.Streaming) );
        ( "indexed and incremental server block decodes",
          Wl_client.feed Wl_client.initial
            (s_settings
            ^ frame
                {
                  H2.typ = H2.Headers;
                  flags = 0x4;
                  stream_id = 1;
                  payload = "\x88\x5f\x10application/grpc";
                })
          |> ok_feed (fun (conn, evs, _) ->
                 String.equal (tags evs) "O"
                 && conn.Wl_client.phase = Wl_client.Streaming) );
        ( "data envelope becomes a typed response",
          Wl_client.feed streaming s_data
          |> ok_feed (fun (_, evs, _) -> response_ok evs) );
        ( "data emits both window updates",
          Wl_client.feed streaming s_data
          |> ok_feed (fun (_, _, out) ->
                 window_updates_are (String.length (envelope resp_msg)) out) );
        ( "envelope split across data frames buffers",
          drop 4 (envelope resp_msg)
          |> Option.fold ~none:false ~some:(fun tail_part ->
                 let conn, evs1, _ =
                   Wl_client.feed streaming
                     (frame
                        {
                          H2.typ = H2.Data;
                          flags = 0;
                          stream_id = 1;
                          payload = "\x00\x00\x00\x00";
                        })
                 in
                 let _, evs2, _ =
                   Wl_client.feed conn
                     (frame
                        {
                          H2.typ = H2.Data;
                          flags = 0;
                          stream_id = 1;
                          payload = tail_part;
                        })
                 in
                 evs1 = [] && response_ok evs2) );
        ( "whole script one byte at a time",
          stepwise script
          |> (fun (conn, evs, _) ->
               String.equal (tags evs) "ORF" && response_ok evs
               && conn.Wl_client.phase = Wl_client.Closed) );
        ( "padded data still parses and window covers padding",
          Wl_client.feed streaming
            (frame
               {
                 H2.typ = H2.Data;
                 flags = 0x8;
                 stream_id = 1;
                 payload = "\x03" ^ envelope resp_msg ^ "\x00\x00\x00";
               })
          |> ok_feed (fun (_, evs, out) ->
                 response_ok evs
                 && window_updates_are (String.length (envelope resp_msg) + 4) out) );
        ( "trailers status zero finishes",
          Wl_client.feed streaming (s_trailers ())
          |> ok_feed (fun (conn, evs, _) ->
                 String.equal (tags evs) "F"
                 && conn.Wl_client.phase = Wl_client.Closed) );
        ( "trailers nonzero status is a typed grpc error",
          err_is "grpc_error:8:oops"
            (Wl_client.feed streaming
               (s_trailers ~status:"8" ~extra:[ ("grpc-message", "oops") ] ())) );
        ( "trailers-only response reports the status",
          err_is "grpc_error:12:"
            (Wl_client.feed Wl_client.initial (s_trailers ~status:"12" ())) );
        ( "trailers without grpc-status rejected",
          err_is "bad_trailers"
            (Wl_client.feed streaming
               (frame
                  {
                    H2.typ = H2.Headers;
                    flags = 0x5;
                    stream_id = 1;
                    payload = hb [ ("x", "y") ];
                  })) );
        ( "non-numeric grpc-status rejected",
          err_is "bad_trailers"
            (Wl_client.feed streaming (s_trailers ~status:"abc" ())) );
        ( "status 503 rejected",
          err_is "bad_response:503"
            (Wl_client.feed Wl_client.initial
               (frame
                  {
                    H2.typ = H2.Headers;
                    flags = 0x4;
                    stream_id = 1;
                    payload = hb [ (":status", "503") ];
                  })) );
        ( "ping gets an ack with the same payload",
          Wl_client.feed Wl_client.initial
            (frame
               { H2.typ = H2.Ping; flags = 0; stream_id = 0; payload = "12345678" })
          |> ok_feed (fun (_, evs, out) ->
                 evs = []
                 && H2.decode_frame out
                    |> Result.fold ~error:(fun _ -> false)
                         ~ok:(fun (a, rest) ->
                           a.H2.typ = H2.Ping && a.H2.flags = 0x1
                           && String.equal a.H2.payload "12345678"
                           && String.equal rest "")) );
        ( "goaway is a typed error",
          err_is "goaway:0:2"
            (Wl_client.feed Wl_client.initial
               (frame
                  {
                    H2.typ = H2.Goaway;
                    flags = 0;
                    stream_id = 0;
                    payload = H2.be32 0 ^ H2.be32 2;
                  })) );
        ( "rst_stream on our stream is a typed error",
          err_is "stream_reset:8"
            (Wl_client.feed streaming
               (frame
                  {
                    H2.typ = H2.Rst_stream;
                    flags = 0;
                    stream_id = 1;
                    payload = H2.be32 8;
                  })) );
        ( "compressed envelope rejected",
          err_is "compressed_unsupported"
            (Wl_client.feed streaming
               (frame
                  {
                    H2.typ = H2.Data;
                    flags = 0;
                    stream_id = 1;
                    payload = "\x01\x00\x00\x00\x00";
                  })) );
        ( "end_stream on data is a typed error",
          err_is "no_trailers"
            (Wl_client.feed streaming
               (frame
                  {
                    H2.typ = H2.Data;
                    flags = 0x1;
                    stream_id = 1;
                    payload = envelope resp_msg;
                  })) );
        ( "headers without end_headers rejected",
          err_is "continuation_unsupported"
            (Wl_client.feed Wl_client.initial
               (frame
                  { H2.typ = H2.Headers; flags = 0; stream_id = 1; payload = "" })) );
        ( "priority window_update and unknown frames ignored",
          Wl_client.feed Wl_client.initial
            (frame { H2.typ = H2.Priority; flags = 0; stream_id = 1; payload = "12345" }
            ^ frame
                {
                  H2.typ = H2.Window_update;
                  flags = 0;
                  stream_id = 0;
                  payload = H2.be32 100;
                }
            ^ frame { H2.typ = H2.Unknown 0xfa; flags = 0; stream_id = 0; payload = "z" })
          |> ok_feed (fun (_, evs, out) -> evs = [] && String.equal out "") );
        ( "frames after close are ignored",
          (fun (conn, _, _) -> Wl_client.feed conn (s_data ^ s_headers))
            (Wl_client.feed streaming (s_trailers ()))
          |> (fun (conn, evs, out) ->
               evs = []
               && String.equal out ""
               && conn.Wl_client.phase = Wl_client.Closed) );
        ( "incomplete frame stays buffered",
          drop 0 s_data
          |> Option.fold ~none:false ~some:(fun whole ->
                 Der.take 5 (Der.bytes_of_string whole)
                 |> Option.fold ~none:false ~some:(fun (head, tail) ->
                        let conn, evs1, _ =
                          Wl_client.feed streaming (string_of_chars head)
                        in
                        let _, evs2, _ =
                          Wl_client.feed conn (string_of_chars tail)
                        in
                        evs1 = [] && response_ok evs2)) );
        ( "events survive a goaway in the same read",
          Wl_client.feed streaming
            (s_data
            ^ frame
                {
                  H2.typ = H2.Goaway;
                  flags = 0;
                  stream_id = 0;
                  payload = H2.be32 0 ^ H2.be32 2;
                })
          |> (fun (conn, evs, _) ->
               response_ok evs && failed_with "goaway:0:2" conn) );
        ( "goaway after the trailers is a clean end",
          (fun (conn, _, _) ->
            Wl_client.feed conn
              (frame
                 {
                   H2.typ = H2.Goaway;
                   flags = 0;
                   stream_id = 0;
                   payload = H2.be32 1 ^ H2.be32 0;
                 }))
            (Wl_client.feed streaming (s_trailers ()))
          |> (fun (conn, evs, out) ->
               evs = [] && String.equal out ""
               && conn.Wl_client.phase = Wl_client.Closed) );
        ( "rst_stream after the trailers is a clean end",
          (fun (conn, _, _) ->
            Wl_client.feed conn
              (frame
                 {
                   H2.typ = H2.Rst_stream;
                   flags = 0;
                   stream_id = 1;
                   payload = H2.be32 0;
                 }))
            (Wl_client.feed streaming (s_trailers ()))
          |> (fun (conn, evs, out) ->
               evs = [] && String.equal out ""
               && conn.Wl_client.phase = Wl_client.Closed) );
        ( "zero-length data emits no window update",
          Wl_client.feed streaming
            (frame { H2.typ = H2.Data; flags = 0; stream_id = 1; payload = "" })
          |> (fun (conn, evs, out) ->
               evs = [] && String.equal out ""
               && conn.Wl_client.phase = Wl_client.Streaming) );
        ( "data before the response headers rejected",
          err_is "bad_response:data_before_headers"
            (Wl_client.feed Wl_client.initial s_data) );
        ( "trailers over a buffered partial envelope rejected",
          (fun (conn, _, _) -> Wl_client.feed conn (s_trailers ()))
            (Wl_client.feed streaming
               (frame
                  {
                    H2.typ = H2.Data;
                    flags = 0;
                    stream_id = 1;
                    payload = "\x00\x00\x00\x00";
                  }))
          |> err_is "truncated_message" );
        ( "push_promise rejected",
          err_is "push_unsupported"
            (Wl_client.feed Wl_client.initial
               (frame
                  {
                    H2.typ = H2.Push_promise;
                    flags = 0x4;
                    stream_id = 1;
                    payload = "";
                  })) );
        ( "frames on another stream rejected",
          err_is "unexpected_stream:3"
            (Wl_client.feed Wl_client.initial
               (frame
                  { H2.typ = H2.Headers; flags = 0x4; stream_id = 3; payload = "" })) );
        ( "request advertises push disabled",
          Wl_client.request_bytes ~authority:"a"
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun bytes ->
                 drop (String.length H2.client_preface) bytes
                 |> Option.fold ~none:false ~some:(fun rest ->
                        H2.decode_frame rest
                        |> Result.fold ~error:(fun _ -> false)
                             ~ok:(fun (sf, _) ->
                               H2.decode_settings sf.H2.payload
                               |> Result.fold ~error:(fun _ -> false)
                                    ~ok:(fun ps -> ps = [ (2, 0) ])))) );
        ( "headers after close still update the dynamic table",
          (fun (conn, _, _) ->
            Wl_client.feed conn
              (frame
                 {
                   H2.typ = H2.Headers;
                   flags = 0x4;
                   stream_id = 1;
                   payload = "\x40\x01k\x01v";
                 }))
            (Wl_client.feed streaming (s_trailers ()))
          |> (fun (conn, evs, _) ->
               evs = []
               && conn.Wl_client.dyn.Hpack.size = 34
               && conn.Wl_client.phase = Wl_client.Closed) );
      ]
  in
  exit (min failures 1)
