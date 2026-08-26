open Tinysvid
open Tinysvid_io

let () = Uds.ignore_sigpipe ()

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- server-side bytes (same builders as the engine suite) ----------- *)

let frame f = H2.encode_frame f |> Result.fold ~error:(fun _ -> "") ~ok:Fun.id

let envelope body =
  H2.encode_envelope ~flag:0 body |> Result.fold ~error:(fun _ -> "") ~ok:Fun.id

let ok_s r = Result.fold ~error:(fun _ -> "") ~ok:Fun.id r

let ld field s =
  ok_s (Pb.encode_key field Pb.Length_delimited)
  ^ ok_s (Pb.encode_varint (String.length s))
  ^ s

let svid_msg id = ld 1 id ^ ld 2 "CERT" ^ ld 3 "KEY" ^ ld 4 "BUNDLE"

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

let s_data id =
  frame
    { H2.typ = H2.Data; flags = 0; stream_id = 1; payload = envelope (ld 1 (svid_msg id)) }

let s_trailers status =
  frame
    {
      H2.typ = H2.Headers;
      flags = 0x5;
      stream_id = 1;
      payload = H2.encode_header_block [ ("grpc-status", status) ];
    }

let s_settings = frame H2.settings_initial

let one_script = s_settings ^ s_headers ^ s_data "spiffe://example.org/a" ^ s_trailers "0"

let two_script =
  s_settings ^ s_headers
  ^ s_data "spiffe://example.org/a"
  ^ s_data "spiffe://example.org/b"
  ^ s_trailers "0"

(* One socketpair per case: preload the server side, run the client. *)
let with_pair script f =
  Uds.pair ()
  |> Result.fold ~error:(fun _ -> false)
       ~ok:(fun (a, b) ->
         let preloaded = Uds.write_all b script in
         let out =
           Result.fold ~error:(fun _ -> false)
             ~ok:(fun () -> f a b)
             preloaded
         in
         Uds.close a;
         Uds.close b;
         out)

let first_id r =
  List.find_map (fun s -> Some s.Pb.spiffe_id) r.Pb.svids
  |> Option.fold ~none:"" ~some:Fun.id

let () =
  let failures =
    List.fold_left
      (fun acc (name, ok) -> acc + check name ok)
      0
      [
        ( "fetch returns the first typed response",
          with_pair one_script (fun a _ ->
              Wl_io.fetch a ~authority:"agent"
              |> Result.fold ~error:(fun _ -> false)
                   ~ok:(fun r -> String.equal (first_id r) "spiffe://example.org/a")) );
        ( "fetch stops at the first of two responses",
          with_pair two_script (fun a _ ->
              Wl_io.fetch a ~authority:"agent"
              |> Result.fold ~error:(fun _ -> false)
                   ~ok:(fun r -> String.equal (first_id r) "spiffe://example.org/a")) );
        ( "watch delivers every response then finishes",
          with_pair two_script (fun a _ ->
              let seen = ref [] in
              Wl_io.watch a ~authority:"agent" ~on_response:(fun r ->
                  seen := first_id r :: !seen)
              |> Result.fold ~error:(fun _ -> false)
                   ~ok:(fun () ->
                     List.rev !seen
                     = [ "spiffe://example.org/a"; "spiffe://example.org/b" ])) );
        ( "grpc failure surfaces as a client error",
          with_pair (s_settings ^ s_headers ^ s_trailers "8") (fun a _ ->
              Wl_io.fetch a ~authority:"agent"
              |> Result.fold ~ok:(fun _ -> false)
                   ~error:(fun e ->
                     String.equal (Wl_io.error_to_string e) "client:grpc_error:8:")) );
        ( "eof before any response is an io error",
          Uds.pair ()
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun (a, b) ->
                 let preloaded =
                   Result.bind (Uds.write_all b (s_settings ^ s_headers))
                     (fun () -> Uds.shutdown_send b)
                 in
                 let out =
                   Result.fold ~error:(fun _ -> false)
                     ~ok:(fun () ->
                       Wl_io.fetch a ~authority:"agent"
                       |> Result.fold ~ok:(fun _ -> false)
                            ~error:(fun e ->
                              match e with
                              | Wl_io.Io Uds.Eof -> true
                              | Wl_io.Io (Uds.Path_too_long _)
                              | Wl_io.Io (Uds.Sys _)
                              | Wl_io.Client _ ->
                                  false))
                     preloaded
                 in
                 Uds.close a;
                 Uds.close b;
                 out) );
        ( "the wire carries the request then the acks",
          with_pair one_script (fun a b ->
              Result.bind
                (Wl_client.request_bytes ~authority:"agent"
                |> Result.map_error (fun _ -> ()))
                (fun req ->
                  Result.bind
                    (Wl_io.fetch a ~authority:"agent"
                    |> Result.map_error (fun _ -> ()))
                    (fun _ ->
                      Result.bind
                        (Uds.read_exactly b ~len:(String.length req)
                        |> Result.map_error (fun _ -> ()))
                        (fun got ->
                          Result.bind
                            (Uds.read_some b ~max:64
                            |> Result.map_error (fun _ -> ()))
                            (fun after ->
                              Result.bind
                                (H2.decode_frame after
                                |> Result.map_error (fun _ -> ()))
                                (fun (ack, _) ->
                                  Ok
                                    (String.equal got req
                                    && ack.H2.typ = H2.Settings
                                    && ack.H2.flags = 0x1))))))
              |> Result.fold ~error:(fun _ -> false) ~ok:Fun.id) );
      ]
  in
  exit (min failures 1)
