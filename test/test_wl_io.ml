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

(* --- a real DER root for the rotation cases (as in test_x509) -------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

let byte n =
  String.to_seq byte_table |> Seq.drop n |> Seq.uncons
  |> Option.fold ~none:"POISON" ~some:(fun (c, _) -> String.make 1 c)

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

let svid_bundle_msg id bundle = ld 1 id ^ ld 2 "CERT" ^ ld 3 "KEY" ^ ld 4 bundle

let s_data_bundle id bundle =
  frame
    {
      H2.typ = H2.Data;
      flags = 0;
      stream_id = 1;
      payload = envelope (ld 1 (svid_bundle_msg id bundle));
    }

let rotation_script =
  s_settings ^ s_headers
  ^ s_data_bundle "spiffe://example.org/a" root_der
  ^ s_trailers "0"

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
                              | Wl_io.Client _ | Wl_io.Rotation _ ->
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
        ( "watch_rotation folds a response into fresh typed state",
          with_pair rotation_script (fun a _ ->
              Trust_domain.parse "example.org"
              |> Result.fold ~error:(fun _ -> false)
                   ~ok:(fun td ->
                     Wl_io.watch_rotation a ~authority:"agent"
                       ~init:(Rotation.create ~td ~epoch:(Bundle.Epoch 3))
                     |> Result.fold ~error:(fun _ -> false)
                          ~ok:(fun st ->
                            Rotation.usable st
                            |> Option.fold ~none:false ~some:(fun u ->
                                   let (Bundle.Roots rs) =
                                     Bundle.usable_roots u
                                   in
                                   Bundle.epoch_value (Bundle.usable_epoch u)
                                   = 3
                                   && List.equal String.equal rs [ root_der ]))))
        );
        ( "watch_rotation fails closed on bad bundle bytes",
          with_pair one_script (fun a _ ->
              Trust_domain.parse "example.org"
              |> Result.fold ~error:(fun _ -> false)
                   ~ok:(fun td ->
                     Wl_io.watch_rotation a ~authority:"agent"
                       ~init:(Rotation.create ~td ~epoch:(Bundle.Epoch 0))
                     |> Result.fold ~ok:(fun _ -> false)
                          ~error:(fun e ->
                            match e with
                            | Wl_io.Rotation (Rotation.Bad_bundle _) -> true
                            | Wl_io.Rotation
                                ( Rotation.No_svid_for_domain
                                | Rotation.Bad_svid_id _ )
                            | Wl_io.Io _ | Wl_io.Client _ ->
                                false))) );
      ]
  in
  exit (min failures 1)
