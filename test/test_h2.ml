open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let frame_eq (a : H2.frame) (b : H2.frame) =
  a.H2.typ = b.H2.typ
  && a.H2.flags = b.H2.flags
  && a.H2.stream_id = b.H2.stream_id
  && String.equal a.H2.payload b.H2.payload

(* Encode, append trailing bytes, decode: the frame comes back intact and
   the trailer is the unconsumed rest. *)
let roundtrips f =
  H2.encode_frame f
  |> Result.fold
       ~error:(fun _ -> false)
       ~ok:(fun wire ->
         H2.decode_frame (wire ^ "TRAIL")
         |> Result.fold
              ~error:(fun _ -> false)
              ~ok:(fun (g, rest) -> frame_eq f g && String.equal rest "TRAIL"))

let is_incomplete ~need ~have r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | H2.Incomplete { need = n; have = h } -> n = need && h = have
      | H2.Payload_too_long _ | H2.Bad_stream_id _ | H2.Bad_flags _
      | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
          false)
    r

let is_payload_too_long r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | H2.Payload_too_long _ -> true
      | H2.Incomplete _ | H2.Bad_stream_id _ | H2.Bad_flags _
      | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
          false)
    r

let is_settings_length r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | H2.Settings_length _ -> true
      | H2.Incomplete _ | H2.Bad_stream_id _ | H2.Bad_flags _
      | H2.Payload_too_long _ | H2.Bad_envelope_flag _ ->
          false)
    r

let is_bad_envelope_flag r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | H2.Bad_envelope_flag _ -> true
      | H2.Incomplete _ | H2.Bad_stream_id _ | H2.Bad_flags _
      | H2.Payload_too_long _ | H2.Settings_length _ ->
          false)
    r

let frame typ = { H2.typ; flags = 0; stream_id = 1; payload = "pay" }

let all_types =
  [
    H2.Data;
    H2.Headers;
    H2.Priority;
    H2.Rst_stream;
    H2.Settings;
    H2.Push_promise;
    H2.Ping;
    H2.Goaway;
    H2.Window_update;
    H2.Continuation;
    H2.Unknown 0x2a;
  ]

let type_roundtrip_tests =
  List.map
    (fun t ->
      ( Printf.sprintf "frame type roundtrip 0x%02x" (H2.frame_type_to_byte t),
        roundtrips (frame t) ))
    all_types

let payload_of_len n = String.concat "" (List.init n (fun _ -> "a"))

let payload_len_tests =
  List.map
    (fun n ->
      ( Printf.sprintf "payload length %d accepted" n,
        roundtrips
          { H2.typ = H2.Data; flags = 0; stream_id = 3; payload = payload_of_len n }
      ))
    [ 0; 16383; 16384 ]

let settings_pairs = [ (0x1, 4096); (0x4, 65535); (0x5, 16384) ]

let pair_eq (i, v) (i', v') = i = i' && v = v'

let settings_roundtrip =
  H2.decode_settings (H2.encode_settings settings_pairs)
  |> Result.fold
       ~error:(fun _ -> false)
       ~ok:(fun got -> List.equal pair_eq settings_pairs got)

let envelope_roundtrip =
  H2.encode_envelope ~flag:1 "grpc-body"
  |> Result.fold
       ~error:(fun _ -> false)
       ~ok:(fun wire ->
         H2.decode_envelope (wire ^ "XY")
         |> Result.fold
              ~error:(fun _ -> false)
              ~ok:(fun (flag, body, rest) ->
                flag = 1
                && String.equal body "grpc-body"
                && String.equal rest "XY"))

let () =
  let failures =
    List.fold_left
      (fun acc (name, ok) -> acc + check name ok)
      0
      (type_roundtrip_tests @ payload_len_tests
      @ [
          ( "flags byte and max stream id",
            roundtrips
              {
                H2.typ = H2.Headers;
                flags = 0xed;
                stream_id = 0x7fffffff;
                payload = "";
              } );
          ( "reserved bit masked on decode",
            (* header: len 0, type Ping (0x6), flags 0, stream id with the
               reserved top bit set: decodes to 0x00000001 *)
            H2.decode_frame "\x00\x00\x00\x06\x00\x80\x00\x00\x01"
            |> Result.fold
                 ~error:(fun _ -> false)
                 ~ok:(fun (f, rest) ->
                   f.H2.stream_id = 1 && String.equal rest "") );
          ( "payload length 16385 rejected",
            is_payload_too_long
              (H2.encode_frame
                 {
                   H2.typ = H2.Data;
                   flags = 0;
                   stream_id = 3;
                   payload = payload_of_len 16385;
                 }) );
          ( "stream id 0x80000000 rejected on encode",
            H2.encode_frame
              { H2.typ = H2.Data; flags = 0; stream_id = 0x80000000; payload = "" }
            |> Result.fold
                 ~ok:(fun _ -> false)
                 ~error:(fun e ->
                   match e with
                   | H2.Bad_stream_id n -> n = 0x80000000
                   | H2.Incomplete _ | H2.Payload_too_long _ | H2.Bad_flags _
                   | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
                       false) );
          ( "flags 0x100 rejected on encode",
            H2.encode_frame
              { H2.typ = H2.Data; flags = 0x100; stream_id = 1; payload = "" }
            |> Result.fold
                 ~ok:(fun _ -> false)
                 ~error:(fun e ->
                   match e with
                   | H2.Bad_flags n -> n = 0x100
                   | H2.Incomplete _ | H2.Payload_too_long _ | H2.Bad_stream_id _
                   | H2.Settings_length _ | H2.Bad_envelope_flag _ ->
                       false) );
          ( "short header incomplete 9/2",
            is_incomplete ~need:9 ~have:2 (H2.decode_frame "\x00\x00") );
          ( "short payload incomplete 14/12",
            (* header claims a 5-byte payload, only 3 bytes follow *)
            is_incomplete ~need:14 ~have:12
              (H2.decode_frame "\x00\x00\x05\x00\x00\x00\x00\x00\x01abc") );
          ("settings roundtrip", settings_roundtrip);
          ( "settings empty payload",
            H2.decode_settings ""
            |> Result.fold ~error:(fun _ -> false) ~ok:(fun l -> l = []) );
          ( "settings 5-byte payload rejected",
            is_settings_length (H2.decode_settings "\x00\x04\x00\x00\x40") );
          ( "settings initial frame",
            H2.settings_initial.H2.typ = H2.Settings
            && H2.settings_initial.H2.flags = 0
            && H2.settings_initial.H2.stream_id = 0
            && String.equal H2.settings_initial.H2.payload "" );
          ( "settings ack frame",
            H2.settings_ack.H2.typ = H2.Settings
            && H2.settings_ack.H2.flags = 0x1
            && String.equal H2.settings_ack.H2.payload "" );
          ( "client preface",
            String.equal H2.client_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" );
          ("envelope roundtrip", envelope_roundtrip);
          ( "envelope truncated prefix incomplete 5/3",
            is_incomplete ~need:5 ~have:3 (H2.decode_envelope "\x00\x00\x00") );
          ( "envelope truncated body incomplete 9/7",
            is_incomplete ~need:9 ~have:7
              (H2.decode_envelope "\x00\x00\x00\x00\x04ab") );
          ( "envelope flag 2 rejected",
            is_bad_envelope_flag (H2.decode_envelope "\x02\x00\x00\x00\x00") );
          ( "envelope encode flag 2 rejected",
            is_bad_envelope_flag (H2.encode_envelope ~flag:2 "x") );
          ( "prefix int 10 in 5-bit prefix",
            String.equal "\x0a" (H2.encode_prefix_int ~prefix:5 10) );
          ( "prefix int 1337 in 5-bit prefix",
            String.equal "\x1f\x9a\x0a" (H2.encode_prefix_int ~prefix:5 1337) );
          ( "prefix int 42 in 8-bit prefix",
            String.equal "\x2a" (H2.encode_prefix_int ~prefix:8 42) );
          ( "header block custom-key custom-header",
            String.equal "\x00\x0acustom-key\x0dcustom-header"
              (H2.encode_header_block [ ("custom-key", "custom-header") ]) );
        ])
  in
  exit (min failures 1)
