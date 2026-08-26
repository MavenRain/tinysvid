open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- hand-built wire bytes (test_chain byte_table idiom) ------------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

let byte n =
  String.to_seq byte_table
  |> Seq.drop (n land 0xff)
  |> Seq.uncons
  |> Option.fold ~none:"POISON" ~some:(fun (c, _) -> String.make 1 c)

(* length-delimited payload with a single-byte length (all bodies here
   are under 128 bytes) *)
let ld body = byte (String.length body) ^ body

(* --- matchers -------------------------------------------------------- *)

let is_truncated_varint r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Truncated_varint -> true
      | Pb.Varint_too_long | Pb.Negative_varint _ | Pb.Group_wire_type _
      | Pb.Invalid_wire_type _ | Pb.Truncated_field _ ->
          false)
    r

let is_varint_too_long r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Varint_too_long -> true
      | Pb.Truncated_varint | Pb.Negative_varint _ | Pb.Group_wire_type _
      | Pb.Invalid_wire_type _ | Pb.Truncated_field _ ->
          false)
    r

let is_negative_varint r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Negative_varint _ -> true
      | Pb.Truncated_varint | Pb.Varint_too_long | Pb.Group_wire_type _
      | Pb.Invalid_wire_type _ | Pb.Truncated_field _ ->
          false)
    r

let is_group_wire_type field r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Group_wire_type f -> f = field
      | Pb.Truncated_varint | Pb.Varint_too_long | Pb.Negative_varint _
      | Pb.Invalid_wire_type _ | Pb.Truncated_field _ ->
          false)
    r

let is_invalid_wire_type r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Invalid_wire_type _ -> true
      | Pb.Truncated_varint | Pb.Varint_too_long | Pb.Negative_varint _
      | Pb.Group_wire_type _ | Pb.Truncated_field _ ->
          false)
    r

let is_truncated_field r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Pb.Truncated_field _ -> true
      | Pb.Truncated_varint | Pb.Varint_too_long | Pb.Negative_varint _
      | Pb.Group_wire_type _ | Pb.Invalid_wire_type _ ->
          false)
    r

(* --- varint helpers -------------------------------------------------- *)

let encodes_to n expected =
  Pb.encode_varint n
  |> Result.fold ~error:(fun _ -> false) ~ok:(String.equal expected)

let decodes_to wire expected =
  Pb.decode_varint (Der.bytes_of_string wire)
  |> Result.fold
       ~error:(fun _ -> false)
       ~ok:(fun (v, rest) -> v = expected && rest = [])

let varint_roundtrip n =
  Pb.encode_varint n
  |> Result.fold
       ~error:(fun _ -> false)
       ~ok:(fun wire -> decodes_to wire n)

let vector_tests =
  List.concat_map
    (fun (n, wire) ->
      [
        (Printf.sprintf "varint encode %d" n, encodes_to n wire);
        (Printf.sprintf "varint decode %d" n, decodes_to wire n);
      ])
    [
      (0, "\x00");
      (1, "\x01");
      (127, "\x7f");
      (128, "\x80\x01");
      (300, "\xac\x02");
    ]

let sweep_values =
  [ 0; 1; 5; 127; 128; 300; 16383; 16384; 2097151; 268435455; 1 lsl 35; Int.max_int ]

let sweep_ok = List.for_all varint_roundtrip sweep_values

let all_continuation n = String.concat "" (List.init n (fun _ -> "\x80"))

(* --- svid / response builders and equality --------------------------- *)

let svid_eq (a : Pb.x509_svid) (b : Pb.x509_svid) =
  String.equal a.Pb.spiffe_id b.Pb.spiffe_id
  && String.equal a.Pb.x509_svid b.Pb.x509_svid
  && String.equal a.Pb.x509_svid_key b.Pb.x509_svid_key
  && String.equal a.Pb.bundle b.Pb.bundle

let response_eq (a : Pb.x509_svid_response) (b : Pb.x509_svid_response) =
  List.equal svid_eq a.Pb.svids b.Pb.svids
  && List.equal String.equal a.Pb.crl b.Pb.crl
  && List.equal
       (fun (k, v) (k', v') -> String.equal k k' && String.equal v v')
       a.Pb.federated_bundles b.Pb.federated_bundles

(* svid A carries all four fields with an interleaved unknown field of
   each wire type: field 9 varint, field 10 fixed64, field 11 fixed32,
   field 12 length-delimited. *)
let svid_a_body =
  "\x0a" ^ ld "spiffe://td/a" (* field 1 *)
  ^ "\x48\x96\x01" (* field 9, varint 150 *)
  ^ "\x12" ^ ld "CERTA" (* field 2 *)
  ^ "\x51" ^ "12345678" (* field 10, fixed64 *)
  ^ "\x1a" ^ ld "KEYA" (* field 3 *)
  ^ "\x5d" ^ "abcd" (* field 11, fixed32 *)
  ^ "\x22" ^ ld "BUNA" (* field 4 *)
  ^ "\x62" ^ ld "xyz" (* field 12, length-delimited *)

let svid_b_body = "\x0a" ^ ld "spiffe://td/b"

let entry_body = "\x0a" ^ ld "td2" ^ "\x12" ^ ld "B2"

(* Top level interleaves unknown fields of all four wire types between
   the known ones: field 15 varint, field 14 fixed64, field 13 fixed32,
   field 16 length-delimited (two-byte key 0x82 0x01). *)
let response_wire =
  "\x0a" ^ ld svid_a_body (* field 1, svid A *)
  ^ "\x78\x01" (* field 15, varint *)
  ^ "\x12" ^ ld "CRL1" (* field 2, crl *)
  ^ "\x1a" ^ ld entry_body (* field 3, map entry *)
  ^ "\x71" ^ "ABCDEFGH" (* field 14, fixed64 *)
  ^ "\x0a" ^ ld svid_b_body (* field 1, svid B *)
  ^ "\x6d" ^ "WXYZ" (* field 13, fixed32 *)
  ^ "\x82\x01" ^ ld "qq" (* field 16, length-delimited *)

let expected_response =
  {
    Pb.svids =
      [
        {
          Pb.spiffe_id = "spiffe://td/a";
          x509_svid = "CERTA";
          x509_svid_key = "KEYA";
          bundle = "BUNA";
        };
        {
          Pb.spiffe_id = "spiffe://td/b";
          x509_svid = "";
          x509_svid_key = "";
          bundle = "";
        };
      ];
    crl = [ "CRL1" ];
    federated_bundles = [ ("td2", "B2") ];
  }

let empty_expected = { Pb.svids = []; crl = []; federated_bundles = [] }

(* one svid whose spiffe_id field repeats: the later value wins *)
let last_wins_wire = "\x0a" ^ ld ("\x0a" ^ ld "A" ^ "\x0a" ^ ld "B")

let () =
  let failures =
    List.fold_left
      (fun acc (name, ok) -> acc + check name ok)
      0
      (vector_tests
      @ [
          ("varint roundtrip sweep", sweep_ok);
          ("varint Int.max_int roundtrip", varint_roundtrip Int.max_int);
          ( "truncated varint rejected",
            is_truncated_varint (Pb.decode_varint (Der.bytes_of_string "\x80")) );
          ( "11-byte all-continuation varint rejected",
            is_varint_too_long
              (Pb.decode_varint (Der.bytes_of_string (all_continuation 11))) );
          ( "10-byte varint accepted",
            Pb.decode_varint (Der.bytes_of_string (all_continuation 9 ^ "\x01"))
            |> Result.is_ok );
          ( "negative varint encode rejected",
            is_negative_varint (Pb.encode_varint (-1)) );
          ( "key roundtrip field 12 length-delimited",
            Pb.encode_key 12 Pb.Length_delimited
            |> Result.fold
                 ~error:(fun _ -> false)
                 ~ok:(fun wire ->
                   Pb.decode_key (Der.bytes_of_string wire)
                   |> Result.fold
                        ~error:(fun _ -> false)
                        ~ok:(fun ((f, w), rest) ->
                          f = 12 && w = Pb.Length_delimited && rest = [])) );
          ( "group wire type 3 rejected with field",
            is_group_wire_type 1 (Pb.decode_key (Der.bytes_of_string "\x0b")) );
          ( "group wire type 4 rejected with field",
            is_group_wire_type 2 (Pb.decode_key (Der.bytes_of_string "\x14")) );
          ( "wire type 6 rejected",
            is_invalid_wire_type (Pb.decode_key (Der.bytes_of_string "\x0e")) );
          ( "group wire type rejected inside response",
            is_group_wire_type 1 (Pb.decode_x509_svid_response "\x0b") );
          ( "skip_field fixed64 truncation rejected",
            is_truncated_field
              (Pb.skip_field Pb.Fixed64 (Der.bytes_of_string "1234")) );
          ("request encodes empty", String.equal (Pb.encode_x509_svid_request ()) "");
          ( "hand-built response decodes exactly",
            Pb.decode_x509_svid_response response_wire
            |> Result.fold
                 ~error:(fun _ -> false)
                 ~ok:(response_eq expected_response) );
          ( "empty input decodes to empty record",
            Pb.decode_x509_svid_response ""
            |> Result.fold
                 ~error:(fun _ -> false)
                 ~ok:(response_eq empty_expected) );
          ( "truncated length-delimited rejected",
            is_truncated_field (Pb.decode_x509_svid_response ("\x0a\x05" ^ "abc")) );
          ( "repeated scalar in one svid: last wins",
            Pb.decode_x509_svid_response last_wins_wire
            |> Result.fold
                 ~error:(fun _ -> false)
                 ~ok:(fun r ->
                   List.equal svid_eq r.Pb.svids
                     [
                       {
                         Pb.spiffe_id = "B";
                         x509_svid = "";
                         x509_svid_key = "";
                         bundle = "";
                       };
                     ]) );
        ])
  in
  exit (min failures 1)
