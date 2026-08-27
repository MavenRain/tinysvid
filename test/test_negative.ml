(* M27: negative corpus for the two untrusted-byte parsers, Der and Pb.
   Every vector in the corpus is malformed by construction, so the single
   oracle is: the parser must return Error. Three sweep families keep the
   corpus sound (no vector that could legally parse):

   - DER prefix sweep: every proper prefix of a valid TLV breaks the
     outer length, so parse_exact must reject all of them.
   - DER outer-length sweep: any wrong value in the outer length octet
     yields truncation, trailing bytes, an indefinite form, a
     non-minimal form, or an overflow; all 255 wrong values must reject.
   - Pb cut sweep: a cut at a top-level field boundary is a valid
     shorter message (the positive control); a cut anywhere else lands
     inside a key, a length, or a payload and must reject.

   Structured per-construct vectors pin the exact error name through
   error_to_string, so a reject for the wrong reason still fails. *)

open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- byte emission (the test_chain byte_table idiom) ----------------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

(* The char for the low eight bits of v, off the table: total, no chr. *)
let chr v =
  String.to_seq byte_table
  |> Seq.drop (v land 0xff)
  |> Seq.uncons
  |> Option.fold ~none:'\x00' ~some:fst

let byte n = String.make 1 (chr n)

(* Total prefix: the first n bytes of s (all of s when n is larger). *)
let prefix n s = String.to_seq s |> Seq.take n |> String.of_seq

(* Total single-byte substitution at index j. *)
let put j v s = String.mapi (fun k c -> if k = j then chr v else c) s

(* --- DER corpus ------------------------------------------------------ *)

(* tlv builds tag ^ length ^ body for bodies under 128 bytes, the only
   sizes this corpus needs (single length octet keeps the sweeps small). *)
let tlv tag body = byte tag ^ byte (String.length body) ^ body

(* A certificate-shaped nest: SEQUENCE { [0] { INTEGER }, SEQUENCE { OID,
   UTF8String }, BIT STRING, INTEGER } exercises constructed, context,
   and primitive nodes at depth three. *)
let leaf_int = tlv 0x02 "\x2a"
let oid = tlv 0x06 "\x2a\x86\x48\xce\x3d\x04\x03\x02"
let utf8 = tlv 0x0c "tinysvid"
let bitstr = tlv 0x03 "\x00\x6b\x17\xd1\xf2"
let ctx0 = tlv 0xa0 leaf_int
let inner_seq = tlv 0x30 (oid ^ utf8)
let cert_like = tlv 0x30 (ctx0 ^ inner_seq ^ bitstr ^ leaf_int)

(* Recursive walk: every constructed node's value must itself parse as a
   run of TLVs. The positive control runs this over cert_like. *)
let rec deep (node : Der.tlv) =
  match node.header.constructed with
  | false -> true
  | true ->
      Der.children node
      |> Result.fold ~ok:(List.for_all deep) ~error:(fun _ -> false)

let der_rejects s = Result.is_error (Der.parse_exact s)

let der_rejects_as s name =
  Der.parse_exact s
  |> Result.fold
       ~ok:(fun _ -> false)
       ~error:(fun e -> String.equal (Der.error_to_string e) name)

(* --- Pb corpus ------------------------------------------------------- *)

let key f w = byte ((f lsl 3) lor w)
let ld body = byte (String.length body) ^ body

let svid_body =
  key 1 2 ^ ld "spiffe://example.org/wl"
  ^ key 2 2 ^ ld "CERT"
  ^ key 3 2 ^ ld "KEY"
  ^ key 4 2 ^ ld "ROOTS"

let map_body = key 1 2 ^ ld "other.example" ^ key 2 2 ^ ld "FED"

(* Top-level fields of a valid X509SVIDResponse, one part per field:
   the three known fields plus one unknown field of every wire type, so
   the cut sweep crosses every skip path. *)
let parts =
  [
    key 1 2 ^ ld svid_body;
    key 2 2 ^ ld "CRL1";
    key 3 2 ^ ld map_body;
    key 9 0 ^ "\x96\x01";
    key 10 1 ^ "\x01\x02\x03\x04\x05\x06\x07\x08";
    key 11 5 ^ "\xaa\xbb\xcc\xdd";
    key 12 2 ^ ld "junk";
  ]

let resp = String.concat "" parts

(* Byte offsets where a cut leaves a valid shorter message: the start,
   the end, and every top-level field boundary in between. *)
let boundaries =
  List.fold_left
    (fun (pos, acc) part ->
      let p = pos + String.length part in
      (p, p :: acc))
    (0, [ 0 ]) parts
  |> snd

let pb_rejects_as r name =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e -> String.equal (Pb.error_to_string e) name)
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

let decode = Pb.decode_x509_svid_response

(* Ten continuation octets and a terminator: the varint cap fires on the
   tenth octet, so the terminator is never read. *)
let long_varint = String.concat "" (List.init 10 (fun _ -> "\x80")) ^ "\x01"

let () =
  let n_der = String.length cert_like in
  let outer_len = n_der - 2 in
  let n_pb = String.length resp in
  let failures =
    List.fold_left ( + ) 0
      [
        (* positive controls: the sweeps mutate genuinely valid bytes,
           and the oracle reaches both parsers *)
        check "der: cert-shaped vector parses to depth three"
          (Der.parse_exact cert_like
          |> Result.fold ~ok:deep ~error:(fun _ -> false));
        check "pb: response vector decodes with all fields"
          (decode resp
          |> Result.fold
               ~ok:(fun (r : Pb.x509_svid_response) ->
                 List.length r.svids = 1
                 && List.for_all
                      (fun (s : Pb.x509_svid) ->
                        String.equal s.spiffe_id "spiffe://example.org/wl"
                        && String.equal s.x509_svid "CERT"
                        && String.equal s.x509_svid_key "KEY"
                        && String.equal s.bundle "ROOTS")
                      r.svids
                 && List.equal String.equal r.crl [ "CRL1" ]
                 && List.equal
                      (fun (k1, v1) (k2, v2) ->
                        String.equal k1 k2 && String.equal v1 v2)
                      r.federated_bundles
                      [ ("other.example", "FED") ])
               ~error:(fun _ -> false));
        (* DER sweep 1: every proper prefix breaks the outer length *)
        check
          (Printf.sprintf "der: all %d proper prefixes reject" n_der)
          (List.init n_der Fun.id
          |> List.for_all (fun i -> der_rejects (prefix i cert_like)));
        (* DER sweep 2: all 255 wrong outer-length octets reject *)
        check "der: all 255 wrong outer-length octets reject"
          (List.init 256 Fun.id
          |> List.filter (fun v -> v <> outer_len)
          |> List.for_all (fun v -> der_rejects (put 1 v cert_like)));
        (* DER sweep 3: any appended octet is trailing_bytes *)
        check "der: all 256 one-octet extensions reject as trailing"
          (List.init 256 Fun.id
          |> List.for_all (fun v ->
                 der_rejects_as (cert_like ^ byte v) "trailing_bytes:1"));
        (* DER structured vectors, exact error names *)
        check "der: empty input" (der_rejects_as "" "truncated_header");
        check "der: tag without length" (der_rejects_as "\x30" "truncated_length");
        check "der: long form missing octet"
          (der_rejects_as "\x30\x81" "truncated_length");
        check "der: indefinite length"
          (der_rejects_as "\x30\x80\x02\x01\x2a\x00\x00" "indefinite_length");
        check "der: non-minimal long form"
          (der_rejects_as "\x30\x81\x4f" "non_minimal_length");
        check "der: leading-zero length octet"
          (der_rejects_as "\x30\x82\x00\x81" "non_minimal_length");
        check "der: five length octets overflow"
          (der_rejects_as "\x30\x85\x01\x01\x01\x01\x01" "length_overflow:5");
        check "der: high tag number form"
          (der_rejects_as "\x1f\x01\x2a" "high_tag_number");
        check "der: value shorter than length"
          (der_rejects_as "\x02\x05\x2a" "truncated_value:5:1");
        check "der: children of a primitive reject"
          (Der.parse_exact "\x02\x01\x2a"
          |> Result.fold
               ~ok:(fun node ->
                 Der.children node
                 |> Result.fold
                      ~ok:(fun _ -> false)
                      ~error:(fun e ->
                        String.equal (Der.error_to_string e) "not_constructed"))
               ~error:(fun _ -> false));
        (* Pb sweep: every cut off a field boundary rejects, every cut on
           one decodes (the boundary cuts double as positive controls) *)
        check
          (Printf.sprintf "pb: all %d cut points split boundary/reject" (n_pb + 1))
          (List.init (n_pb + 1) Fun.id
          |> List.for_all (fun i ->
                 let r = decode (prefix i resp) in
                 match List.mem i boundaries with
                 | true -> Result.is_ok r
                 | false -> Result.is_error r));
        (* Pb structured vectors *)
        check "pb: all 9 truncated varints reject"
          (List.init 9 (fun i -> i + 1)
          |> List.for_all (fun n ->
                 pb_rejects_as (decode (prefix n long_varint)) "truncated_varint"));
        check "pb: eleven-octet varint key rejects"
          (pb_rejects_as (decode long_varint) "varint_too_long");
        check "pb: eleven-octet varint in a skipped field rejects"
          (pb_rejects_as (decode (key 9 0 ^ long_varint)) "varint_too_long");
        check "pb: group wire type 3 rejects"
          (pb_rejects_as (decode (key 5 3)) "group_wire_type:5");
        check "pb: group wire type 4 rejects"
          (pb_rejects_as (decode (key 5 4)) "group_wire_type:5");
        check "pb: wire type 6 rejects"
          (pb_rejects_as (decode (key 5 6)) "invalid_wire_type:5:6");
        check "pb: wire type 7 rejects"
          (pb_rejects_as (decode (key 5 7)) "invalid_wire_type:5:7");
        check "pb: length prefix beyond input rejects"
          (is_truncated_field (decode (key 2 2 ^ "\xff\xff\xff\xff\x07")));
        check "pb: truncated fixed64 skip rejects"
          (pb_rejects_as (decode (key 10 1 ^ "\x00\x00")) "truncated_field:8:2");
        check "pb: truncated fixed32 skip rejects"
          (pb_rejects_as (decode (key 11 5 ^ "\x00")) "truncated_field:4:1");
        check "pb: group inside an svid body propagates"
          (pb_rejects_as (decode (key 1 2 ^ ld (key 2 3))) "group_wire_type:2");
        check "pb: truncation inside a map entry propagates"
          (pb_rejects_as
             (decode (key 3 2 ^ ld (key 2 2 ^ "\x05")))
             "truncated_field:5:0");
      ]
  in
  exit (min failures 1)
