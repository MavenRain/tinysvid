(* M23: minimal protobuf (proto3) codec for the SPIFFE Workload API
   messages X509SVIDRequest and X509SVIDResponse. Pure string-in,
   string-out: input becomes a char list once (the Der idiom) and every
   step consumes from the head, so no index arithmetic and no partial
   String access.

   Varint values live in the OCaml int (63-bit): that is the documented
   domain. Encodings up to 10 wire bytes are accepted (non-minimal ones
   included); bits above position 62 fall outside the domain and are
   dropped. Wire types 3 and 4 (groups, removed in proto3) are a typed
   reject. Unknown fields of the four supported wire types are skipped.
   When a scalar field repeats, the last occurrence wins, per proto3;
   repeated-field order is preserved. *)

type wire_type = Varint | Fixed64 | Length_delimited | Fixed32

type error =
  | Truncated_varint
  | Varint_too_long
  | Negative_varint of int
  | Group_wire_type of int
  | Invalid_wire_type of { field : int; wire : int }
  | Truncated_field of { need : int; have : int }

let error_to_string e =
  match e with
  | Truncated_varint -> "truncated_varint"
  | Varint_too_long -> "varint_too_long"
  | Negative_varint n -> Printf.sprintf "negative_varint:%d" n
  | Group_wire_type f -> Printf.sprintf "group_wire_type:%d" f
  | Invalid_wire_type { field; wire } ->
      Printf.sprintf "invalid_wire_type:%d:%d" field wire
  | Truncated_field { need; have } ->
      Printf.sprintf "truncated_field:%d:%d" need have

(* --- byte emission (the test_chain byte_table idiom) ----------------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

(* One byte of output; the low eight bits of n. The land keeps Seq.drop
   in range, so the none branch is unreachable and total anyway. *)
let byte n =
  String.to_seq byte_table
  |> Seq.drop (n land 0xff)
  |> Seq.uncons
  |> Option.fold ~none:"" ~some:(fun (c, _) -> String.make 1 c)

let string_of_chars l = List.to_seq l |> String.of_seq

(* --- varint --------------------------------------------------------- *)

let max_varint_bytes = 10

(* A continuation byte at position 63 or above would shift outside the
   int; its payload bits are dropped, which keeps the shift specified. *)
let contribution b shift =
  match () with
  | () when shift > 62 -> 0
  | () -> (b land 0x7f) lsl shift

(* decode_varint : char list -> (int * char list, error) result. count is
   the position (1-based) of the byte under the cursor; a continuation
   bit on byte 10 means the encoding runs longer than 10 bytes. *)
let decode_varint cs =
  let rec go acc shift count cs =
    match cs with
    | [] -> Error Truncated_varint
    | c :: tl -> (
        let b = Char.code c in
        let acc = acc lor contribution b shift in
        match () with
        | () when b land 0x80 = 0 -> Ok (acc, tl)
        | () when count >= max_varint_bytes -> Error Varint_too_long
        | () -> go acc (shift + 7) (count + 1) tl)
  in
  go 0 0 1 cs

let encode_varint n =
  match () with
  | () when n < 0 -> Error (Negative_varint n)
  | () ->
      let rec go acc rem =
        match () with
        | () when rem < 0x80 -> Ok (acc ^ byte rem)
        | () -> go (acc ^ byte (0x80 lor (rem land 0x7f))) (rem lsr 7)
      in
      go "" n

(* --- field key ------------------------------------------------------- *)

let wire_type_to_int w =
  match w with
  | Varint -> 0
  | Fixed64 -> 1
  | Length_delimited -> 2
  | Fixed32 -> 5

let decode_key cs =
  Result.bind (decode_varint cs) (fun (k, rest) ->
      let field = k lsr 3 in
      let wire = k land 0x7 in
      match () with
      | () when wire = 0 -> Ok ((field, Varint), rest)
      | () when wire = 1 -> Ok ((field, Fixed64), rest)
      | () when wire = 2 -> Ok ((field, Length_delimited), rest)
      | () when wire = 5 -> Ok ((field, Fixed32), rest)
      | () when wire = 3 || wire = 4 -> Error (Group_wire_type field)
      | () -> Error (Invalid_wire_type { field; wire }))

let encode_key field wire = encode_varint ((field lsl 3) lor wire_type_to_int wire)

(* --- length-delimited payloads and skipping ------------------------- *)

let take_or n cs =
  Der.take n cs
  |> Option.to_result ~none:(Truncated_field { need = n; have = List.length cs })

(* A varint length prefix, then that many bytes. *)
let read_bytes cs =
  Result.bind (decode_varint cs) (fun (n, rest) ->
      take_or n rest
      |> Result.map (fun (bs, tl) -> (string_of_chars bs, tl)))

(* skip_field : wire_type -> char list -> (char list, error) result.
   Drops one unknown field's payload of any supported wire type. *)
let skip_field wire cs =
  match wire with
  | Varint -> decode_varint cs |> Result.map (fun (_, rest) -> rest)
  | Fixed64 -> take_or 8 cs |> Result.map (fun (_, rest) -> rest)
  | Fixed32 -> take_or 4 cs |> Result.map (fun (_, rest) -> rest)
  | Length_delimited -> read_bytes cs |> Result.map (fun (_, rest) -> rest)

(* --- SPIFFE Workload API messages ----------------------------------- *)

(* X509SVIDRequest has no fields, so its encoding is empty. *)
let encode_x509_svid_request () = ""

type x509_svid = {
  spiffe_id : string;
  x509_svid : string;
  x509_svid_key : string;
  bundle : string;
}

type x509_svid_response = {
  svids : x509_svid list;
  crl : string list;
  federated_bundles : (string * string) list;
}

let empty_svid = { spiffe_id = ""; x509_svid = ""; x509_svid_key = ""; bundle = "" }

let empty_response = { svids = []; crl = []; federated_bundles = [] }

(* X509SVID: four length-delimited fields, numbers 1 to 4. A missing
   field stays ""; a repeated one keeps its last occurrence. A known
   field number on the wrong wire type is skipped like an unknown. *)
let decode_svid body =
  let rec go acc cs =
    match cs with
    | [] -> Ok acc
    | _ :: _ ->
        Result.bind (decode_key cs) (fun ((field, wire), rest) ->
            match wire with
            | Length_delimited ->
                Result.bind (read_bytes rest) (fun (s, tl) ->
                    let acc =
                      match () with
                      | () when field = 1 -> { acc with spiffe_id = s }
                      | () when field = 2 -> { acc with x509_svid = s }
                      | () when field = 3 -> { acc with x509_svid_key = s }
                      | () when field = 4 -> { acc with bundle = s }
                      | () -> acc
                    in
                    go acc tl)
            | Varint | Fixed64 | Fixed32 ->
                Result.bind (skip_field wire rest) (go acc))
  in
  go empty_svid (Der.bytes_of_string body)

(* One federated_bundles map entry: key = field 1 string, value = field 2
   bytes; last occurrence wins inside the entry, unknowns skipped. *)
let decode_map_entry body =
  let rec go k v cs =
    match cs with
    | [] -> Ok (k, v)
    | _ :: _ ->
        Result.bind (decode_key cs) (fun ((field, wire), rest) ->
            match wire with
            | Length_delimited ->
                Result.bind (read_bytes rest) (fun (s, tl) ->
                    match () with
                    | () when field = 1 -> go s v tl
                    | () when field = 2 -> go k s tl
                    | () -> go k v tl)
            | Varint | Fixed64 | Fixed32 ->
                Result.bind (skip_field wire rest) (go k v))
  in
  go "" "" (Der.bytes_of_string body)

(* X509SVIDResponse: repeated svids (1), repeated crl (2), map
   federated_bundles (3). Repeated-field order is preserved. *)
let decode_x509_svid_response s =
  let rec go svids crls fbs cs =
    match cs with
    | [] ->
        Ok
          {
            svids = List.rev svids;
            crl = List.rev crls;
            federated_bundles = List.rev fbs;
          }
    | _ :: _ ->
        Result.bind (decode_key cs) (fun ((field, wire), rest) ->
            match wire with
            | Length_delimited ->
                Result.bind (read_bytes rest) (fun (body, tl) ->
                    match () with
                    | () when field = 1 ->
                        Result.bind (decode_svid body) (fun sv ->
                            go (sv :: svids) crls fbs tl)
                    | () when field = 2 -> go svids (body :: crls) fbs tl
                    | () when field = 3 ->
                        Result.bind (decode_map_entry body) (fun kv ->
                            go svids crls (kv :: fbs) tl)
                    | () -> go svids crls fbs tl)
            | Varint | Fixed64 | Fixed32 ->
                Result.bind (skip_field wire rest) (go svids crls fbs))
  in
  go [] [] [] (Der.bytes_of_string s)
