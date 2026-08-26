(* The Sig_backend.S implementation over the sha2 digests: Ed25519
   (RFC 8032, SHA-512 inside the scheme) and ecdsa-with-SHA256 over
   P-256 (RFC 5758). SubjectPublicKeyInfo and the ECDSA signature
   structure are parsed with the library's DER walker; any malformed
   input is a false verdict, never an exception. *)

open Limbs
module Der = Tinysvid.Der
module Sig_backend = Tinysvid.Sig_backend

(* SPKI algorithm OIDs as raw content octets: id-ecPublicKey
   1.2.840.10045.2.1 and prime256v1 1.2.840.10045.3.1.7 (RFC 5480
   section 2.1.1); Ed25519 keys reuse the signature OID 1.3.101.112
   (RFC 8410 section 3). *)
let oid_ec_public_key = "\x2a\x86\x48\xce\x3d\x02\x01"

let oid_prime256v1 = "\x2a\x86\x48\xce\x3d\x03\x01\x07"

let ok_result (r : ('a, 'e) result) : 'a option =
  Result.fold ~ok:Option.some ~error:(fun _ -> None) r

let is_universal (c : Der.tag_class) : bool =
  match c with
  | Der.Universal -> true
  | Der.Application | Der.Context_specific | Der.Private_class -> false

let shape ~(constructed : bool) ~(number : int) (t : Der.tlv) : bool =
  is_universal t.Der.header.Der.cls
  && Bool.equal t.Der.header.Der.constructed constructed
  && Int.equal t.Der.header.Der.number number

let is_seq (t : Der.tlv) : bool = shape ~constructed:true ~number:16 t

let is_oid (t : Der.tlv) : bool = shape ~constructed:false ~number:6 t

let is_bit_string (t : Der.tlv) : bool = shape ~constructed:false ~number:3 t

let is_integer (t : Der.tlv) : bool = shape ~constructed:false ~number:2 t

(* SubjectPublicKeyInfo (RFC 5280 section 4.1): SEQUENCE of an
   AlgorithmIdentifier (an OID plus at most one OID parameter here) and
   the subjectPublicKey BIT STRING, whose unused-bits octet must be
   zero. Returns (algorithm oid, parameter oid, key octets). *)
let parse_spki (spki : string) : (string * string option * string) option =
  let* node = ok_result (Der.parse_exact spki) in
  let* () = guard (is_seq node) in
  let* kids = ok_result (Der.children node) in
  match kids with
  | [ alg; key ] ->
    let* () = guard (is_seq alg) in
    let* algkids = ok_result (Der.children alg) in
    let* oid, param =
      match algkids with
      | [ o ] ->
        let* () = guard (is_oid o) in
        Some (o.Der.value, None)
      | [ o; pr ] ->
        let* () = guard (is_oid o && is_oid pr) in
        Some (o.Der.value, Some pr.Der.value)
      | [] | _ :: _ :: _ :: _ -> None
    in
    let* () = guard (is_bit_string key) in
    let* payload =
      match List.of_seq (String.to_seq key.Der.value) with
      | '\x00' :: rest -> Some (String.of_seq (List.to_seq rest))
      | [] | _ :: _ -> None
    in
    Some (oid, param, payload)
  | [] | [ _ ] | _ :: _ :: _ :: _ -> None

(* DER INTEGER content as big-endian limbs: nonempty, nonnegative, and
   minimally encoded (a leading zero octet only under a set high bit). *)
let int_limbs (t : Der.tlv) : int list option =
  let* () = guard (is_integer t) in
  match string_to_ints t.Der.value with
  | [] -> None
  | b0 :: rest ->
    let* () = guard (b0 < 0x80) in
    let* () =
      match (b0, rest) with
      | 0, [] -> Some ()
      | 0, b1 :: _ -> guard (b1 >= 0x80)
      | _, _ -> Some ()
    in
    Some (limbs_of_be_bytes (b0 :: rest))

(* ECDSA signatureValue content (RFC 5480 appendix A): SEQUENCE of the
   two INTEGERs r and s. *)
let parse_ecdsa_sig (s : string) : (int list * int list) option =
  let* node = ok_result (Der.parse_exact s) in
  let* () = guard (is_seq node) in
  let* kids = ok_result (Der.children node) in
  match kids with
  | [ ri; si ] ->
    let* r = int_limbs ri in
    let* sv = int_limbs si in
    Some (r, sv)
  | [] | [ _ ] | _ :: _ :: _ :: _ -> None

(* An uncompressed SEC 1 point: 0x04 then 32 bytes X then 32 bytes Y. *)
let uncompressed_point (key : string) : (int list * int list) option =
  match string_to_ints key with
  | 0x04 :: rest ->
    let* () = guard (Int.equal (List.length rest) 64) in
    let xb, yb = split_at 32 rest in
    Some (limbs_of_be_bytes xb, limbs_of_be_bytes yb)
  | [] | _ :: _ -> None

let verify ~(alg : Sig_backend.algorithm) ~(spki : string) ~(message : string)
    ~(signature : string) : bool =
  match alg with
  | Sig_backend.Ed25519 ->
    (let* oid, param, key = parse_spki spki in
     let* () = guard (String.equal oid Sig_backend.ed25519_oid) in
     let* () = guard (Option.is_none param) in
     let* () = guard (Int.equal (String.length key) 32) in
     Some
       (Ed25519.verify (Bytes.of_string key) (Bytes.of_string message)
          (Bytes.of_string signature)))
    |> Option.value ~default:false
  | Sig_backend.Ecdsa_p256_sha256 ->
    (let* oid, param, key = parse_spki spki in
     let* () = guard (String.equal oid oid_ec_public_key) in
     let* pv = param in
     let* () = guard (String.equal pv oid_prime256v1) in
     let* x, y = uncompressed_point key in
     let* r, s = parse_ecdsa_sig signature in
     Some (P256.verify ~x ~y ~digest:(Sha2.Sha256.digest message) ~r ~s))
    |> Option.value ~default:false
