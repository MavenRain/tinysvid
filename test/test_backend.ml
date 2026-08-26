(* Backend gate: the Sig_backend.S implementation over DER SPKI inputs.
   ECDSA P-256 is pinned by the RFC 6979 A.2.5 key and its "sample"
   deterministic signature (P-256 with SHA-256), an openssl-generated
   differential signature over "test", and malformed-structure
   rejections. Ed25519 is pinned end to end by
   test_ed25519; here RFC 8032 test 1 runs through the SPKI path. The
   module constraint pins the seam Chain.Make consumes. *)

module Backend_is_sig : Tinysvid.Sig_backend.S = Tinysvid_sig.Backend
module B = Tinysvid_sig.Backend
module L = Tinysvid_sig.Limbs

let check (name : string) (ok : bool) (acc : string list) : string list =
  if ok then acc else name :: acc

let string_of_ints (l : int list) : string =
  let buf = Buffer.create (max (List.length l) 1) in
  List.iter (fun v -> Buffer.add_int8 buf v) l;
  Buffer.contents buf

let hex_to_string (h : string) : string = string_of_ints (L.ints_of_hex h)

(* Drop the first n characters, index-free. *)
let drop_chars (n : int) (s : string) : string =
  String.of_seq
    (List.to_seq (List.filteri (fun i _ -> i >= n) (List.of_seq (String.to_seq s))))

(* ---------- DER construction for signature fixtures ---------- *)

(* Minimal DER INTEGER from big-endian bytes. *)
let der_int (bs : int list) : int list =
  let rec strip l =
    match l with
    | 0 :: (_ :: _ as rest) -> strip rest
    | [] -> [ 0 ]
    | _ :: _ -> l
  in
  let stripped = strip bs in
  let body =
    match stripped with
    | b :: _ when b >= 0x80 -> 0 :: stripped
    | [] | _ :: _ -> stripped
  in
  2 :: List.length body :: body

(* INTEGER with a gratuitous leading zero: valid BER, invalid DER. *)
let der_int_padded (bs : int list) : int list =
  let body = 0 :: bs in
  2 :: List.length body :: body

let der_seq (body : int list) : int list = 0x30 :: List.length body :: body

let ecdsa_sig_of (r_int : int list) (s_int : int list) : string =
  string_of_ints (der_seq (r_int @ s_int))

let ecdsa_sig (r_hex : string) (s_hex : string) : string =
  ecdsa_sig_of (der_int (L.ints_of_hex r_hex)) (der_int (L.ints_of_hex s_hex))

(* ---------- SPKI fixtures ---------- *)

(* SEQ { SEQ { id-ecPublicKey, prime256v1 }, BIT STRING 0 unused }. *)
let p256_spki_of (point_tag : string) (ux : string) (uy : string) : string =
  hex_to_string
    ("3059301306072a8648ce3d020106082a8648ce3d0301070342" ^ "00" ^ point_tag
   ^ ux ^ uy)

let p256_spki (ux : string) (uy : string) : string = p256_spki_of "04" ux uy

(* Same shape with the curve parameter OID ending in 08: parses, but the
   backend must refuse the unknown curve. *)
let p256_spki_wrong_curve (ux : string) (uy : string) : string =
  hex_to_string
    ("3059301306072a8648ce3d020106082a8648ce3d030108034200" ^ "04" ^ ux ^ uy)

(* SEQ { SEQ { id-Ed25519 }, BIT STRING unused-bits u }. *)
let ed_spki_of (unused : string) (pub : string) : string =
  hex_to_string ("302a300506032b65700321" ^ unused ^ pub)

let ed_spki (pub : string) : string = ed_spki_of "00" pub

(* ---------- RFC 6979 A.2.5 vectors: P-256, SHA-256 ---------- *)

let ux = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"

let uy = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

let sample_r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"

let sample_s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"

(* Same key, message "test": generated once with openssl (ECDSA k is
   random there, so this is a pinned differential vector, not an RFC
   value) and re-verified by openssl against the RFC public key. *)
let test_r = "33b775f36f0788e5c5dfc88d48359420df34b47d7e487ccd866122a6cba31869"

let test_s = "76b8b657b290b174b0d6c05885fb00ffde0f7b2a46d225ce5a7eeb53f73c50ef"

(* Last byte of Ux perturbed: off the curve. *)
let ux_flipped = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7"

let alg_ec = Tinysvid.Sig_backend.Ecdsa_p256_sha256

let alg_ed = Tinysvid.Sig_backend.Ed25519

(* RFC 8032 section 7.1 test 1. *)
let ed_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

let p256_checks (acc : string list) : string list =
  let spki = p256_spki ux uy in
  let sig_sample = ecdsa_sig sample_r sample_s in
  let sig_test = ecdsa_sig test_r test_s in
  acc
  |> check "p256-sample-verify"
       (B.verify ~alg:alg_ec ~spki ~message:"sample" ~signature:sig_sample)
  |> check "p256-test-verify"
       (B.verify ~alg:alg_ec ~spki ~message:"test" ~signature:sig_test)
  |> check "p256-wrong-message"
       (not (B.verify ~alg:alg_ec ~spki ~message:"sampled" ~signature:sig_sample))
  |> check "p256-cross-signature"
       (not (B.verify ~alg:alg_ec ~spki ~message:"sample" ~signature:sig_test))
  |> check "p256-swapped-rs"
       (not
          (B.verify ~alg:alg_ec ~spki ~message:"sample"
             ~signature:(ecdsa_sig sample_s sample_r)))
  |> check "p256-key-off-curve"
       (not
          (B.verify ~alg:alg_ec ~spki:(p256_spki ux_flipped uy) ~message:"sample"
             ~signature:sig_sample))
  |> check "p256-zero-s"
       (not
          (B.verify ~alg:alg_ec ~spki ~message:"sample"
             ~signature:(ecdsa_sig sample_r "00")))
  |> check "p256-trailing-byte"
       (not
          (B.verify ~alg:alg_ec ~spki ~message:"sample"
             ~signature:(sig_sample ^ "\x00")))
  |> check "p256-nonminimal-int"
       (not
          (B.verify ~alg:alg_ec ~spki ~message:"test"
             ~signature:
               (ecdsa_sig_of
                  (der_int_padded (L.ints_of_hex test_r))
                  (der_int (L.ints_of_hex test_s)))))
  |> check "p256-compressed-point"
       (not
          (B.verify ~alg:alg_ec
             ~spki:(p256_spki_of "02" ux uy)
             ~message:"sample" ~signature:sig_sample))
  |> check "p256-wrong-curve-oid"
       (not
          (B.verify ~alg:alg_ec
             ~spki:(p256_spki_wrong_curve ux uy)
             ~message:"sample" ~signature:sig_sample))
  |> check "p256-alg-cross"
       (not
          (B.verify ~alg:alg_ec ~spki:(ed_spki ed_pub) ~message:"sample"
             ~signature:sig_sample))

(* ---------- RFC 8032 section 7.1 test 1 through the SPKI path ---------- *)

let ed_sig =
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
   5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

let ed_checks (acc : string list) : string list =
  let spki = ed_spki ed_pub in
  let sg = hex_to_string ed_sig in
  let sg_flipped = hex_to_string ("e4" ^ drop_chars 2 ed_sig) in
  acc
  |> check "ed-spki-verify"
       (B.verify ~alg:alg_ed ~spki ~message:"" ~signature:sg)
  |> check "ed-spki-sigflip"
       (not (B.verify ~alg:alg_ed ~spki ~message:"" ~signature:sg_flipped))
  |> check "ed-alg-mismatch"
       (not
          (B.verify ~alg:alg_ed ~spki:(p256_spki ux uy) ~message:""
             ~signature:sg))
  |> check "ed-unused-bits"
       (not
          (B.verify ~alg:alg_ed ~spki:(ed_spki_of "01" ed_pub) ~message:""
             ~signature:sg))

let () =
  let failures = [] |> p256_checks |> ed_checks in
  List.iter (fun f -> print_endline ("FAIL " ^ f)) failures;
  let n = List.length failures in
  Printf.printf "test_backend: %d failure(s)\n" n;
  exit (if n = 0 then 0 else 1)
