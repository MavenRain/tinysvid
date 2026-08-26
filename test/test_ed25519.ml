(* Ed25519 gate: RFC 8032 section 7.1 vectors, deterministic round
   trips, on_curve edge encodings, and a solana-keygen differential (inherited from the x402-caml port)
   (4 fresh keypairs from the Solana CLI: seed -> expected pubkey). *)

module E = Tinysvid_sig.Ed25519

let check (name : string) (ok : bool) (acc : string list) : string list =
  if ok then acc else name :: acc

(* ---------- hex helpers, index-free ---------- *)

let hex_val (c : char) : int =
  let n = Char.code c in
  match () with
  | () when n >= 48 && n <= 57 -> n - 48
  | () when n >= 97 && n <= 102 -> n - 87
  | () when n >= 65 && n <= 70 -> n - 55
  | () -> 0

let hex_to_bytes (s : string) : bytes =
  let ints_rev, _ =
    String.fold_left
      (fun (acc, pend) c ->
        let v = hex_val c in
        Option.fold
          ~none:(acc, Some v)
          ~some:(fun hi -> (((hi lsl 4) lor v) :: acc, None))
          pend)
      ([], None) s
  in
  let buf = Buffer.create (max (List.length ints_rev) 1) in
  List.iter (fun v -> Buffer.add_int8 buf v) (List.rev ints_rev);
  Buffer.to_bytes buf

let bytes_to_hex (b : bytes) : string =
  String.concat ""
    (List.map
       (fun c -> Printf.sprintf "%02x" (Char.code c))
       (List.of_seq (Bytes.to_seq b)))

(* ---------- byte-list helpers, index-free ---------- *)

let to_ints (b : bytes) : int list =
  List.map Char.code (List.of_seq (Bytes.to_seq b))

let of_ints (l : int list) : bytes =
  let buf = Buffer.create (max (List.length l) 1) in
  List.iter (fun v -> Buffer.add_int8 buf v) l;
  Buffer.to_bytes buf

(* Flip the low bit of the first byte. *)
let flip_first_bit (b : bytes) : bytes =
  of_ints (List.mapi (fun i v -> if i = 0 then v lxor 1 else v) (to_ints b))

(* Flip the low bit of the byte at index j. *)
let flip_byte (j : int) (b : bytes) : bytes =
  of_ints (List.mapi (fun i v -> if i = j then v lxor 1 else v) (to_ints b))

let drop_last (b : bytes) : bytes =
  let l = to_ints b in
  of_ints (List.filteri (fun i _ -> i < List.length l - 1) l)

(* ---------- RFC 8032 section 7.1 vectors ---------- *)

let rfc_vectors : (string * string * string * string * string) list =
  [ ( "rfc-test1",
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
       5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" );
    ( "rfc-test2",
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
       085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" );
    ( "rfc-test3",
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      "af82",
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
       18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" ) ]

let rfc_checks (acc : string list) : string list =
  List.fold_left
    (fun acc (name, seed_h, pub_h, msg_h, sig_h) ->
      let seed = hex_to_bytes seed_h in
      let pub = hex_to_bytes pub_h in
      let msg = hex_to_bytes msg_h in
      let sg = hex_to_bytes sig_h in
      let derived_pub = Option.value ~default:Bytes.empty (E.public_key seed) in
      let derived_sig = Option.value ~default:Bytes.empty (E.sign seed msg) in
      acc
      |> check (name ^ "-pub") (bytes_to_hex derived_pub = pub_h)
      |> check (name ^ "-sig") (bytes_to_hex derived_sig = bytes_to_hex sg)
      |> check (name ^ "-verify") (E.verify pub msg sg)
      |> check (name ^ "-reject-flip") (not (E.verify pub msg (flip_first_bit sg)))
      |> check (name ^ "-reject-short") (not (E.verify pub msg (drop_last sg)))
      |> check (name ^ "-oncurve") (E.on_curve pub))
    acc rfc_vectors

(* ---------- deterministic round trips ---------- *)

(* Seed s: byte i = (s*31 + i*7) land 255. *)
let det_seed (s : int) : bytes =
  of_ints (List.init 32 (fun i -> ((s * 31) + (i * 7)) land 255))

(* Message of length n for seed s: byte j = (j*11 + s) land 255. *)
let det_msg (s : int) (n : int) : bytes =
  of_ints (List.init n (fun j -> ((j * 11) + s) land 255))

let roundtrip_checks (acc : string list) : string list =
  List.fold_left
    (fun acc s ->
      let seed = det_seed s in
      let pub = Option.value ~default:Bytes.empty (E.public_key seed) in
      let acc = check (Printf.sprintf "rt-%d-oncurve" s) (E.on_curve pub) acc in
      List.fold_left
        (fun acc n ->
          let msg = det_msg s n in
          let sg = Option.value ~default:Bytes.empty (E.sign seed msg) in
          let base = Printf.sprintf "rt-%d-%d" s n in
          let acc = check (base ^ "-verify") (E.verify pub msg sg) acc in
          if n = 0 then acc
          else
            check (base ^ "-reject-msgflip")
              (not (E.verify pub (flip_byte 0 msg) sg))
              acc)
        acc [ 0; 1; 32; 100 ])
    acc [ 0; 1; 2; 3; 4; 5; 6; 7 ]

(* ---------- on_curve edge encodings ---------- *)

(* All-zero: y = 0, so x^2 = -1, solvable because p = 1 mod 4; the
   encoding decompresses to an order-4 point. Expected: true.
   All-0xff: sign bit stripped leaves y = 2^255 - 1 >= p, rejected as
   non-canonical. Expected: false. Both recorded from one run and
   checked stable across two calls. *)
let edge_checks (acc : string list) : string list =
  let zeros = of_ints (List.init 32 (fun _ -> 0)) in
  let ffs = of_ints (List.init 32 (fun _ -> 0xff)) in
  acc
  |> check "edge-zero-true" (E.on_curve zeros = true)
  |> check "edge-zero-stable" (E.on_curve zeros = E.on_curve zeros)
  |> check "edge-ff-false" (E.on_curve ffs = false)
  |> check "edge-ff-stable" (E.on_curve ffs = E.on_curve ffs)

(* ---------- solana-keygen differential (inherited from the x402-caml port) ---------- *)

(* From `solana-keygen new`: each json file holds seed(32) || pubkey(32). *)
let solana_pairs : (string * string) list =
  [ ( "6b986d2185675f824e8b53474e5228c6338ca84235d41a99a9c97f67dd0b0078",
      "bb6aced546ccc509798b22580531997200e394c47dd9a55663f5dba0b4e8ca54" );
    ( "60f7e9ab246822749cb089a8c9e2dd86ef302e6977f7f11022bcdc6c16448aa6",
      "adcf4e245fe73fedd13c93dc1b113c9bad100ddfef2d90c03af0ff6120b29017" );
    ( "67e01d9c558b11853558e1256b12e53b5ecae6375d9816a7772cccf61a623e60",
      "e21d88eb09f6a024bb5466267a6ddc0003fe3e9ca0c6faebb5984fed2cce2d1d" );
    ( "eb46cd983af28f79333d59d9f0546c314bd4e06fdad6c7bf64b70d0015c10e02",
      "17287f027932d4a11c768a90f780821507a63eb4948a17316b1758e50bda406d" ) ]

let solana_checks (acc : string list) : string list =
  List.fold_left
    (fun (acc, i) (seed_h, pub_h) ->
      let derived =
        Option.value ~default:Bytes.empty (E.public_key (hex_to_bytes seed_h))
      in
      (check (Printf.sprintf "solana-%d" i) (bytes_to_hex derived = pub_h) acc, i + 1))
    (acc, 1) solana_pairs
  |> fst

(* ---------- malformed-length inputs ---------- *)

let malformed_checks (acc : string list) : string list =
  let short = of_ints (List.init 31 (fun _ -> 1)) in
  acc
  |> check "badlen-pub" (Option.is_none (E.public_key short))
  |> check "badlen-sign" (Option.is_none (E.sign short Bytes.empty))
  |> check "badlen-oncurve" (not (E.on_curve short))

let () =
  let failures =
    [] |> rfc_checks |> roundtrip_checks |> edge_checks |> solana_checks
    |> malformed_checks
  in
  List.iter (fun f -> print_endline ("FAIL " ^ f)) failures;
  let n = List.length failures in
  Printf.printf "test_ed25519: %d failure(s)\n" n;
  exit (if n = 0 then 0 else 1)
