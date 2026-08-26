(* Ed25519 (RFC 8032), pure OCaml stdlib on the shared limb arithmetic.
   NOT constant-time: this backend only verifies public inputs; sign and
   public_key exist for tests. Ported from the x402-caml client; the
   SHA-512 core now comes from the sha2 library. *)

open Limbs

module Sha512 = struct
  let digest (b : bytes) : bytes = Sha2.Sha512.digest_bytes b
end

(* ---------- field arithmetic mod p = 2^255 - 19 ---------- *)

let p_limbs : int list = (0xffed :: List.init 14 (fun _ -> 0xffff)) @ [ 0x7fff ]

(* 4p, limb-wise: every limb exceeds 0xffff, so x + 4p_i - y stays >= 0. *)
let p4_limbs : int list = List.map (fun v -> 4 * v) p_limbs

(* Reduce to 16 limbs using 2^256 = 38 mod p; result may still be >= p. *)
let rec fe_red (v : int list) : int list =
  let v = trim (carry_norm v) in
  if List.length v <= 16 then pad16 v
  else
    let low, high = split_at 16 v in
    fe_red (add_lists low (List.map (fun h -> h * 38) high))

let fe_of_int (n : int) : int list = fe_red [ n ]

let fe_zero = fe_of_int 0
let fe_one = fe_of_int 1

let fe_add (a : int list) (b : int list) : int list = fe_red (map2t ( + ) a b)

let fe_sub (a : int list) (b : int list) : int list =
  fe_red (map2t ( - ) (map2t ( + ) a p4_limbs) b)

let fe_mul (a : int list) (b : int list) : int list = fe_red (mul_limbs a b)

(* Canonical representative in [0, p), exactly 16 limbs. *)
let fe_canon (v : int list) : int list =
  let rec drop v = if cmp v p_limbs >= 0 then drop (sub_limbs v p_limbs) else v in
  pad16 (trim (drop (fe_red v)))

let fe_eq (a : int list) (b : int list) : bool = fe_canon a = fe_canon b

let fe_neg (a : int list) : int list = fe_sub fe_zero a

let fe_parity (a : int list) : int =
  match fe_canon a with
  | [] -> 0
  | l0 :: _ -> l0 land 1

(* Square-and-multiply, LSB-first over the exponent bits. *)
let fe_pow (base : int list) (e : int list) : int list =
  let res, _ =
    List.fold_left
      (fun (r, b) bit -> ((if bit = 1 then fe_mul r b else r), fe_mul b b))
      (fe_one, base) (bits_of_limbs e)
  in
  res

(* p - 2 *)
let e_pm2 : int list = (0xffeb :: List.init 14 (fun _ -> 0xffff)) @ [ 0x7fff ]

(* (p + 3) / 8 = 2^252 - 2 *)
let e_p38 : int list = (0xfffe :: List.init 14 (fun _ -> 0xffff)) @ [ 0x0fff ]

(* (p - 1) / 4 = 2^253 - 5 *)
let e_pm14 : int list = (0xfffb :: List.init 14 (fun _ -> 0xffff)) @ [ 0x1fff ]

let fe_inv (a : int list) : int list = fe_pow a e_pm2

let fe_div (a : int list) (b : int list) : int list = fe_mul a (fe_inv b)

(* sqrt(-1) = 2^((p-1)/4); 2 is a non-residue because p = 5 mod 8. *)
let sqrt_m1 : int list = fe_pow (fe_of_int 2) e_pm14

(* d = -121665 / 121666, computed from the two literals. *)
let d_const : int list = fe_div (fe_neg (fe_of_int 121665)) (fe_of_int 121666)

let d2_const : int list = fe_add d_const d_const

(* Canonical field element to 32 little-endian bytes. *)
let fe_to_le_bytes (a : int list) : int list =
  List.concat_map (fun limb -> [ limb land 0xff; limb lsr 8 ]) (fe_canon a)

(* ---------- points, extended homogeneous coordinates ---------- *)

type point = { x : int list; y : int list; z : int list; t : int list }

let identity : point = { x = fe_zero; y = fe_one; z = fe_one; t = fe_zero }

(* RFC 8032 complete addition; also used for doubling. *)
let point_add (p : point) (q : point) : point =
  let a = fe_mul (fe_sub p.y p.x) (fe_sub q.y q.x) in
  let b = fe_mul (fe_add p.y p.x) (fe_add q.y q.x) in
  let c = fe_mul (fe_mul p.t q.t) d2_const in
  let dd = fe_mul (fe_add p.z p.z) q.z in
  let e = fe_sub b a in
  let f = fe_sub dd c in
  let g = fe_add dd c in
  let h = fe_add b a in
  { x = fe_mul e f; y = fe_mul g h; z = fe_mul f g; t = fe_mul e h }

let point_neg (p : point) : point =
  { x = fe_neg p.x; y = p.y; z = p.z; t = fe_neg p.t }

(* Double-and-add over the 256 scalar bits, LSB first. *)
let smul (scalar : int list) (p : point) : point =
  let res, _ =
    List.fold_left
      (fun (r, b) bit -> ((if bit = 1 then point_add r b else r), point_add b b))
      (identity, p)
      (bits_of_limbs (pad16 scalar))
  in
  res

let compress (p : point) : int list =
  let zi = fe_inv p.z in
  let x = fe_mul p.x zi in
  let y = fe_mul p.y zi in
  let x0 = fe_parity x in
  List.mapi
    (fun i b -> if i = 31 then b lor (x0 lsl 7) else b)
    (fe_to_le_bytes y)

(* Curve check: -x^2 + y^2 = 1 + d x^2 y^2. *)
let curve_eq (x : int list) (y : int list) : bool =
  let xx = fe_mul x x in
  let yy = fe_mul y y in
  fe_eq (fe_sub yy xx) (fe_add fe_one (fe_mul d_const (fe_mul xx yy)))

let recover_x (y : int list) (sign : int) : int list option =
  let yy = fe_mul y y in
  let u = fe_sub yy fe_one in
  let v = fe_add (fe_mul d_const yy) fe_one in
  let t = fe_mul u (fe_inv v) in
  let cand = fe_pow t e_p38 in
  let c2 = fe_mul cand cand in
  let x_opt =
    match () with
    | () when fe_eq c2 t -> Some cand
    | () when fe_eq c2 (fe_neg t) -> Some (fe_mul cand sqrt_m1)
    | () -> None
  in
  let* x = x_opt in
  let* () = guard (not (fe_eq x fe_zero && sign = 1)) in
  let x = if fe_parity x <> sign then fe_neg x else x in
  let* () = guard (curve_eq x y) in
  Some x

let decompress (bl : int list) : point option =
  let* () = guard (List.length bl = 32) in
  match List.rev bl with
  | [] -> None
  | last :: rest_rev ->
    let sign = (last lsr 7) land 1 in
    let y = pad16 (limbs_of_le_bytes (List.rev ((last land 0x7f) :: rest_rev))) in
    let* () = guard (cmp y p_limbs < 0) in
    let* x = recover_x y sign in
    Some { x; y; z = fe_one; t = fe_mul x y }

(* Base point: y = 4/5, x is the even root. A recovery failure must be
   inert, not fail-open: with an identity fallback every signature would
   verify. base_point_ok gates the public entry points instead. *)
let base_point_opt : point option =
  let y = fe_div (fe_of_int 4) (fe_of_int 5) in
  Option.map
    (fun x -> { x; y; z = fe_one; t = fe_mul x y })
    (recover_x y 0)

let base_point_ok : bool = Option.is_some base_point_opt

let base_point : point = Option.value ~default:identity base_point_opt

(* ---------- scalar arithmetic mod the group order l ---------- *)

(* l = 2^252 + 27742317777372353535851937790883648493 *)
let l_limbs : int list =
  [ 0xd3ed; 0x5cf5; 0x631a; 0x5812; 0x9cd6; 0xa2f7; 0xf9de; 0x14de ]
  @ List.init 7 (fun _ -> 0)
  @ [ 0x1000 ]

(* v mod l by shifted subtraction; bootstraps the power table. *)
let rec big_mod (v : int list) : int list =
  let v = trim v in
  if cmp v l_limbs < 0 then v
  else
    let sh = List.length v - 16 in
    let cand = shift_limbs (trim l_limbs) sh in
    if cmp cand v <= 0 then big_mod (sub_limbs v cand)
    else big_mod (sub_limbs v (shift_limbs (trim l_limbs) (sh - 1)))

(* 2^(16k) mod l for k = 16..31, computed at startup from l itself. *)
let pow2_mod_l_table : int list list =
  List.init 16 (fun i -> big_mod (shift_limbs [ 1 ] (16 + i)))

(* Scale each table row by its high limb; stops at the shorter list. *)
let rec zip_mul (high : int list) (table : int list list) : int list list =
  match (high, table) with
  | [], _ -> []
  | _ :: _, [] -> []
  | h :: hs, m :: ms -> List.map (fun x -> x * h) m :: zip_mul hs ms

(* Reduce any limb list (up to 32 limbs) mod l; result has 16 limbs. *)
let sc_reduce (v : int list) : int list =
  let rec cond_sub v =
    if cmp v l_limbs >= 0 then cond_sub (sub_limbs v l_limbs) else v
  in
  let rec go v =
    let v = trim (carry_norm v) in
    if List.length v <= 16 then pad16 (trim (cond_sub v))
    else
      let low, high = split_at 16 v in
      go (List.fold_left add_lists low (zip_mul high pow2_mod_l_table))
  in
  go v

let sc_add (a : int list) (b : int list) : int list = sc_reduce (add_lists a b)

let sc_mul (a : int list) (b : int list) : int list = sc_reduce (mul_limbs a b)

(* ---------- RFC 8032 Ed25519 operations ---------- *)

let clamp (bl : int list) : int list =
  List.mapi
    (fun i b ->
      match () with
      | () when i = 0 -> b land 248
      | () when i = 31 -> (b land 127) lor 64
      | () -> b)
    bl

let secret_expand (seed : bytes) : (int list * int list) option =
  let* () = guard (Bytes.length seed = 32) in
  let h = bytes_to_ints (Sha512.digest seed) in
  let a_bytes, prefix = split_at 32 h in
  Some (pad16 (limbs_of_le_bytes (clamp a_bytes)), prefix)

let public_key (seed : bytes) : bytes option =
  let* () = guard base_point_ok in
  let* a, _ = secret_expand seed in
  Some (ints_to_bytes (compress (smul a base_point)))

let sign (seed : bytes) (msg : bytes) : bytes option =
  let* () = guard base_point_ok in
  let* a, prefix = secret_expand seed in
  let msg_l = bytes_to_ints msg in
  let a_bytes = compress (smul a base_point) in
  let hash bl = limbs_of_le_bytes (bytes_to_ints (Sha512.digest (ints_to_bytes bl))) in
  let r = sc_reduce (hash (prefix @ msg_l)) in
  let r_bytes = compress (smul r base_point) in
  let k = sc_reduce (hash (r_bytes @ a_bytes @ msg_l)) in
  let s = sc_add r (sc_mul k a) in
  let s_bytes = List.concat_map (fun limb -> [ limb land 0xff; limb lsr 8 ]) s in
  Some (ints_to_bytes (r_bytes @ s_bytes))

let verify (pk : bytes) (msg : bytes) (sg : bytes) : bool =
  match () with
  | () when not base_point_ok -> false
  | () when Bytes.length pk <> 32 -> false
  | () when Bytes.length sg <> 64 -> false
  | () ->
    let r_bytes, s_bytes = split_at 32 (bytes_to_ints sg) in
    let s = limbs_of_le_bytes s_bytes in
    if cmp s l_limbs >= 0 then false
    else
      Option.fold ~none:false
        ~some:(fun a_point ->
          let pk_l = bytes_to_ints pk in
          let k =
            sc_reduce
              (limbs_of_le_bytes
                 (bytes_to_ints
                    (Sha512.digest
                       (ints_to_bytes (r_bytes @ pk_l @ bytes_to_ints msg)))))
          in
          (* [S]B - [k]A must re-encode to the signature's R bytes. *)
          let rp = point_add (smul (pad16 s) base_point) (smul k (point_neg a_point)) in
          compress rp = r_bytes)
        (decompress (bytes_to_ints pk))

let on_curve (b : bytes) : bool =
  Bytes.length b = 32 && Option.is_some (decompress (bytes_to_ints b))
