(* ECDSA P-256 signature verification (FIPS 186-4, SEC 1) on the shared
   limb arithmetic, pure OCaml stdlib. Jacobian coordinates with a = -3;
   the point at infinity is Z = 0. NOT constant-time: verification
   handles only public inputs. The caller supplies the 32-byte SHA-256
   digest of the message. *)

open Limbs

let of_hex (h : string) : int list = pad16 (limbs_of_be_bytes (ints_of_hex h))

let p_mod : int list =
  of_hex "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"

let p_minus_2 : int list =
  of_hex "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd"

let n_ord : int list =
  of_hex "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

let n_minus_2 : int list =
  of_hex "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f"

let b_const : int list =
  of_hex "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"

let gx : int list =
  of_hex "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"

let gy : int list =
  of_hex "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

(* ---------- field arithmetic mod p, canonical 16-limb values ---------- *)

let norm16 (v : int list) : int list = pad16 (trim v)

let fe_red (v : int list) : int list = norm16 (mod_red p_mod v)

let fe_of_int (n : int) : int list = fe_red [ n ]

let fe_zero = fe_of_int 0

let fe_one = fe_of_int 1

let fe_add (a : int list) (b : int list) : int list = fe_red (add_lists a b)

(* a - b for canonical a, b: borrow p once when a < b. *)
let fe_sub (a : int list) (b : int list) : int list =
  if cmp a b >= 0 then norm16 (sub_limbs a b)
  else norm16 (sub_limbs (carry_norm (add_lists a p_mod)) b)

let fe_mul (a : int list) (b : int list) : int list = fe_red (mul_limbs a b)

let fe_eq (a : int list) (b : int list) : bool = cmp a b = 0

(* Square-and-multiply, LSB-first over the exponent bits, generic in the
   multiplication so the same walk serves both moduli. *)
let pow_mod (mul : int list -> int list -> int list) (one : int list)
    (base : int list) (e : int list) : int list =
  let res, _ =
    List.fold_left
      (fun (r, b) bit -> ((if bit = 1 then mul r b else r), mul b b))
      (one, base) (bits_of_limbs e)
  in
  res

let fe_inv (a : int list) : int list = pow_mod fe_mul fe_one a p_minus_2

(* ---------- scalar arithmetic mod the group order n ---------- *)

let sc_red (v : int list) : int list = norm16 (mod_red n_ord v)

let sc_mul (a : int list) (b : int list) : int list = sc_red (mul_limbs a b)

let sc_inv (a : int list) : int list = pow_mod sc_mul (sc_red [ 1 ]) a n_minus_2

(* ---------- curve and Jacobian point arithmetic ---------- *)

(* y^2 = x^3 - 3x + b, both sides canonical mod p. *)
let on_curve (x : int list) (y : int list) : bool =
  let xx = fe_mul x x in
  let rhs = fe_add (fe_sub (fe_mul xx x) (fe_add x (fe_add x x))) b_const in
  fe_eq (fe_mul y y) rhs

type jac = { x : int list; y : int list; z : int list }

let j_infinity : jac = { x = fe_one; y = fe_one; z = fe_zero }

let of_affine (x : int list) (y : int list) : jac = { x; y; z = fe_one }

let is_infinity (q : jac) : bool = fe_eq q.z fe_zero

(* Doubling; y = 0 has no witness on a prime-order curve but the arm
   keeps the map total on arbitrary Jacobian triples. *)
let jdouble (q : jac) : jac =
  match () with
  | () when is_infinity q -> j_infinity
  | () when fe_eq q.y fe_zero -> j_infinity
  | () ->
    let ysq = fe_mul q.y q.y in
    let s = fe_mul (fe_of_int 4) (fe_mul q.x ysq) in
    let zsq = fe_mul q.z q.z in
    let m = fe_mul (fe_of_int 3) (fe_mul (fe_sub q.x zsq) (fe_add q.x zsq)) in
    let x3 = fe_sub (fe_mul m m) (fe_add s s) in
    let y3 =
      fe_sub (fe_mul m (fe_sub s x3)) (fe_mul (fe_of_int 8) (fe_mul ysq ysq))
    in
    let z3 = fe_mul (fe_of_int 2) (fe_mul q.y q.z) in
    { x = x3; y = y3; z = z3 }

let jadd (p : jac) (q : jac) : jac =
  match () with
  | () when is_infinity p -> q
  | () when is_infinity q -> p
  | () ->
    let z1sq = fe_mul p.z p.z in
    let z2sq = fe_mul q.z q.z in
    let u1 = fe_mul p.x z2sq in
    let u2 = fe_mul q.x z1sq in
    let s1 = fe_mul p.y (fe_mul z2sq q.z) in
    let s2 = fe_mul q.y (fe_mul z1sq p.z) in
    (match () with
     | () when fe_eq u1 u2 && fe_eq s1 s2 -> jdouble p
     | () when fe_eq u1 u2 -> j_infinity
     | () ->
       let h = fe_sub u2 u1 in
       let r = fe_sub s2 s1 in
       let hsq = fe_mul h h in
       let hcu = fe_mul hsq h in
       let u1hsq = fe_mul u1 hsq in
       let x3 = fe_sub (fe_sub (fe_mul r r) hcu) (fe_add u1hsq u1hsq) in
       let y3 = fe_sub (fe_mul r (fe_sub u1hsq x3)) (fe_mul s1 hcu) in
       let z3 = fe_mul h (fe_mul p.z q.z) in
       { x = x3; y = y3; z = z3 })

(* Double-and-add over the 256 scalar bits, LSB first. *)
let smul (scalar : int list) (q : jac) : jac =
  let res, _ =
    List.fold_left
      (fun (r, b) bit -> ((if bit = 1 then jadd r b else r), jdouble b))
      (j_infinity, q)
      (bits_of_limbs (pad16 scalar))
  in
  res

let to_affine (q : jac) : (int list * int list) option =
  if is_infinity q then None
  else
    let zi = fe_inv q.z in
    let zi2 = fe_mul zi zi in
    Some (fe_mul q.x zi2, fe_mul q.y (fe_mul zi2 zi))

(* ---------- ECDSA verification ---------- *)

let nonzero (v : int list) : bool = cmp v [] > 0

(* x, y: the public point, big-endian-derived canonical limbs.
   digest: the 32-byte SHA-256 of the signed message.
   r, s: the signature scalars. False on any invalid input. *)
let verify ~(x : int list) ~(y : int list) ~(digest : string) ~(r : int list)
    ~(s : int list) : bool =
  let x = norm16 x and y = norm16 y and r = norm16 r and s = norm16 s in
  match () with
  | () when cmp x p_mod >= 0 || cmp y p_mod >= 0 -> false
  | () when not (on_curve x y) -> false
  | () when (not (nonzero r)) || cmp r n_ord >= 0 -> false
  | () when (not (nonzero s)) || cmp s n_ord >= 0 -> false
  | () ->
    let e = sc_red (limbs_of_be_bytes (string_to_ints digest)) in
    let w = sc_inv s in
    let u1 = sc_mul e w in
    let u2 = sc_mul r w in
    let rp = jadd (smul u1 (of_affine gx gy)) (smul u2 (of_affine x y)) in
    to_affine rp
    |> Option.fold ~none:false ~some:(fun (rx, _) -> cmp (sc_red rx) r = 0)
