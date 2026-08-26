(* Generic little-endian 16-bit limb arithmetic shared by the curve
   backends. Big numbers: immutable int lists, base 2^16 limbs, LSB
   first. 16-bit limbs keep products under 32 bits and sums under 63
   bits. NOT constant-time: this library only verifies public inputs. *)

let ( let* ) = Option.bind

let guard (b : bool) : unit option = if b then Some () else None

let mask16 = 0xffff

(* Total map2: stops at the shorter list. Callers keep lengths equal. *)
let rec map2t (f : int -> int -> int) (a : int list) (b : int list) : int list =
  match (a, b) with
  | [], _ -> []
  | _ :: _, [] -> []
  | x :: xs, y :: ys -> f x y :: map2t f xs ys

(* Total fold over two lists: stops at the shorter list. *)
let rec fold2t (f : 'a -> int -> int -> 'a) (acc : 'a) (a : int list) (b : int list) : 'a =
  match (a, b) with
  | [], _ -> acc
  | _ :: _, [] -> acc
  | x :: xs, y :: ys -> fold2t f (f acc x y) xs ys

(* Drop zero limbs at the most significant end. *)
let trim (ls : int list) : int list =
  let rec dropz l =
    match l with
    | [] -> []
    | 0 :: rest -> dropz rest
    | v :: rest -> v :: rest
  in
  List.rev (dropz (List.rev ls))

let pad_to (n : int) (ls : int list) : int list =
  let len = List.length ls in
  if len >= n then ls else ls @ List.init (n - len) (fun _ -> 0)

let pad16 (ls : int list) : int list = pad_to 16 ls

(* Carry-propagate nonnegative limbs into canonical 16-bit limbs. *)
let carry_norm (ls : int list) : int list =
  let rev_low, c =
    List.fold_left
      (fun (acc, c) v ->
        let s = v + c in
        ((s land mask16) :: acc, s lsr 16))
      ([], 0) ls
  in
  (* Remaining carry becomes limbs above; push builds MSB first. *)
  let rec push c acc = if c = 0 then acc else push (c lsr 16) ((c land mask16) :: acc) in
  List.rev (push c [] @ rev_low)

(* Element-wise add; the shorter list is zero-padded. *)
let rec add_lists (a : int list) (b : int list) : int list =
  match (a, b) with
  | [], rest -> rest
  | rest, [] -> rest
  | x :: xs, y :: ys -> (x + y) :: add_lists xs ys

(* Compare as numbers: negative, zero, positive. *)
let cmp (a : int list) (b : int list) : int =
  let a = trim a and b = trim b in
  let la = List.length a and lb = List.length b in
  if la <> lb then Int.compare la lb
  else
    fold2t
      (fun acc x y -> if acc <> 0 then acc else Int.compare x y)
      0 (List.rev a) (List.rev b)

(* a - b, requires a >= b; result has the length of a. *)
let sub_limbs (a : int list) (b : int list) : int list =
  let b = pad_to (List.length a) b in
  let rev, _ =
    fold2t
      (fun (acc, bor) x y ->
        let s = x - y - bor in
        if s < 0 then ((s + 0x10000) :: acc, 1) else (s :: acc, 0))
      ([], 0) a b
  in
  List.rev rev

let shift_limbs (ls : int list) (k : int) : int list =
  List.init (max k 0) (fun _ -> 0) @ ls

(* Schoolbook multiply; limbs of both inputs must be < 2^16. *)
let mul_limbs (a : int list) (b : int list) : int list =
  let partials =
    List.mapi (fun i ai -> shift_limbs (List.map (fun bj -> ai * bj) b) i) a
  in
  List.fold_left add_lists [] partials

let rec split_at (n : int) (ls : int list) : int list * int list =
  if n <= 0 then ([], ls)
  else
    match ls with
    | [] -> ([], [])
    | x :: rest ->
      let low, high = split_at (n - 1) rest in
      (x :: low, high)

(* LSB-first bits of a limb list. *)
let bits_of_limbs (ls : int list) : int list =
  List.concat_map (fun limb -> List.init 16 (fun i -> (limb lsr i) land 1)) ls

(* ---------- bytes <-> limbs ---------- *)

let bytes_to_ints (b : bytes) : int list =
  List.of_seq (Seq.map Char.code (Bytes.to_seq b))

let string_to_ints (s : string) : int list =
  List.of_seq (Seq.map Char.code (String.to_seq s))

let ints_to_bytes (l : int list) : bytes =
  let buf = Buffer.create (max (List.length l) 1) in
  List.iter (fun v -> Buffer.add_int8 buf v) l;
  Buffer.to_bytes buf

(* Little-endian byte list to 16-bit limbs. *)
let rec limbs_of_le_bytes (bl : int list) : int list =
  match bl with
  | [] -> []
  | [ b0 ] -> [ b0 ]
  | b0 :: b1 :: rest -> (b0 lor (b1 lsl 8)) :: limbs_of_le_bytes rest

(* Big-endian byte list to 16-bit limbs. *)
let limbs_of_be_bytes (bl : int list) : int list = limbs_of_le_bytes (List.rev bl)

(* Hex string to a big-endian byte list, for embedded constants. An odd
   trailing nibble is dropped; constants are always whole bytes. *)
let ints_of_hex (s : string) : int list =
  let hex_val c =
    let n = Char.code c in
    match () with
    | () when n >= 48 && n <= 57 -> n - 48
    | () when n >= 97 && n <= 102 -> n - 87
    | () when n >= 65 && n <= 70 -> n - 55
    | () -> 0
  in
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
  List.rev ints_rev

(* v mod m by quotient-estimate subtraction; m must be nonzero. Each
   step divides the one or two leading limbs of v by mtop, one more than
   the leading limb of m (so mtop >= 1 and the divisions are total), and
   the scaled, shifted subtrahend never exceeds v while every step
   retires about one limb. The input may carry oversized limbs (e.g. a
   schoolbook product); it is normalized first. The result is trimmed
   and canonical. *)
let mod_red (m : int list) (v : int list) : int list =
  let mt = trim m in
  let lm = List.length mt in
  let mtop =
    match List.rev mt with
    | [] -> 1
    | t :: _ -> t + 1
  in
  let rec go v =
    let vt = trim v in
    if cmp vt mt < 0 then vt
    else
      let sh = List.length vt - lm in
      if sh = 0 then go (sub_limbs vt mt)
      else
        let q, sh =
          match List.rev vt with
          | [] -> (1, sh)
          | [ _ ] -> (1, sh)
          | t1 :: t2 :: _ ->
            let q = t1 / mtop in (* @total-accessor *)
            if q >= 1 then (q, sh)
            else (max (((t1 lsl 16) lor t2) / mtop) 1, sh - 1) (* @total-accessor *)
        in
        go (sub_limbs vt (carry_norm (shift_limbs (List.map (fun x -> x * q) mt) sh)))
  in
  go (trim (carry_norm v))
