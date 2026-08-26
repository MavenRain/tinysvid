(* Sub(1) of the presheaf topos Set^W over the discrete world category:
   the powerset of reachable worlds as a complete Heyting algebra.
   Fixpoints exist by Knaster-Tarski; the lattice is finite so naive
   iteration terminates. *)

open State

type t = StateSet.t

let of_pred univ p = StateSet.filter p univ

let top univ = univ

let bot = StateSet.empty

let meet = StateSet.inter

let join = StateSet.union

let neg univ a = StateSet.diff univ a

let impl univ a b = join (neg univ a) b

let equal = StateSet.equal

let is_valid univ a = StateSet.subset univ a

let nonempty a = not (StateSet.is_empty a)

let rec fix f x =
  let y = f x in
  if equal x y then x else fix f y

let lfp f = fix f bot

let gfp univ f = fix f (top univ)
