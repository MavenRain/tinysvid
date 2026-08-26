(* Trust-bundle state machine, the code image of the model's Coupled frame.
   Freshness is a phantom type: Fresh and Grace bundles are distinct types,
   a stale bundle is Void and holds no roots, so no API can validate with
   it. refresh is the only Fresh constructor and it stamps the current
   epoch, so "rotated but still fresh" is not expressible. *)

type epoch = Epoch of int

let epoch_value (Epoch n) = n

let epoch_gap ~now:(Epoch now) ~held:(Epoch held) = now - held

type roots = Roots of string list

type fresh

type grace

type 'a held = {
  held_td : Trust_domain.t;
  held_epoch : epoch;
  held_roots : roots;
}

let refresh ~td ~epoch ~roots : fresh held =
  { held_td = td; held_epoch = epoch; held_roots = roots }

type usable = Ufresh of fresh held | Ugrace of grace held

type t = Usable of usable | Void

let of_fresh h = Usable (Ufresh h)

let to_grace (h : fresh held) : grace held =
  { held_td = h.held_td; held_epoch = h.held_epoch; held_roots = h.held_roots }

(* One TTL step. Rotation handlers must route through this, which is what
   keeps the code inside the model's Coupled frame. *)
let degrade = function
  | Usable (Ufresh h) -> Usable (Ugrace (to_grace h))
  | Usable (Ugrace _) -> Void
  | Void -> Void

let usable = function Usable u -> Some u | Void -> None

let usable_td = function Ufresh h -> h.held_td | Ugrace h -> h.held_td

let usable_epoch = function Ufresh h -> h.held_epoch | Ugrace h -> h.held_epoch

let usable_roots = function Ufresh h -> h.held_roots | Ugrace h -> h.held_roots
