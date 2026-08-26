(* Bounded frame: three epochs expose authority-to-bundle gaps 0, 1, 2.
   Gap 2 is the hazard the design must make unreachable. *)

type epoch = E0 | E1 | E2

let epoch_index = function E0 -> 0 | E1 -> 1 | E2 -> 2

let epoch_succ = function E0 -> Some E1 | E1 -> Some E2 | E2 -> None

type freshness = Fresh | Grace

type bundle = Held of freshness * epoch | Void

type svid = No_svid | Svid of epoch

type link = Up | Down

type state = { auth : epoch; bundle : bundle; svid : svid; link : link }

let init = { auth = E0; bundle = Held (Fresh, E0); svid = No_svid; link = Up }

module StateSet = Set.Make (struct
  type t = state

  let compare = Stdlib.compare
end)
