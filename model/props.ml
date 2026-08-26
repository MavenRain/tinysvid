open State

let gap w =
  match w.bundle with
  | Held (_, e) -> Some (epoch_index w.auth - epoch_index e)
  | Void -> None

let usable w = Frame.usable w.bundle

let fresh w =
  match w.bundle with Held (Fresh, _) -> true | Held (Grace, _) | Void -> false

let grace w =
  match w.bundle with Held (Grace, _) -> true | Held (Fresh, _) | Void -> false

let gap_is k w = gap w |> Option.fold ~none:false ~some:(Int.equal k)

let gap_at_most k w = gap w |> Option.fold ~none:false ~some:(fun g -> g <= k)

let gap_at_least k w = gap w |> Option.fold ~none:false ~some:(fun g -> g >= k)

(* The workload observes only its local components, never the authority
   epoch. The authority observes its own epoch and the link. *)

let obs_workload w = (w.bundle, w.svid, w.link)

let obs_authority w = (w.auth, w.link)
