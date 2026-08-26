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
   epoch. The authority observes its own epoch and the link. The kernel
   compares observations as strings, so each view renders its components
   injectively. *)

let bundle_view b =
  match b with
  | Held (Fresh, e) -> "fresh:" ^ string_of_int (epoch_index e)
  | Held (Grace, e) -> "grace:" ^ string_of_int (epoch_index e)
  | Void -> "void"

let svid_view s =
  match s with
  | Svid e -> "svid:" ^ string_of_int (epoch_index e)
  | No_svid -> "none"

let link_view l = match l with Up -> "up" | Down -> "down"

let view_workload w =
  String.concat "|" [ bundle_view w.bundle; svid_view w.svid; link_view w.link ]

let view_authority w =
  String.concat "|"
    [ "auth:" ^ string_of_int (epoch_index w.auth); link_view w.link ]
