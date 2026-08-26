(* Transition structure. Coupled is the shipped design: authority rotation
   degrades every held bundle one step, because one rotation period is an
   upper bound for bundle TTL. Uncoupled is the negative control: rotation
   leaves held bundles untouched, which makes the gap-2 hazard reachable. *)

open State

type coupling = Coupled | Uncoupled

type tname = Rotate | Tick | Sync | Renew | Expire | Link_flip

let tname_to_string = function
  | Rotate -> "rotate"
  | Tick -> "tick"
  | Sync -> "sync"
  | Renew -> "renew"
  | Expire -> "expire"
  | Link_flip -> "link-flip"

let degrade = function
  | Held (Fresh, e) -> Held (Grace, e)
  | Held (Grace, _) -> Void
  | Void -> Void

let usable = function Held (_, _) -> true | Void -> false

let steps coupling w =
  let rotated b = match coupling with Coupled -> degrade b | Uncoupled -> b in
  let rotate =
    epoch_succ w.auth
    |> Option.map (fun a -> (Rotate, { w with auth = a; bundle = rotated w.bundle }))
  in
  let tick = Some (Tick, { w with bundle = degrade w.bundle }) in
  let sync =
    match w.link with
    | Up -> Some (Sync, { w with bundle = Held (Fresh, w.auth) })
    | Down -> None
  in
  let renew =
    match (w.link, usable w.bundle) with
    | Up, true -> Some (Renew, { w with svid = Svid w.auth })
    | Up, false | Down, true | Down, false -> None
  in
  let expire =
    match w.svid with
    | Svid _ -> Some (Expire, { w with svid = No_svid })
    | No_svid -> None
  in
  let flip =
    let l = match w.link with Up -> Down | Down -> Up in
    Some (Link_flip, { w with link = l })
  in
  List.filter_map Fun.id [ rotate; tick; sync; renew; expire; flip ]

let post coupling w = List.map snd (steps coupling w)

(* Reachable closure via the kernel; the StateSet result keeps the
   downstream gates (correspondence, zx differential) unchanged. *)
let reachable coupling start =
  Ctlk.reachable Stdlib.compare (post coupling) start |> StateSet.of_list
