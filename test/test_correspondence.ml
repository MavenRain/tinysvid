(* Model-to-code gate: over every reachable world of the Coupled frame,
   the library bundle machine commutes with the model transition through
   the lift/observe maps. A drift in either side breaks this test before
   it breaks production. *)

open Svid_model

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let observe_model b =
  match b with
  | State.Held (State.Fresh, e) -> "fresh:" ^ string_of_int (State.epoch_index e)
  | State.Held (State.Grace, e) -> "grace:" ^ string_of_int (State.epoch_index e)
  | State.Void -> "void"

let observe_lib b =
  Tinysvid.Bundle.usable b
  |> Option.fold ~none:"void" ~some:(fun u ->
         let tag =
           match u with
           | Tinysvid.Bundle.Ufresh _ -> "fresh"
           | Tinysvid.Bundle.Ugrace _ -> "grace"
         in
         tag ^ ":"
         ^ string_of_int
             (Tinysvid.Bundle.epoch_value (Tinysvid.Bundle.usable_epoch u)))

let lift ~td b =
  match b with
  | State.Held (State.Fresh, e) ->
      Tinysvid.Bundle.of_fresh
        (Tinysvid.Bundle.refresh ~td
           ~epoch:(Tinysvid.Bundle.Epoch (State.epoch_index e))
           ~roots:(Tinysvid.Bundle.Roots []))
  | State.Held (State.Grace, e) ->
      Tinysvid.Bundle.degrade
        (Tinysvid.Bundle.of_fresh
           (Tinysvid.Bundle.refresh ~td
              ~epoch:(Tinysvid.Bundle.Epoch (State.epoch_index e))
              ~roots:(Tinysvid.Bundle.Roots [])))
  | State.Void -> Tinysvid.Bundle.Void

let () =
  Tinysvid.Trust_domain.parse "example.org"
  |> Result.fold
       ~error:(fun _ ->
         Printf.printf "FAIL trust-domain fixture\n";
         exit 1)
       ~ok:(fun td ->
         let univ = Frame.reachable Frame.Coupled State.init in
         let worlds = State.StateSet.elements univ in
         let lift_faithful =
           List.for_all
             (fun (w : State.state) ->
               String.equal
                 (observe_lib (lift ~td w.bundle))
                 (observe_model w.bundle))
             worlds
         in
         let degrade_commutes =
           List.for_all
             (fun (w : State.state) ->
               String.equal
                 (observe_lib (Tinysvid.Bundle.degrade (lift ~td w.bundle)))
                 (observe_model (Frame.degrade w.bundle)))
             worlds
         in
         let failures =
           List.fold_left ( + ) 0
             [
               check "lift is faithful on every reachable world" lift_faithful;
               check "degrade commutes with the model on every reachable world"
                 degrade_commutes;
             ]
         in
         exit (Int.min failures 1))
