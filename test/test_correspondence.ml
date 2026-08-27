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
         (* M26: the rotation engine is the code image of the
            (auth, bundle) projection of the Coupled frame. Lift each
            world, apply the engine step, and compare against the model
            transition. refresh is checked against the Sync result on
            every world: the link-Up enabling condition lives with the
            caller (a watch response only arrives over a live link). *)
         let lift_engine (w : State.state) =
           {
             Tinysvid.Rotation.td;
             epoch = Tinysvid.Bundle.Epoch (State.epoch_index w.auth);
             bundle = lift ~td w.bundle;
           }
         in
         let observe_engine e =
           "auth:"
           ^ string_of_int
               (Tinysvid.Bundle.epoch_value (Tinysvid.Rotation.epoch e))
           ^ "|"
           ^ observe_lib (Tinysvid.Rotation.bundle e)
         in
         let observe_pair (a, b) =
           "auth:" ^ string_of_int (State.epoch_index a) ^ "|" ^ observe_model b
         in
         let rotate_commutes =
           List.for_all
             (fun (w : State.state) ->
               State.epoch_succ w.auth
               |> Option.fold ~none:true
                    ~some:(fun a' ->
                      String.equal
                        (observe_engine
                           (Tinysvid.Rotation.rotate (lift_engine w)))
                        (observe_pair (a', Frame.degrade w.bundle))))
             worlds
         in
         let tick_commutes =
           List.for_all
             (fun (w : State.state) ->
               String.equal
                 (observe_engine (Tinysvid.Rotation.tick (lift_engine w)))
                 (observe_pair (w.auth, Frame.degrade w.bundle)))
             worlds
         in
         let refresh_commutes =
           List.for_all
             (fun (w : State.state) ->
               String.equal
                 (observe_engine
                    (Tinysvid.Rotation.refresh (lift_engine w)
                       ~roots:(Tinysvid.Bundle.Roots [])))
                 (observe_pair (w.auth, State.Held (State.Fresh, w.auth))))
             worlds
         in
         let failures =
           List.fold_left ( + ) 0
             [
               check "lift is faithful on every reachable world" lift_faithful;
               check "degrade commutes with the model on every reachable world"
                 degrade_commutes;
               check "engine rotate commutes with the model Rotate"
                 rotate_commutes;
               check "engine tick commutes with the model Tick" tick_commutes;
               check "engine refresh commutes with the model Sync"
                 refresh_commutes;
             ]
         in
         exit (Int.min failures 1))
