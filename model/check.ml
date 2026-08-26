(* Property suite over the ctlk_topos kernel: each property is a CTLK
   formula evaluated by Ctlk.eval to a subobject of the reachable state
   object. Exit code 0 only when every verdict matches its expectation.
   The N-check runs on the Uncoupled negative-control frame and must
   expose the hazard; the Coupled design plus the Fresh/Grace/Void types
   exclude it. *)

open Svid_model
module T = Topos

type agent = Workload | Authority

type prop =
  | Usable
  | Fresh
  | Grace
  | Gap_is of int
  | Gap_at_most of int
  | Gap_at_least of int
  | Renew_enabled

type kind = Must_be_valid | Must_be_satisfiable

type check = {
  name : string;
  desc : string;
  kind : kind;
  frame : Frame.coupling;
  form : (prop, agent) Ctlk.form;
}

let view ag w =
  match ag with
  | Workload -> Props.view_workload w
  | Authority -> Props.view_authority w

let den coupling p =
  match p with
  | Usable -> Props.usable
  | Fresh -> Props.fresh
  | Grace -> Props.grace
  | Gap_is k -> Props.gap_is k
  | Gap_at_most k -> Props.gap_at_most k
  | Gap_at_least k -> Props.gap_at_least k
  | Renew_enabled ->
      fun w ->
        Frame.steps coupling w
        |> List.exists (fun (n, _) ->
               match n with
               | Frame.Renew -> true
               | Frame.Rotate | Frame.Tick | Frame.Sync | Frame.Expire
               | Frame.Link_flip ->
                   false)

let () =
  let agents = [ Workload; Authority ] in
  let sys_c =
    Ctlk.system_of Stdlib.compare (Frame.post Frame.Coupled) State.init agents view
  in
  let sys_u =
    Ctlk.system_of Stdlib.compare (Frame.post Frame.Uncoupled) State.init agents
      view
  in
  let open Ctlk in
  let checks =
    [
      {
        name = "A1-rotation-safety";
        desc = "AG (usable -> gap <= 1)";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Imp (Atom Usable, Atom (Gap_at_most 1));
      };
      {
        name = "A2-no-deadlock";
        desc = "AG EX true";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Ex Tt;
      };
      {
        name = "A3-recovery";
        desc = "AG EF fresh";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Ag (Ef (Atom Fresh));
      };
      {
        name = "A4-fresh-is-knowledge";
        desc = "AG (fresh -> K_workload gap = 0)";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Imp (Atom Fresh, Know (Workload, Atom (Gap_is 0)));
      };
      {
        name = "A5-grace-is-bounded-knowledge";
        desc = "AG (grace -> K_workload gap <= 1)";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Imp (Atom Grace, Know (Workload, Atom (Gap_at_most 1)));
      };
      {
        name = "A6-grace-uncertainty";
        desc = "EF (grace & !K_workload gap = 0 & !K_workload gap = 1)";
        kind = Must_be_satisfiable;
        frame = Frame.Coupled;
        form =
          And
            ( Atom Grace,
              And
                ( Not (Know (Workload, Atom (Gap_is 0))),
                  Not (Know (Workload, Atom (Gap_is 1))) ) );
      };
      {
        name = "A7-renew-needs-usable-bundle";
        desc = "AG (enabled renew -> usable)";
        kind = Must_be_valid;
        frame = Frame.Coupled;
        form = Imp (Atom Renew_enabled, Atom Usable);
      };
      {
        name = "A8-authority-blindness";
        desc = "EF (usable & !K_authority usable)";
        kind = Must_be_satisfiable;
        frame = Frame.Coupled;
        form = And (Atom Usable, Not (Know (Authority, Atom Usable)));
      };
      {
        name = "N1-uncoupled-hazard";
        desc = "uncoupled frame reaches usable & gap >= 2";
        kind = Must_be_satisfiable;
        frame = Frame.Uncoupled;
        form = And (Atom Usable, Atom (Gap_at_least 2));
      };
    ]
  in
  Printf.printf "worlds: coupled %d, uncoupled %d\n" (T.size sys_c.Ctlk.space)
    (T.size sys_u.Ctlk.space);
  (* Frame.reachable serves the correspondence and zx gates; it must
     agree with the kernel closure the property systems are built on. *)
  let reach_agree =
    State.StateSet.equal
      (Frame.reachable Frame.Coupled State.init)
      (State.StateSet.of_list sys_c.Ctlk.space.T.carrier)
    && State.StateSet.equal
         (Frame.reachable Frame.Uncoupled State.init)
         (State.StateSet.of_list sys_u.Ctlk.space.T.carrier)
  in
  Printf.printf "%s R0-reachable-agrees-kernel   both frames\n"
    (if reach_agree then "PASS" else "FAIL");
  let failures =
    List.fold_left
      (fun acc c ->
        let sys, den_f =
          match c.frame with
          | Frame.Coupled -> (sys_c, den Frame.Coupled)
          | Frame.Uncoupled -> (sys_u, den Frame.Uncoupled)
        in
        let sub = Ctlk.eval sys den_f c.form in
        let got =
          match c.kind with
          | Must_be_valid -> T.holds_everywhere sys.Ctlk.space sub
          | Must_be_satisfiable -> List.exists sub sys.Ctlk.space.T.carrier
        in
        let label =
          match c.kind with
          | Must_be_valid -> "valid"
          | Must_be_satisfiable -> "satisfiable"
        in
        let verdict = if got then "PASS" else "FAIL" in
        Printf.printf "%s %-28s must be %-11s  %s\n" verdict c.name label c.desc;
        acc + Bool.to_int (not got))
      (Bool.to_int (not reach_agree))
      checks
  in
  Printf.printf "%d checks, %d failures\n" (List.length checks + 1) failures;
  exit (Int.min failures 1)
