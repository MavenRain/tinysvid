(* Property suite. Exit code 0 only when every verdict matches its
   expectation. The N-check runs on the Uncoupled negative-control frame
   and must expose the hazard; the Coupled design plus the
   Fresh/Grace/Void types exclude it. *)

open Svid_model
open State

type kind = Must_be_valid | Must_be_satisfiable

type check = {
  name : string;
  desc : string;
  kind : kind;
  univ : StateSet.t;
  sub : StateSet.t;
}

let () =
  let univ_c = Frame.reachable Frame.Coupled init in
  let post_c = Frame.post Frame.Coupled in
  let univ_u = Frame.reachable Frame.Uncoupled init in
  let pc p = Sub.of_pred univ_c p in
  let usable_c = pc Props.usable in
  let fresh_c = pc Props.fresh in
  let grace_c = pc Props.grace in
  let know_w = Modal.know ~obs:Props.obs_workload univ_c in
  let know_a = Modal.know ~obs:Props.obs_authority univ_c in
  let enabled t w = Frame.steps Frame.Coupled w |> List.exists (fun (n, _) -> n = t) in
  let checks =
    [
      {
        name = "A1-rotation-safety";
        desc = "AG (usable -> gap <= 1)";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Sub.impl univ_c usable_c (pc (Props.gap_at_most 1));
      };
      {
        name = "A2-no-deadlock";
        desc = "AG EX true";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Modal.ex ~post:post_c univ_c (Sub.top univ_c);
      };
      {
        name = "A3-recovery";
        desc = "AG EF fresh";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Ctlk.ag ~post:post_c univ_c (Ctlk.ef ~post:post_c univ_c fresh_c);
      };
      {
        name = "A4-fresh-is-knowledge";
        desc = "AG (fresh -> K_workload gap = 0)";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Sub.impl univ_c fresh_c (know_w (pc (Props.gap_is 0)));
      };
      {
        name = "A5-grace-is-bounded-knowledge";
        desc = "AG (grace -> K_workload gap <= 1)";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Sub.impl univ_c grace_c (know_w (pc (Props.gap_at_most 1)));
      };
      {
        name = "A6-grace-uncertainty";
        desc = "EF (grace & !K_workload gap = 0 & !K_workload gap = 1)";
        kind = Must_be_satisfiable;
        univ = univ_c;
        sub =
          Sub.meet grace_c
            (Sub.meet
               (Sub.neg univ_c (know_w (pc (Props.gap_is 0))))
               (Sub.neg univ_c (know_w (pc (Props.gap_is 1)))));
      };
      {
        name = "A7-renew-needs-usable-bundle";
        desc = "AG (enabled renew -> usable)";
        kind = Must_be_valid;
        univ = univ_c;
        sub = Sub.impl univ_c (pc (enabled Frame.Renew)) usable_c;
      };
      {
        name = "A8-authority-blindness";
        desc = "EF (usable & !K_authority usable)";
        kind = Must_be_satisfiable;
        univ = univ_c;
        sub = Sub.meet usable_c (Sub.neg univ_c (know_a usable_c));
      };
      {
        name = "N1-uncoupled-hazard";
        desc = "uncoupled frame reaches usable & gap >= 2";
        kind = Must_be_satisfiable;
        univ = univ_u;
        sub =
          Sub.meet
            (Sub.of_pred univ_u Props.usable)
            (Sub.of_pred univ_u (Props.gap_at_least 2));
      };
    ]
  in
  Printf.printf "worlds: coupled %d, uncoupled %d\n"
    (StateSet.cardinal univ_c) (StateSet.cardinal univ_u);
  let failures =
    List.fold_left
      (fun acc c ->
        let got =
          match c.kind with
          | Must_be_valid -> Sub.is_valid c.univ c.sub
          | Must_be_satisfiable -> Sub.nonempty c.sub
        in
        let label =
          match c.kind with
          | Must_be_valid -> "valid"
          | Must_be_satisfiable -> "satisfiable"
        in
        let verdict = if got then "PASS" else "FAIL" in
        Printf.printf "%s %-28s must be %-11s  %s\n" verdict c.name label c.desc;
        acc + Bool.to_int (not got))
      0 checks
  in
  Printf.printf "%d checks, %d failures\n" (List.length checks) failures;
  exit (Int.min failures 1)
