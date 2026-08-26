(* Modalities as adjoints along relations, per the quantifiers-as-adjoints
   reading of the internal logic. EX is inverse image along the transition
   relation (an existential along a projection composed with pullback), AX
   its de Morgan dual (the universal adjoint). know is the comonad
   q* . forall_q induced by the quotient map q_i : W -> W / ~_i of an
   agent's observational equivalence, i.e. S5 necessity for that agent. *)

open State

let ex ~post univ phi =
  Sub.of_pred univ (fun w -> List.exists (fun v -> StateSet.mem v phi) (post w))

let ax ~post univ phi = Sub.neg univ (ex ~post univ (Sub.neg univ phi))

let know ~obs univ phi =
  Sub.of_pred univ (fun w ->
      StateSet.for_all (fun v -> obs v <> obs w || StateSet.mem v phi) univ)
