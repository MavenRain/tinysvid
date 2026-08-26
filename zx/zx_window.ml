(* ZxCaml artifact: the SVID validity window and the A4/A5 epoch-gap
   rule over ints. window_ok mirrors Svid.check_window: valid while
   not_before <= now < not_after. gap_limit mirrors Chain.epoch_rule
   over the k encoding: fresh (1) allows gap 0, grace (2) allows gap at
   most 1, void (0) allows nothing; a negative gap always rejects.
   check is the conjunction, as at the chain validation boundary.
   entrypoint probes the window boundaries, the empty window, the full
   gap table, and the conjunction, and returns the violation count; the
   expected return is 0. The host gate test/test_zx.ml compares both
   checks against Svid and Chain on shared vectors. *)

let ge x lo = if x >= lo then 1 else 0

let lt x hi = if x < hi then 1 else 0

let le x hi = if x <= hi then 1 else 0

let eq x v = if x = v then 1 else 0

let ne x v = 1 - eq x v

let window_ok now nb na = ge now nb * lt now na

let gap_limit k = if k = 1 then 0 else if k = 2 then 1 else 0 - 1

let gap_ok k g = ge g 0 * le g (gap_limit k)

let check k g now nb na = gap_ok k g * window_ok now nb na

let win_probes d =
  (d * 0)
  +
  ne (window_ok 9 10 20) 0 + ne (window_ok 10 10 20) 1
  + ne (window_ok 19 10 20) 1 + ne (window_ok 20 10 20) 0
  + ne (window_ok 10 10 10) 0 + ne (window_ok 0 10 20) 0
  + ne (window_ok 30 10 20) 0

let gap_probes d =
  (d * 0)
  +
  ne (gap_ok 1 0) 1 + ne (gap_ok 1 1) 0 + ne (gap_ok 1 (0 - 1)) 0
  + ne (gap_ok 2 0) 1 + ne (gap_ok 2 1) 1 + ne (gap_ok 2 2) 0
  + ne (gap_ok 2 (0 - 1)) 0 + ne (gap_ok 0 0) 0 + ne (gap_ok 0 1) 0

let combine_probes d =
  (d * 0)
  +
  ne (check 1 0 10 10 20) 1 + ne (check 1 0 9 10 20) 0
  + ne (check 1 1 15 10 20) 0 + ne (check 2 1 15 10 20) 1
  + ne (check 0 0 15 10 20) 0

let entrypoint _input = win_probes 0 + gap_probes 0 + combine_probes 0
