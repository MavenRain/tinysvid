(* Differential conformance gate (M20): the zx dialect is a subset of
   OCaml, so the artifact sources build into the host library
   tinysvid_zx and run here against the tinysvid core and the model on
   shared vectors: all 256 byte codes for the charset, all encoded
   frame states for the bundle step, and full grids for the window and
   the epoch-gap rule. Fidelity from these sources to the .so artifacts
   rests on the omlz codegen. Every artifact entrypoint must also
   return 0, its own violation count. *)

open Tinysvid
module ZC = Tinysvid_zx.Zx_charset
module ZS = Tinysvid_zx.Zx_step
module ZW = Tinysvid_zx.Zx_window
module MS = Svid_model.State
module MF = Svid_model.Frame

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* All 256 bytes, as in test_x509: no partial Char.chr anywhere. *)
let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

(* --- charset: host predicate against zx predicate, all 256 codes ---- *)

let charset_agrees host zx =
  String.to_seq byte_table
  |> Seq.fold_left
       (fun (i, ok) c -> (i + 1, ok && Bool.to_int (host c) = zx i))
       (0, true)
  |> snd

(* --- bundle step: int encoding against Bundle and the model frame --- *)

let all3 = [ 0; 1; 2 ]

let gaps = [ -2; -1; 0; 1; 2; 3 ]

let td = Trust_domain.Td "example.org"

let fresh e = Bundle.refresh ~td ~epoch:(Bundle.Epoch e) ~roots:(Bundle.Roots [])

let bundle_of_k k e =
  if k = 1 then Bundle.of_fresh (fresh e)
  else if k = 2 then Bundle.degrade (Bundle.of_fresh (fresh e))
  else Bundle.Void

let k_of_usable u =
  match u with
  | Bundle.Ufresh h ->
      ignore h;
      1
  | Bundle.Ugrace h ->
      ignore h;
      2

let k_of b = Bundle.usable b |> Option.fold ~none:0 ~some:k_of_usable

let epoch_of_int e = if e = 1 then MS.E1 else if e = 2 then MS.E2 else MS.E0

let mb_of k e =
  if k = 1 then MS.Held (MS.Fresh, epoch_of_int e)
  else if k = 2 then MS.Held (MS.Grace, epoch_of_int e)
  else MS.Void

let k_of_mb b =
  match b with
  | MS.Held (MS.Fresh, e) ->
      ignore e;
      1
  | MS.Held (MS.Grace, e) ->
      ignore e;
      2
  | MS.Void -> 0

let tick_agrees_bundle =
  List.for_all (fun k -> k_of (Bundle.degrade (bundle_of_k k 1)) = ZS.tick_k k) all3

let sync_agrees_bundle =
  List.for_all
    (fun a ->
      let h = fresh a in
      k_of (Bundle.of_fresh h) = ZS.sync_k a
      && Bundle.epoch_value (Bundle.usable_epoch (Bundle.Ufresh h)) = ZS.sync_b a)
    all3

let degrade_agrees_model =
  List.for_all
    (fun k ->
      List.for_all (fun e -> k_of_mb (MF.degrade (mb_of k e)) = ZS.degrade k) all3)
    all3

let rotate_agrees_model =
  List.for_all
    (fun a ->
      let succ = MS.epoch_succ (epoch_of_int a) in
      Option.fold ~none:(ZS.rotate_a a = a)
        ~some:(fun e -> MS.epoch_index e = ZS.rotate_a a)
        succ
      && List.for_all
           (fun k ->
             Option.fold
               ~none:(ZS.rotate_k a k = k)
               ~some:(fun e ->
                 ignore e;
                 k_of_mb (MF.degrade (mb_of k 1)) = ZS.rotate_k a k)
               succ)
           all3)
    all3

(* --- window and gap: shared grids against Svid and Chain ------------ *)

module Fake : Sig_backend.S = struct
  let verify ~alg ~spki ~message ~signature =
    ignore alg;
    ignore spki;
    ignore message;
    ignore signature;
    false
end

module C = Chain.Make (Fake)

let range5 = [ 0; 1; 2; 3; 4 ]

let cert nb na =
  {
    Svid.san_uris = [];
    not_before = Int64.of_int nb;
    not_after = Int64.of_int na;
    is_ca = false;
    key_usage = [];
  }

let window_agrees =
  List.for_all
    (fun now ->
      List.for_all
        (fun nb ->
          List.for_all
            (fun na ->
              Result.is_ok (Svid.check_window ~now:(Int64.of_int now) (cert nb na))
              = (ZW.window_ok now nb na = 1))
            range5)
        range5)
    range5

let gap_agrees k g =
  let held = 1 in
  let now_epoch = Bundle.Epoch (held + g) in
  let hf = fresh held in
  let u = if k = 1 then Bundle.Ufresh hf else Bundle.Ugrace (Bundle.to_grace hf) in
  Result.is_ok (C.epoch_rule ~now_epoch u) = (ZW.gap_ok k g = 1)

let gap_agrees_chain =
  List.for_all (fun k -> List.for_all (gap_agrees k) gaps) [ 1; 2 ]

let void_gap_rejects = List.for_all (fun g -> ZW.gap_ok 0 g = 0) gaps

let () =
  let failures =
    List.fold_left ( + ) 0
      [
        check "td_char agrees with Trust_domain on all 256 codes"
          (charset_agrees Trust_domain.is_td_char ZC.td_char);
        check "seg_char agrees with Spiffe_id on all 256 codes"
          (charset_agrees Spiffe_id.is_segment_char ZC.seg_char);
        check "tick_k agrees with Bundle.degrade" tick_agrees_bundle;
        check "sync_k/sync_b agree with Bundle.refresh" sync_agrees_bundle;
        check "degrade agrees with the model frame" degrade_agrees_model;
        check "rotate_a/rotate_k agree with the model frame" rotate_agrees_model;
        check "window_ok agrees with Svid.check_window on the 5^3 grid"
          window_agrees;
        check "gap_ok agrees with Chain.epoch_rule for fresh and grace"
          gap_agrees_chain;
        check "gap_ok rejects everything for void" void_gap_rejects;
        check "zx_core entrypoint returns 0" (Tinysvid_zx.Zx_core.entrypoint 0 = 0);
        check "zx_charset entrypoint returns 0" (ZC.entrypoint 0 = 0);
        check "zx_step entrypoint returns 0" (ZS.entrypoint 0 = 0);
        check "zx_window entrypoint returns 0" (ZW.entrypoint 0 = 0);
      ]
  in
  exit (Int.min failures 1)
