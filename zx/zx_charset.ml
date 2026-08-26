(* ZxCaml artifact: SPIFFE charset predicates over byte codes 0..255.
   td_char accepts [a-z0-9._-] (SPIFFE-ID spec section 2.1); seg_char
   accepts [a-zA-Z0-9._-] (section 2.2). The dialect stays inside the
   ZxCaml subset: ints, shallow ifs, no variants, no recursion, no
   top-level constants. Indicator sums over disjoint ranges replace the
   nested conditionals the house style would otherwise use. entrypoint
   probes every range boundary, each singleton, and the td-subset-of-seg
   law, and returns the violation count; the expected return is 0. The
   host gate test/test_zx.ml compares both predicates against the
   library on all 256 byte codes. *)

let ge x lo = if x >= lo then 1 else 0

let le x hi = if x <= hi then 1 else 0

let eq x v = if x = v then 1 else 0

let in_range b lo hi = ge b lo * le b hi

let td_char b =
  in_range b 97 122 + in_range b 48 57 + eq b 45 + eq b 46 + eq b 95

let seg_char b = td_char b + in_range b 65 90

let ne x v = 1 - eq x v

let td_probe b want = ne (td_char b) want

let seg_probe b want = ne (seg_char b) want

let sub_probe b = 1 - ge (seg_char b) (td_char b)

let bounds_td d =
  (d * 0)
  +
  td_probe 44 0 + td_probe 45 1 + td_probe 46 1 + td_probe 47 0
  + td_probe 48 1 + td_probe 57 1 + td_probe 58 0 + td_probe 64 0
  + td_probe 65 0 + td_probe 90 0 + td_probe 91 0 + td_probe 94 0
  + td_probe 95 1 + td_probe 96 0 + td_probe 97 1 + td_probe 122 1
  + td_probe 123 0 + td_probe 0 0 + td_probe 255 0

let bounds_seg d =
  (d * 0)
  +
  seg_probe 44 0 + seg_probe 45 1 + seg_probe 46 1 + seg_probe 47 0
  + seg_probe 48 1 + seg_probe 57 1 + seg_probe 58 0 + seg_probe 64 0
  + seg_probe 65 1 + seg_probe 90 1 + seg_probe 91 0 + seg_probe 94 0
  + seg_probe 95 1 + seg_probe 96 0 + seg_probe 97 1 + seg_probe 122 1
  + seg_probe 123 0 + seg_probe 0 0 + seg_probe 255 0

let bounds_sub d =
  (d * 0)
  +
  sub_probe 44 + sub_probe 45 + sub_probe 48 + sub_probe 65 + sub_probe 90
  + sub_probe 95 + sub_probe 97 + sub_probe 122 + sub_probe 255

let entrypoint _input = bounds_td 0 + bounds_seg 0 + bounds_sub 0
