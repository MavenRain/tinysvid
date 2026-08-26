(* ZxCaml artifact: inductive-step check of the model's A1 invariant
   (usable -> auth - held <= 1) over the int-encoded bundle projection.
   Encoding: k in {0=void, 1=fresh, 2=grace}, b = held epoch, a = authority
   epoch, each in {0, 1, 2}. entrypoint returns the count of invariant-
   preservation violations across rotate, tick, and sync; the expected
   return is 0. The dialect stays inside the ZxCaml subset: ints, single
   non-nested ifs, no variants, no recursion. Branchless arithmetic (the
   live multiplier) replaces the nested conditional the house style would
   otherwise use. *)

let inv a k b =
  if k = 0 then 1 else if a - b <= 1 then 1 else 0

let degrade k = if k = 1 then 2 else 0

let step_check a k b =
  let live = inv a k b in
  let ra = if a < 2 then a + 1 else a in
  let rk = if a < 2 then degrade k else k in
  let bad_rotate = 1 - inv ra rk b in
  let bad_tick = 1 - inv a (degrade k) b in
  let bad_sync = 1 - inv a 1 a in
  live * (bad_rotate + bad_tick + bad_sync)

let row a k = step_check a k 0 + step_check a k 1 + step_check a k 2

let plane a = row a 0 + row a 1 + row a 2

let entrypoint _input = plane 0 + plane 1 + plane 2
