(* ZxCaml artifact: inductive check of the model's A1 invariant
   (usable -> auth - held <= 1) over the int-encoded bundle projection.
   A1 as stated is not inductive on the full cube: the unreachable
   fresh-but-stale state (a=1, k=1, b=0) breaks the rotate step. The
   check therefore uses the strengthened invariant inv -- void, or
   fresh with gap exactly 0, or grace with gap 0 or 1, which is the
   A4/A5 epoch-gap rule -- and verifies both that inv is inductive
   under rotate, tick, and sync, and that inv implies A1. Encoding:
   k in {0=void, 1=fresh, 2=grace}, b = held epoch, a = authority
   epoch, each in {0, 1, 2}. entrypoint returns the violation count
   across all 27 states; the expected return is 0. The dialect stays
   inside the ZxCaml subset: ints, shallow ifs, no variants, no
   recursion. Indicator arithmetic replaces the nested conditionals
   the house style would otherwise use. *)

let eq x v = if x = v then 1 else 0

let ge x lo = if x >= lo then 1 else 0

let le x hi = if x <= hi then 1 else 0

let degrade k = if k = 1 then 2 else 0

let gap01 a b = ge (a - b) 0 * le (a - b) 1

let inv a k b = eq k 0 + (eq k 1 * eq a b) + (eq k 2 * gap01 a b)

let a1 a k b = eq k 0 + ((1 - eq k 0) * le (a - b) 1)

let step_check a k b =
  let live = inv a k b in
  let ra = if a < 2 then a + 1 else a in
  let rk = if a < 2 then degrade k else k in
  let bad_rotate = 1 - inv ra rk b in
  let bad_tick = 1 - inv a (degrade k) b in
  let bad_sync = 1 - inv a 1 a in
  let bad_a1 = 1 - a1 a k b in
  live * (bad_rotate + bad_tick + bad_sync + bad_a1)

let row a k = step_check a k 0 + step_check a k 1 + step_check a k 2

let plane a = row a 0 + row a 1 + row a 2

let entrypoint _input = plane 0 + plane 1 + plane 2
