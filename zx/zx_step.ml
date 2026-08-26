(* ZxCaml artifact: the Coupled-frame bundle step over the int encoding
   from zx_core: k in {0=void, 1=fresh, 2=grace}, a = authority epoch
   and b = held epoch, each in {0, 1, 2}. rotate advances the authority
   and degrades the held bundle one step while a < 2; tick degrades the
   held bundle; sync re-fetches a fresh bundle stamped with the current
   authority epoch (the caller owes link-up). entrypoint checks domain
   closure, the degrade chain, the rotate laws at and below the epoch
   ceiling, and the sync laws over all 27 states, and returns the
   violation count; the expected return is 0. The host gate
   test/test_zx.ml compares each component against Bundle and against
   the model frame. *)

let degrade k = if k = 1 then 2 else 0

let rotate_a a = if a < 2 then a + 1 else a

let rotate_k a k = if a < 2 then degrade k else k

let tick_k k = degrade k

let sync_k a = 1 + (a * 0)

let sync_b a = a

let ge x lo = if x >= lo then 1 else 0

let le x hi = if x <= hi then 1 else 0

let eq x v = if x = v then 1 else 0

let ne x v = 1 - eq x v

let in_dom x = ge x 0 * le x 2

let dom_bad x = 1 - in_dom x

let cell a k b =
  dom_bad (rotate_a a) + dom_bad (rotate_k a k) + dom_bad (tick_k k)
  + dom_bad (sync_k b) + dom_bad (sync_b a)
  + ne (degrade (degrade (degrade k))) 0
  + (eq a 2 * (ne (rotate_a a) a + ne (rotate_k a k) k))
  + (le a 1 * (ne (rotate_a a) (a + 1) + ne (rotate_k a k) (degrade k)))
  + ne (sync_k b) 1 + ne (sync_b a) a

let row a k = cell a k 0 + cell a k 1 + cell a k 2

let plane a = row a 0 + row a 1 + row a 2

let entrypoint _input = plane 0 + plane 1 + plane 2
