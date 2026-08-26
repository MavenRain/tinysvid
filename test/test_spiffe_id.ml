open Tinysvid

let accepts s expected =
  Spiffe_id.parse s
  |> Result.fold
       ~ok:(fun id -> String.equal (Spiffe_id.to_string id) expected)
       ~error:(fun _ -> false)

let rejects s =
  Spiffe_id.parse s |> Result.fold ~ok:(fun _ -> false) ~error:(fun _ -> true)

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let () =
  let long_td = String.make 255 'a' in
  let over_td = String.make 256 'a' in
  let failures =
    List.fold_left ( + ) 0
      [
        check "workload id round-trips"
          (accepts "spiffe://example.org/workload/db"
             "spiffe://example.org/workload/db");
        check "trust-domain root id"
          (accepts "spiffe://example.org" "spiffe://example.org");
        check "mixed-case path accepted"
          (accepts "spiffe://example.org/Payments/API-v2.1_x"
             "spiffe://example.org/Payments/API-v2.1_x");
        check "255-char trust domain accepted"
          (accepts ("spiffe://" ^ long_td) ("spiffe://" ^ long_td));
        check "wrong scheme rejected" (rejects "http://example.org/x");
        check "empty trust domain rejected" (rejects "spiffe://");
        check "uppercase trust domain rejected" (rejects "spiffe://EXAMPLE.org/x");
        check "trust domain with port rejected"
          (rejects "spiffe://example.org:8443/x");
        check "256-char trust domain rejected" (rejects ("spiffe://" ^ over_td));
        check "trailing slash rejected" (rejects "spiffe://example.org/");
        check "empty segment rejected" (rejects "spiffe://example.org//a");
        check "dot segment rejected" (rejects "spiffe://example.org/./x");
        check "dotdot segment rejected" (rejects "spiffe://example.org/../x");
        check "space in segment rejected" (rejects "spiffe://example.org/a b");
        check "percent in segment rejected" (rejects "spiffe://example.org/a%20b");
        check "query in segment rejected" (rejects "spiffe://example.org/a?x=1");
        check "over-long id rejected"
          (rejects ("spiffe://example.org/" ^ String.make 2048 'a'));
      ]
  in
  exit (Int.min failures 1)
