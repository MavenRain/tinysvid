(* M21 gate: the UDS transport against an in-process socketpair and a
   real bind/listen/connect roundtrip, single process, deterministic. *)

open Tinysvid_io

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let eq_ok expected r =
  Result.fold ~ok:(String.equal expected) ~error:(fun _ -> false) r

let is_sys r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Uds.Sys _ -> true
      | Uds.Path_too_long _ -> false
      | Uds.Eof -> false)
    r

let is_eof r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Uds.Eof -> true
      | Uds.Sys _ -> false
      | Uds.Path_too_long _ -> false)
    r

let is_path_too_long n r =
  Result.fold
    ~ok:(fun _ -> false)
    ~error:(fun e ->
      match e with
      | Uds.Path_too_long m -> m = n
      | Uds.Sys _ -> false
      | Uds.Eof -> false)
    r

(* Boundary helper for the stale socket file between forced reruns. *)
let rm path = try Unix.unlink path with Unix.Unix_error (_, _, _) -> ()

let () = Uds.ignore_sigpipe ()

let pair_tests =
  Uds.pair ()
  |> Result.fold
       ~error:(fun _ -> [ ("pair created", false) ])
       ~ok:(fun (a, b) ->
         let w = Uds.write_all a "hello" in
         let r = Uds.read_exactly b ~len:5 in
         let w6 = Uds.write_all a "abcdef" in
         let r4 = Uds.read_exactly b ~len:4 in
         let r2 = Uds.read_exactly b ~len:2 in
         let w3 = Uds.write_all a "xyz" in
         let s2 = Uds.read_some b ~max:2 in
         let s10 = Uds.read_some b ~max:10 in
         let z_read = Uds.read_some b ~max:0 in
         let z_exact = Uds.read_exactly b ~len:0 in
         let z_write = Uds.write_all a "" in
         Uds.close a;
         let eof = Uds.read_some b ~max:1 in
         let eof_exact = Uds.read_exactly b ~len:3 in
         Uds.close b;
         [
           ("pair write_all", Result.is_ok w);
           ("pair read_exactly whole", eq_ok "hello" r);
           ("pair write six", Result.is_ok w6);
           ("pair read_exactly split head", eq_ok "abcd" r4);
           ("pair read_exactly split tail", eq_ok "ef" r2);
           ("pair write three", Result.is_ok w3);
           ("pair read_some capped", eq_ok "xy" s2);
           ("pair read_some rest", eq_ok "z" s10);
           ("read_some zero max", eq_ok "" z_read);
           ("read_exactly zero len", eq_ok "" z_exact);
           ("write_all empty", Result.is_ok z_write);
           ("read_some after close is eof", is_eof eof);
           ("read_exactly after close is eof", is_eof eof_exact);
         ])

let epipe_tests =
  Uds.pair ()
  |> Result.fold
       ~error:(fun _ -> [ ("epipe pair created", false) ])
       ~ok:(fun (a, b) ->
         Uds.close b;
         let w1 = Uds.write_all a "x" in
         let w2 = Uds.write_all a "y" in
         Uds.close a;
         [
           ( "write to closed peer errors",
             Result.is_error w1 || Result.is_error w2 );
         ])

let path_tests =
  let long = String.make 200 'a' in
  [
    ("connect long path rejected", is_path_too_long 200 (Uds.connect ~path:long));
    ( "listen long path rejected",
      is_path_too_long 200 (Uds.listen ~path:long ~backlog:1) );
    ("connect missing path errors", is_sys (Uds.connect ~path:"no-such.sock"));
  ]

let sock_path = "test-uds.sock"

let roundtrip_tests =
  rm sock_path;
  Uds.listen ~path:sock_path ~backlog:1
  |> Result.fold
       ~error:(fun _ -> [ ("uds listen", false) ])
       ~ok:(fun l ->
         Uds.connect ~path:sock_path
         |> Result.fold
              ~error:(fun _ ->
                Uds.close_listener l;
                rm sock_path;
                [ ("uds connect", false) ])
              ~ok:(fun c ->
                Uds.accept l
                |> Result.fold
                     ~error:(fun _ ->
                       Uds.close c;
                       Uds.close_listener l;
                       rm sock_path;
                       [ ("uds accept", false) ])
                     ~ok:(fun s ->
                       let w1 = Uds.write_all c "ping" in
                       let r1 = Uds.read_exactly s ~len:4 in
                       let w2 = Uds.write_all s "pong!" in
                       let r2 = Uds.read_exactly c ~len:5 in
                       Uds.close c;
                       Uds.close s;
                       Uds.close_listener l;
                       rm sock_path;
                       [
                         ("uds client write", Result.is_ok w1);
                         ("uds server read", eq_ok "ping" r1);
                         ("uds server write", Result.is_ok w2);
                         ("uds client read", eq_ok "pong!" r2);
                       ])))

let () =
  let tests = pair_tests @ epipe_tests @ path_tests @ roundtrip_tests in
  let failures = List.fold_left (fun acc (n, ok) -> acc + check n ok) 0 tests in
  exit (min failures 1)
