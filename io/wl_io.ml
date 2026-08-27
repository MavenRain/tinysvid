(* M24 stage C: blocking Workload API runner over the UDS transport.
   The pure engine (Tinysvid.Wl_client) owns the protocol; this module
   only moves bytes: write the request, then read, feed, write the
   engine's replies, and hand each event to the caller's stop function
   until it answers. *)

type error =
  | Io of Uds.error
  | Client of Tinysvid.Wl_client.error
  | Rotation of Tinysvid.Rotation.error

let error_to_string e =
  match e with
  | Io e -> "io:" ^ Uds.error_to_string e
  | Client e -> "client:" ^ Tinysvid.Wl_client.error_to_string e
  | Rotation e -> "rotation:" ^ Tinysvid.Rotation.error_to_string e

let chunk_size = 16384

(* run_fold : Uds.conn -> authority:string -> init:'acc ->
              step:('acc -> Tinysvid.Wl_client.event ->
                    ('acc, 'stopped) Either.t) -> ('stopped, error) result
   Threads an accumulator through every event in order; the first Right
   ends the run. An Eof before step answers surfaces as an io error. *)
let run_fold conn ~authority ~init ~step =
  Result.bind
    (Tinysvid.Wl_client.request_bytes ~authority
    |> Result.map_error (fun e -> Client e))
    (fun req ->
      Result.bind
        (Uds.write_all conn req |> Result.map_error (fun e -> Io e))
        (fun () ->
          let rec loop st acc =
            Result.bind
              (Uds.read_some conn ~max:chunk_size
              |> Result.map_error (fun e -> Io e))
              (fun chunk ->
                let st, events, out = Tinysvid.Wl_client.feed st chunk in
                Result.bind
                  (match () with
                  | () when String.length out = 0 -> Ok ()
                  | () ->
                      Uds.write_all conn out |> Result.map_error (fun e -> Io e))
                  (fun () ->
                    (* events first, then the terminal phase: a response
                       decoded in the same read as a failure still
                       reaches the caller. *)
                    List.fold_left
                      (fun verdict ev ->
                        Either.fold verdict
                          ~left:(fun acc -> step acc ev)
                          ~right:(fun stopped -> Either.Right stopped))
                      (Either.Left acc) events
                    |> Either.fold
                         ~right:(fun stopped -> Ok stopped)
                         ~left:(fun acc ->
                           match st.Tinysvid.Wl_client.phase with
                           | Tinysvid.Wl_client.Failed e -> Error (Client e)
                           | Tinysvid.Wl_client.Awaiting_headers
                           | Tinysvid.Wl_client.Streaming
                           | Tinysvid.Wl_client.Closed ->
                               loop st acc)))
          in
          loop Tinysvid.Wl_client.initial init))

(* run : Uds.conn -> authority:string ->
         stop:(Tinysvid.Wl_client.event -> 'a option) -> ('a, error) result
   Every event goes to stop in order; the first Some ends the run. *)
let run conn ~authority ~stop =
  run_fold conn ~authority ~init:() ~step:(fun () ev ->
      stop ev |> Option.fold ~none:(Either.Left ()) ~some:Either.right)

(* The first SVID response; the caller closes the connection. *)
let fetch conn ~authority =
  run conn ~authority ~stop:(fun ev ->
      match ev with
      | Tinysvid.Wl_client.Response r -> Some r
      | Tinysvid.Wl_client.Opened _ | Tinysvid.Wl_client.Finished -> None)

(* Deliver every response until the server ends the stream cleanly. *)
let watch conn ~authority ~on_response =
  run conn ~authority ~stop:(fun ev ->
      match ev with
      | Tinysvid.Wl_client.Response r ->
          on_response r;
          None
      | Tinysvid.Wl_client.Finished -> Some ()
      | Tinysvid.Wl_client.Opened _ -> None)

(* M26: fold every watch response into the typed rotation state through
   Rotation.refresh_of_response, which routes through Bundle.refresh at
   the engine's current epoch. A response that fails to refresh (a
   foreign-domain-only response, a malformed spiffe_id, bad bundle
   bytes) is a typed failure, not a skipped update: a node that keeps
   serving silently on a stale bundle is the hazard the model rejects.
   A clean server Finished returns the final state. The rotate and tick
   timers stay with the caller; both are pure Rotation steps. *)
let watch_rotation conn ~authority ~init =
  run_fold conn ~authority ~init ~step:(fun st ev ->
      match ev with
      | Tinysvid.Wl_client.Opened _ -> Either.Left st
      | Tinysvid.Wl_client.Response r ->
          Tinysvid.Rotation.refresh_of_response st r
          |> Result.fold ~ok:Either.left ~error:(fun e ->
                 Either.Right (Error (Rotation e)))
      | Tinysvid.Wl_client.Finished -> Either.Right (Ok st))
  |> Result.join

(* Connect, fetch one response, close either way. *)
let fetch_path ~path ~authority =
  Result.bind
    (Uds.connect ~path |> Result.map_error (fun e -> Io e))
    (fun conn ->
      let r = fetch conn ~authority in
      Uds.close conn;
      r)
