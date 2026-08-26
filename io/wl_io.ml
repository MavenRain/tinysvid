(* M24 stage C: blocking Workload API runner over the UDS transport.
   The pure engine (Tinysvid.Wl_client) owns the protocol; this module
   only moves bytes: write the request, then read, feed, write the
   engine's replies, and hand each event to the caller's stop function
   until it answers. *)

type error = Io of Uds.error | Client of Tinysvid.Wl_client.error

let error_to_string e =
  match e with
  | Io e -> "io:" ^ Uds.error_to_string e
  | Client e -> "client:" ^ Tinysvid.Wl_client.error_to_string e

let chunk_size = 16384

(* run : Uds.conn -> authority:string ->
         stop:(Tinysvid.Wl_client.event -> 'a option) -> ('a, error) result
   Every event goes to stop in order; the first Some ends the run. An
   Eof before stop answers surfaces as an io error. *)
let run conn ~authority ~stop =
  Result.bind
    (Tinysvid.Wl_client.request_bytes ~authority
    |> Result.map_error (fun e -> Client e))
    (fun req ->
      Result.bind
        (Uds.write_all conn req |> Result.map_error (fun e -> Io e))
        (fun () ->
          let rec loop st =
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
                       reaches the caller. The fold arms are values, so
                       this stays one tail call whichever way it goes. *)
                    match
                      List.find_map stop events
                      |> Option.fold ~none:`Continue ~some:(fun a -> `Done a)
                    with
                    | `Done a -> Ok a
                    | `Continue -> (
                        match st.Tinysvid.Wl_client.phase with
                        | Tinysvid.Wl_client.Failed e -> Error (Client e)
                        | Tinysvid.Wl_client.Awaiting_headers
                        | Tinysvid.Wl_client.Streaming
                        | Tinysvid.Wl_client.Closed ->
                            loop st)))
          in
          loop Tinysvid.Wl_client.initial))

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

(* Connect, fetch one response, close either way. *)
let fetch_path ~path ~authority =
  Result.bind
    (Uds.connect ~path |> Result.map_error (fun e -> Io e))
    (fun conn ->
      let r = fetch conn ~authority in
      Uds.close conn;
      r)
