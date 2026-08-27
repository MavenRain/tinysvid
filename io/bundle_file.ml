(* M25: file bundle source for fully disconnected nodes. The file holds
   the trust bundle as concatenated DER certificates, the same format
   the Workload API bundle field carries, so one parser serves both
   sources (Tinysvid.Bundle_source). Reading is wrapped once at this
   boundary, the uds.ml rule; parsing fails closed in the core. *)

type error =
  | Io of Uds.error
  | Source of Tinysvid.Bundle_source.error
  | Too_large of int

let error_to_string e =
  match e with
  | Io ie -> "io:" ^ Uds.error_to_string ie
  | Source se -> "source:" ^ Tinysvid.Bundle_source.error_to_string se
  | Too_large n -> Printf.sprintf "too_large:%d" n

let chunk_size = 65536

(* A trust bundle is small; cap the read so a misconfigured path (a
   device, a pipe, a huge file) fails closed instead of exhausting
   memory before parsing rejects the content. *)
let max_bundle_bytes = 1_048_576

let read_all fd =
  let buf = Buffer.create chunk_size in
  let bytes = Bytes.create chunk_size in
  let rec go () =
    Result.bind
      (Uds.wrap "read" (fun () -> Unix.read fd bytes 0 chunk_size)
      |> Result.map_error (fun e -> Io e))
      (fun n ->
        match () with
        | () when n = 0 -> Ok (Buffer.contents buf)
        | () when Buffer.length buf + n > max_bundle_bytes ->
            Error (Too_large (Buffer.length buf + n))
        | () ->
            Buffer.add_subbytes buf bytes 0 n;
            go ())
  in
  go ()

let load_roots ~path =
  Result.bind
    (Uds.wrap "open" (fun () -> Unix.openfile path [ Unix.O_RDONLY ] 0)
    |> Result.map_error (fun e -> Io e))
    (fun fd ->
      let read = read_all fd in
      Uds.close_fd fd;
      Result.bind read (fun s ->
          Tinysvid.Bundle_source.roots_of_der_concat s
          |> Result.map_error (fun e -> Source e)))

(* Load and stamp at the engine's current epoch: the file source is the
   disconnected node's Sync, routed through Bundle.refresh exactly like
   a wire response. *)
let refresh ~path st =
  load_roots ~path
  |> Result.map (fun roots -> Tinysvid.Rotation.refresh st ~roots)
