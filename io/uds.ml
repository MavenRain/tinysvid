(* M21: Unix-domain-socket transport over the unix library, nothing else.

   Every Unix call is wrapped at this boundary: a raise becomes an error
   value, so no caller sees an exception. The connection and listener
   types are abstract constructors; a file descriptor never escapes on
   its own. *)

type error =
  | Path_too_long of int
  | Sys of { call : string; err : Unix.error }
  | Eof

let error_to_string e =
  match e with
  | Path_too_long n -> Printf.sprintf "path_too_long:%d" n
  | Sys { call; err } -> Printf.sprintf "sys:%s:%s" call (Unix.error_message err)
  | Eof -> "eof"

type conn = Conn of Unix.file_descr
type listener = Listener of Unix.file_descr

(* The smallest sun_path bound among supported targets (macOS: 104 bytes
   including the terminator). Checked here so bind and connect never see
   a path the kernel would truncate. *)
let max_path_length = 103

(* The one exception boundary in the library: exactly one raising Unix
   call per use, a named constructor, an error value out. *)
let wrap call f =
  try Ok (f ()) with Unix.Unix_error (err, _, _) -> Error (Sys { call; err })

let close_fd fd = wrap "close" (fun () -> Unix.close fd) |> ignore
let close (Conn fd) = close_fd fd
let close_listener (Listener fd) = close_fd fd

(* A write to a peer that already closed raises SIGPIPE, which kills the
   process before the EPIPE error value can exist. A daemon opts in once
   at startup; after this, such a write returns Error (Sys EPIPE). *)
let ignore_sigpipe () = Sys.set_signal Sys.sigpipe Sys.Signal_ignore

let checked_path path k =
  match () with
  | () when String.length path > max_path_length ->
      Error (Path_too_long (String.length path))
  | () -> k ()

let with_new_socket k =
  Result.bind
    (wrap "socket" (fun () -> Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0))
    (fun fd -> k fd |> Result.map_error (fun e -> close_fd fd; e))

let connect ~path =
  checked_path path (fun () ->
      with_new_socket (fun fd ->
          wrap "connect" (fun () -> Unix.connect fd (Unix.ADDR_UNIX path))
          |> Result.map (fun () -> Conn fd)))

let listen ~path ~backlog =
  checked_path path (fun () ->
      with_new_socket (fun fd ->
          Result.bind
            (wrap "bind" (fun () -> Unix.bind fd (Unix.ADDR_UNIX path)))
            (fun () ->
              wrap "listen" (fun () -> Unix.listen fd backlog)
              |> Result.map (fun () -> Listener fd))))

let accept (Listener fd) =
  wrap "accept" (fun () -> Unix.accept fd)
  |> Result.map (fun (conn_fd, _) -> Conn conn_fd)

(* An in-process connected pair: the loopback transport for tests and
   for wiring a client to a local source without a filesystem path. *)
let pair () =
  wrap "socketpair" (fun () -> Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0)
  |> Result.map (fun (a, b) -> (Conn a, Conn b))

(* Close only our sending side: the peer then reads Eof while its own
   writes toward us still succeed. *)
let shutdown_send (Conn fd) =
  wrap "shutdown" (fun () -> Unix.shutdown fd Unix.SHUTDOWN_SEND)

let read_some (Conn fd) ~max =
  match () with
  | () when max <= 0 -> Ok ""
  | () ->
      let buf = Bytes.create max in
      Result.bind
        (wrap "read" (fun () -> Unix.read fd buf 0 max))
        (fun n ->
          match () with
          | () when n = 0 -> Error Eof
          (* Unix.read returns n in [0, max]; the Seq pipeline keeps the
             chunk construction total whatever n is. *)
          | () -> Ok (Bytes.to_seq buf |> Seq.take (Stdlib.min n max) |> String.of_seq))

(* read_some never returns an empty chunk for a positive max (a zero
   read is Eof), so the recursion strictly shrinks or errors. *)
let read_exactly conn ~len =
  let rec go acc remaining =
    match () with
    | () when remaining <= 0 -> Ok acc
    | () ->
        Result.bind (read_some conn ~max:remaining) (fun chunk ->
            go (acc ^ chunk) (remaining - String.length chunk))
  in
  go "" len

let write_all (Conn fd) data =
  let buf = Bytes.of_string data in
  let total = Bytes.length buf in
  let rec go off =
    match () with
    | () when off >= total -> Ok ()
    | () ->
        Result.bind
          (wrap "write" (fun () -> Unix.write fd buf off (total - off)))
          (fun n ->
            match () with
            | () when n <= 0 -> Error Eof
            | () -> go (off + n))
  in
  go 0
