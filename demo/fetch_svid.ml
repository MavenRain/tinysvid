(* M28: the demo client for the end-to-end run. It connects to a
   Workload API socket, runs one FetchX509SVID call through the typed
   engine, and prints what the toolkit certifies: the parsed SPIFFE
   ID, the certificate and key byte counts, and the number of roots
   the bundle parser accepts. The socket path comes from the first
   argument or from SPIFFE_ENDPOINT_SOCKET, with or without the
   unix:// scheme. Exit code 0 means every check passed; a malformed
   SPIFFE ID or bundle is a failure, not a warning. *)

open Tinysvid
open Tinysvid_io

let drop_prefix n s = String.to_seq s |> Seq.drop n |> String.of_seq

let scheme = "unix://"

let path_of_endpoint s =
  match () with
  | () when String.starts_with ~prefix:scheme s ->
      drop_prefix (String.length scheme) s
  | () -> s

let socket_path () =
  match Array.to_list Sys.argv with
  | [ _; p ] -> Some (path_of_endpoint p)
  | [ _ ] ->
      Sys.getenv_opt "SPIFFE_ENDPOINT_SOCKET" |> Option.map path_of_endpoint
  | _ -> None

let svid_report (s : Pb.x509_svid) =
  Result.bind
    (Spiffe_id.parse s.Pb.spiffe_id
    |> Result.map_error (fun e -> "spiffe_id:" ^ Spiffe_id.error_to_string e))
    (fun id ->
      Bundle_source.roots_of_der_concat s.Pb.bundle
      |> Result.map_error (fun e -> "bundle:" ^ Bundle_source.error_to_string e)
      |> Result.map (fun (Bundle.Roots raws) ->
             Printf.printf "svid: %s\n  cert: %d B  key: %d B  roots: %d\n"
               (Spiffe_id.to_string id)
               (String.length s.Pb.x509_svid)
               (String.length s.Pb.x509_svid_key)
               (List.length raws)))

let response_report (r : Pb.x509_svid_response) =
  match r.Pb.svids with
  | [] -> Error "no svids in response"
  | _ :: _ ->
      List.fold_left
        (fun acc s -> Result.bind acc (fun () -> svid_report s))
        (Ok ()) r.Pb.svids
      |> Result.map (fun () ->
             Printf.printf "federated bundles: %d\n"
               (List.length r.Pb.federated_bundles))

let () =
  Uds.ignore_sigpipe ();
  socket_path ()
  |> Option.to_result
       ~none:"usage: fetch_svid SOCKET_PATH (or set SPIFFE_ENDPOINT_SOCKET)"
  |> Fun.flip Result.bind (fun path ->
         Wl_io.fetch_path ~path ~authority:"localhost"
         |> Result.map_error Wl_io.error_to_string)
  |> Fun.flip Result.bind response_report
  |> Result.fold
       ~ok:(fun () -> exit 0)
       ~error:(fun msg ->
         Printf.eprintf "error: %s\n" msg;
         exit 1)
