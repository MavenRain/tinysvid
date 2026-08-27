(* Trust-bundle source bytes: X.509 certificates in concatenated DER.
   The Workload API bundle field and the M25 file source share this
   format, so one parser serves both the connected and the disconnected
   path. Fail closed: every certificate must parse; one bad certificate
   rejects the whole bundle, because a silently dropped root would split
   trust between nodes that read the same bytes. *)

type error =
  | Empty_bundle
  | Bad_der of Der.error
  | Bad_certificate of { index : int; err : X509.error }

let error_to_string e =
  match e with
  | Empty_bundle -> "empty_bundle"
  | Bad_der de -> "bad_der:" ^ Der.error_to_string de
  | Bad_certificate { index; err } ->
      Printf.sprintf "bad_certificate:%d:%s" index (X509.error_to_string err)

(* Each top-level DER node must be a whole certificate; the node's raw
   octets become the root string chain validation re-parses. *)
let roots_of_der_concat s =
  Result.bind
    (Der.parse_all s |> Result.map_error (fun e -> Bad_der e))
    (fun nodes ->
      match nodes with
      | [] -> Error Empty_bundle
      | _ :: _ ->
          List.mapi (fun index node -> (index, node)) nodes
          |> List.fold_left
               (fun acc (index, node) ->
                 Result.bind acc (fun raws ->
                     X509.parse_full node.Der.raw
                     |> Result.map_error (fun err ->
                            Bad_certificate { index; err })
                     |> Result.map (fun _ -> node.Der.raw :: raws)))
               (Ok [])
          |> Result.map (fun raws -> Bundle.Roots (List.rev raws)))
