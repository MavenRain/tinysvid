(* Chain validation (M14): build the path from a leaf X.509-SVID up
   through intermediates to a root held in the trust bundle, verifying
   every signature through the plugged backend (M13), then apply the
   epoch-gap rule the model certifies: A4, a Fresh bundle knows gap 0;
   A5, a Grace bundle knows gap at most 1. The static side of that rule
   is the Bundle phantom types; the dynamic check here catches a caller
   that held a bundle across epochs without routing Bundle.degrade.
   validate takes Bundle.usable, so a Void bundle cannot reach it. *)

module Make (B : Sig_backend.S) = struct
  (* Positions count from the leaf: Cert and the Link_* errors carry the
     chain index of the child whose parse or parent link failed. An
     unsupported algorithm or bad signature on the topmost certificate
     surfaces as No_matching_root, since no root can verify it. *)
  type error =
    | Empty_chain
    | Cert of int * X509.error
    | Leaf of Svid.error
    | Link_issuer of int
    | Link_not_ca of int
    | Link_missing_cert_sign of int
    | Link_window of int
    | Unsupported_algorithm of int
    | Bad_signature of int
    | No_matching_root
    | Epoch_gap of int

  let error_to_string e =
    match e with
    | Empty_chain -> "empty_chain"
    | Cert (n, x) -> Printf.sprintf "cert:%d:%s" n (X509.error_to_string x)
    | Leaf le -> "leaf:" ^ Svid.error_to_string le
    | Link_issuer n -> Printf.sprintf "link_issuer:%d" n
    | Link_not_ca n -> Printf.sprintf "link_not_ca:%d" n
    | Link_missing_cert_sign n -> Printf.sprintf "link_missing_cert_sign:%d" n
    | Link_window n -> Printf.sprintf "link_window:%d" n
    | Unsupported_algorithm n -> Printf.sprintf "unsupported_algorithm:%d" n
    | Bad_signature n -> Printf.sprintf "bad_signature:%d" n
    | No_matching_root -> "no_matching_root"
    | Epoch_gap n -> Printf.sprintf "epoch_gap:%d" n

  (* A4/A5 at the validation boundary. A negative gap means the bundle
     claims an epoch the node has not reached: rejected the same way. *)
  let epoch_rule ~now_epoch (bundle : Bundle.usable) =
    let gap =
      Bundle.epoch_gap ~now:now_epoch ~held:(Bundle.usable_epoch bundle)
    in
    let limit = match bundle with Bundle.Ufresh _ -> 0 | Bundle.Ugrace _ -> 1 in
    match () with
    | () when gap >= 0 && gap <= limit -> Ok ()
    | () -> Error (Epoch_gap gap)

  let parse_chain ders =
    List.fold_left
      (fun acc der ->
        Result.bind acc (fun (pos, parsed) ->
            X509.parse_full der
            |> Result.map_error (fun e -> Cert (pos, e))
            |> Result.map (fun f -> (pos + 1, f :: parsed))))
      (Ok (0, []))
      ders
    |> Result.map (fun (_count, parsed) -> List.rev parsed)

  let verify_signed ~pos ~signer_spki (child : X509.full) =
    Sig_backend.algorithm_of_oid child.sig_alg_oid
    |> Option.fold
         ~none:(Error (Unsupported_algorithm pos))
         ~some:(fun alg ->
           match () with
           | ()
             when B.verify ~alg ~spki:signer_spki ~message:child.tbs_raw
                    ~signature:child.sig_value ->
               Ok ()
           | () -> Error (Bad_signature pos))

  (* One child-to-parent link: parent is a CA with keyCertSign, valid at
     now, named as the child's issuer, and its key verifies the child. *)
  let link ~now ~pos (child : X509.full) (parent : X509.full) =
    match () with
    | () when not (String.equal child.issuer parent.subject) ->
        Error (Link_issuer pos)
    | () when not parent.cert.Svid.is_ca -> Error (Link_not_ca pos)
    | () when not (List.mem Svid.Key_cert_sign parent.cert.Svid.key_usage) ->
        Error (Link_missing_cert_sign pos)
    | () when Result.is_error (Svid.check_window ~now parent.cert) ->
        Error (Link_window pos)
    | () -> verify_signed ~pos ~signer_spki:parent.spki child

  let rec links ~now pos certs =
    match certs with
    | child :: parent :: rest ->
        Result.bind (link ~now ~pos child parent) (fun () ->
            links ~now (pos + 1) (parent :: rest))
    | [ topmost ] ->
        ignore topmost;
        Ok ()
    | [] -> Ok ()

  (* A bundle root anchors the chain when it parses as a certificate,
     is a valid-at-now CA with keyCertSign named as the topmost cert's
     issuer, and its key verifies that cert. Roots that fail to parse
     are not candidates; root self-signatures are not checked. *)
  let root_anchors ~now ~pos (topmost : X509.full) root_der =
    X509.parse_full root_der
    |> Result.fold
         ~error:(fun parse_failure ->
           ignore parse_failure;
           false)
         ~ok:(fun (r : X509.full) ->
           String.equal topmost.issuer r.subject
           && r.cert.Svid.is_ca
           && List.mem Svid.Key_cert_sign r.cert.Svid.key_usage
           && Result.is_ok (Svid.check_window ~now r.cert)
           && Result.is_ok (verify_signed ~pos ~signer_spki:r.spki topmost))

  (* chain is leaf-first raw DER certificates. *)
  let validate ~now ~now_epoch ~(bundle : Bundle.usable) ~chain :
      (Spiffe_id.t, error) result =
    Result.bind (epoch_rule ~now_epoch bundle) (fun () ->
        Result.bind (parse_chain chain) (fun certs ->
            match certs with
            | [] -> Error Empty_chain
            | leaf :: rest ->
                Result.bind
                  (Svid.validate_leaf ~now ~bundle leaf.X509.cert
                  |> Result.map_error (fun e -> Leaf e))
                  (fun id ->
                    Result.bind (links ~now 0 certs) (fun () ->
                        let topmost =
                          List.fold_left (fun acc c -> ignore acc; c) leaf rest
                        in
                        let (Bundle.Roots roots) = Bundle.usable_roots bundle in
                        let top_pos = List.length rest in
                        match () with
                        | ()
                          when List.exists
                                 (root_anchors ~now ~pos:top_pos topmost)
                                 roots ->
                            Ok id
                        | () -> Error No_matching_root))))
end
