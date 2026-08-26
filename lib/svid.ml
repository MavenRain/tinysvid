(* X.509-SVID leaf validation, per SVID spec sections 4.1-4.3, over an
   abstract certificate record. DER parsing and signature checking arrive
   in later milestones; this core is what the ZxCaml artifact mirrors.
   validate_leaf takes Bundle.usable, not Bundle.t: a Void bundle cannot
   reach validation at the type level. *)

type key_usage =
  | Digital_signature
  | Key_cert_sign
  | Crl_sign
  | Key_agreement
  | Other_usage

type cert = {
  san_uris : string list;
  not_before : int64;
  not_after : int64;
  is_ca : bool;
  key_usage : key_usage list;
}

type error =
  | No_uri_san
  | Multiple_uri_san
  | Leaf_is_ca
  | Missing_digital_signature
  | Signing_usage_on_leaf
  | Not_yet_valid
  | Expired
  | Bad_id of Spiffe_id.error
  | Foreign_trust_domain

let check_window ~now c =
  match () with
  | () when Int64.compare now c.not_before < 0 -> Error Not_yet_valid
  | () when Int64.compare now c.not_after >= 0 -> Error Expired
  | () -> Ok ()

let check_leaf_flags c =
  match () with
  | () when c.is_ca -> Error Leaf_is_ca
  | () when not (List.mem Digital_signature c.key_usage) ->
      Error Missing_digital_signature
  | () when List.mem Key_cert_sign c.key_usage || List.mem Crl_sign c.key_usage
    -> Error Signing_usage_on_leaf
  | () -> Ok ()

let check_uri_san c =
  match c.san_uris with
  | [] -> Error No_uri_san
  | [ u ] -> Ok u
  | _ :: _ :: _ -> Error Multiple_uri_san

let validate_leaf ~now ~(bundle : Bundle.usable) (c : cert) :
    (Spiffe_id.t, error) result =
  Result.bind (check_window ~now c) (fun () ->
      Result.bind (check_leaf_flags c) (fun () ->
          Result.bind (check_uri_san c) (fun u ->
              Result.bind
                (Spiffe_id.parse u |> Result.map_error (fun e -> Bad_id e))
                (fun id ->
                  if
                    Trust_domain.equal
                      (Spiffe_id.trust_domain id)
                      (Bundle.usable_td bundle)
                  then Ok id
                  else Error Foreign_trust_domain))))
