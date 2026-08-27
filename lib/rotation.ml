(* M26: the rotation loop engine, the code image of the (auth, bundle)
   projection of the model's Coupled frame. The engine epoch is the
   node's rotation clock: one rotation period is an upper bound for
   bundle TTL (the Coupled assumption), so a local timer tracks the
   authority epoch with no connectivity. Every bundle change routes
   through Bundle.refresh and Bundle.degrade; there is no parallel
   state machine.

   rotate      = model Rotate: the rotation-period timer fires; the
                 epoch advances and a held bundle degrades one step.
   tick        = model Tick: the TTL timer fires; a held bundle
                 degrades one step.
   refresh     = model Sync: fresh roots arrive (a Workload API watch
                 response, or the M25 file source at boot) and are
                 stamped with the current epoch, so A4 (fresh knows
                 gap 0) holds by construction.
   accept_leaf = the A7 image: leaf acceptance is enabled only through
                 a usable bundle.

   test/test_correspondence.ml holds rotate, tick, and refresh to the
   model transitions over every reachable Coupled world. *)

type t = { td : Trust_domain.t; epoch : Bundle.epoch; bundle : Bundle.t }

(* A node boots with no bundle; the first refresh comes from the wire
   or from the file source. *)
let create ~td ~epoch = { td; epoch; bundle = Bundle.Void }

let td t = t.td

let epoch t = t.epoch

let bundle t = t.bundle

let usable t = Bundle.usable t.bundle

let rotate t =
  {
    t with
    epoch = Bundle.Epoch (Bundle.epoch_value t.epoch + 1);
    bundle = Bundle.degrade t.bundle;
  }

let tick t = { t with bundle = Bundle.degrade t.bundle }

let refresh t ~roots =
  {
    t with
    bundle = Bundle.of_fresh (Bundle.refresh ~td:t.td ~epoch:t.epoch ~roots);
  }

type error =
  | No_svid_for_domain
  | Bad_svid_id of { index : int; err : Spiffe_id.error }
  | Bad_bundle of Bundle_source.error

let error_to_string e =
  match e with
  | No_svid_for_domain -> "no_svid_for_domain"
  | Bad_svid_id { index; err } ->
      Printf.sprintf "bad_svid_id:%d:%s" index (Spiffe_id.error_to_string err)
  | Bad_bundle be -> "bad_bundle:" ^ Bundle_source.error_to_string be

(* The svid entry whose identity lives in this engine's trust domain
   carries the bundle for that domain. A malformed spiffe_id anywhere
   in the response is a server fault: reject the whole response, fail
   closed, rather than guess which entry was meant. *)
let refresh_of_response t (r : Pb.x509_svid_response) =
  let entries =
    List.mapi (fun index sv -> (index, sv)) r.Pb.svids
    |> List.fold_left
         (fun acc (index, (sv : Pb.x509_svid)) ->
           Result.bind acc (fun tail ->
               Spiffe_id.parse sv.Pb.spiffe_id
               |> Result.map_error (fun err -> Bad_svid_id { index; err })
               |> Result.map (fun id -> (id, sv) :: tail)))
         (Ok [])
    |> Result.map List.rev
  in
  Result.bind entries (fun entries ->
      Result.bind
        (List.find_opt
           (fun ((id : Spiffe_id.t), _) ->
             Trust_domain.equal (Spiffe_id.trust_domain id) t.td)
           entries
        |> Option.to_result ~none:No_svid_for_domain)
        (fun (_, (sv : Pb.x509_svid)) ->
          Bundle_source.roots_of_der_concat sv.Pb.bundle
          |> Result.map_error (fun be -> Bad_bundle be)
          |> Result.map (fun roots -> refresh t ~roots)))

type accept_error = No_usable_bundle | Leaf of Svid.error

let accept_error_to_string e =
  match e with
  | No_usable_bundle -> "no_usable_bundle"
  | Leaf le -> "leaf:" ^ Svid.error_to_string le

(* Renew is enabled only with a usable bundle (A7): a Void engine
   cannot reach Svid.validate_leaf at the type level. *)
let accept_leaf t ~now cert =
  Result.bind
    (usable t |> Option.to_result ~none:No_usable_bundle)
    (fun u ->
      Svid.validate_leaf ~now ~bundle:u cert
      |> Result.map_error (fun le -> Leaf le))
