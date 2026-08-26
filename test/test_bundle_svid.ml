open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let freshness_label u =
  match u with Bundle.Ufresh _ -> "fresh" | Bundle.Ugrace _ -> "grace"

let observe b =
  Bundle.usable b
  |> Option.fold ~none:"void" ~some:(fun u ->
         freshness_label u ^ ":"
         ^ string_of_int (Bundle.epoch_value (Bundle.usable_epoch u)))

let good_cert id =
  {
    Svid.san_uris = [ id ];
    not_before = 100L;
    not_after = 200L;
    is_ca = false;
    key_usage = [ Svid.Digital_signature ];
  }

let leaf_ok ~now ~bundle c =
  Svid.validate_leaf ~now ~bundle c
  |> Result.fold ~ok:(fun _ -> true) ~error:(fun _ -> false)

let leaf_err ~now ~bundle c e =
  Svid.validate_leaf ~now ~bundle c
  |> Result.fold ~ok:(fun _ -> false) ~error:(fun got -> got = e)

let () =
  Trust_domain.parse "example.org"
  |> Result.fold
       ~error:(fun _ ->
         Printf.printf "FAIL trust-domain fixture\n";
         exit 1)
       ~ok:(fun td ->
         let b0 =
           Bundle.of_fresh
             (Bundle.refresh ~td ~epoch:(Bundle.Epoch 0)
                ~roots:(Bundle.Roots [ "root-der" ]))
         in
         let b1 = Bundle.degrade b0 in
         let b2 = Bundle.degrade b1 in
         let b3 = Bundle.degrade b2 in
         let with_usable b k =
           Bundle.usable b |> Option.fold ~none:false ~some:k
         in
         let failures =
           List.fold_left ( + ) 0
             [
               check "refresh yields fresh:0" (String.equal (observe b0) "fresh:0");
               check "one degrade yields grace:0"
                 (String.equal (observe b1) "grace:0");
               check "two degrades yield void" (String.equal (observe b2) "void");
               check "degrade on void stays void"
                 (String.equal (observe b3) "void");
               check "valid leaf accepted"
                 (with_usable b0 (fun u ->
                      leaf_ok ~now:150L ~bundle:u
                        (good_cert "spiffe://example.org/workload/db")));
               check "grace bundle still validates"
                 (with_usable b1 (fun u ->
                      leaf_ok ~now:150L ~bundle:u
                        (good_cert "spiffe://example.org/workload/db")));
               check "expired leaf rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:250L ~bundle:u
                        (good_cert "spiffe://example.org/w")
                        Svid.Expired));
               check "not-yet-valid leaf rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:50L ~bundle:u
                        (good_cert "spiffe://example.org/w")
                        Svid.Not_yet_valid));
               check "ca leaf rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        { (good_cert "spiffe://example.org/w") with is_ca = true }
                        Svid.Leaf_is_ca));
               check "cert-sign usage rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        {
                          (good_cert "spiffe://example.org/w") with
                          key_usage =
                            [ Svid.Digital_signature; Svid.Key_cert_sign ];
                        }
                        Svid.Signing_usage_on_leaf));
               check "no digital-signature usage rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        {
                          (good_cert "spiffe://example.org/w") with
                          key_usage = [ Svid.Key_agreement ];
                        }
                        Svid.Missing_digital_signature));
               check "zero san rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        { (good_cert "spiffe://example.org/w") with san_uris = [] }
                        Svid.No_uri_san));
               check "two sans rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        {
                          (good_cert "spiffe://example.org/w") with
                          san_uris =
                            [ "spiffe://example.org/a"; "spiffe://example.org/b" ];
                        }
                        Svid.Multiple_uri_san));
               check "foreign trust domain rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        (good_cert "spiffe://other.org/w")
                        Svid.Foreign_trust_domain));
               check "malformed san id rejected"
                 (with_usable b0 (fun u ->
                      leaf_err ~now:150L ~bundle:u
                        (good_cert "spiffe://example.org/../x")
                        (Svid.Bad_id (Spiffe_id.Dot_segment ".."))));
             ]
         in
         exit (Int.min failures 1))
