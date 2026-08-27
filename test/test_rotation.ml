open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- tiny DER encoder for fixtures (as in test_x509) ---------------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

let byte n =
  String.to_seq byte_table |> Seq.drop n |> Seq.uncons
  |> Option.fold ~none:"POISON" ~some:(fun (c, _) -> String.make 1 c)

let len_bytes n =
  match () with
  | () when n < 0x80 -> byte n
  | () when n < 0x100 -> "\x81" ^ byte n
  | () when n < 0x10000 -> "\x82" ^ byte (n lsr 8) ^ byte (n land 0xff)
  | () -> "POISON"

let tlv tag body = tag ^ len_bytes (String.length body) ^ body

let seq parts = tlv "\x30" (String.concat "" parts)

let octets body = tlv "\x04" body

let oid body = tlv "\x06" body

let utc s = tlv "\x17" s

let ku_ext bits = seq [ oid "\x55\x1d\x0f"; octets (tlv "\x03" bits) ]

let bc_ext ca =
  seq
    [
      oid "\x55\x1d\x13";
      octets (seq (if ca then [ tlv "\x01" "\xff" ] else []));
    ]

let alg_ed = seq [ oid "\x2b\x65\x70" ]

let name s = seq [ tlv "\x0c" s ]

let spki key = seq [ alg_ed; tlv "\x03" ("\x00" ^ key) ]

let good_validity = seq [ utc "250101000000Z"; utc "260101000000Z" ]

let tbs ~issuer ~subject ~key =
  seq
    [
      tlv "\xa0" (tlv "\x02" "\x02");
      tlv "\x02" "\x01";
      alg_ed;
      name issuer;
      good_validity;
      name subject;
      spki key;
      tlv "\xa3" (seq [ bc_ext true; ku_ext "\x02\x04" ]);
    ]

let signed tbs_der = seq [ tbs_der; alg_ed; tlv "\x03" "\x00SIG" ]

let root_der = signed (tbs ~issuer:"root" ~subject:"root" ~key:"K_ROOT")

let other_der = signed (tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1")

(* --- harness -------------------------------------------------------- *)

let svid_entry id bundle =
  { Pb.spiffe_id = id; x509_svid = "CERT"; x509_svid_key = "KEY"; bundle }

let response svids = { Pb.svids; crl = []; federated_bundles = [] }

let leaf_cert =
  {
    Svid.san_uris = [ "spiffe://example.org/wl" ];
    not_before = 0L;
    not_after = 100L;
    is_ca = false;
    key_usage = [ Svid.Digital_signature ];
  }

let observe st =
  Rotation.usable st
  |> Option.fold ~none:"void" ~some:(fun u ->
         let tag =
           match u with
           | Bundle.Ufresh _ -> "fresh"
           | Bundle.Ugrace _ -> "grace"
         in
         let (Bundle.Roots roots) = Bundle.usable_roots u in
         Printf.sprintf "%s:%d:%d" tag
           (Bundle.epoch_value (Bundle.usable_epoch u))
           (List.length roots))

let engine_errors_as expected r =
  Result.fold r
    ~ok:(fun _ -> false)
    ~error:(fun e -> String.equal (Rotation.error_to_string e) expected)

let () =
  Trust_domain.parse "example.org"
  |> Result.fold
       ~error:(fun _ ->
         Printf.printf "FAIL trust-domain fixture\n";
         exit 1)
       ~ok:(fun td ->
         let e0 = Rotation.create ~td ~epoch:(Bundle.Epoch 0) in
         let fresh0 = Rotation.refresh e0 ~roots:(Bundle.Roots [ root_der ]) in
         let good =
           response
             [
               svid_entry "spiffe://other.test/w" other_der;
               svid_entry "spiffe://example.org/wl" (root_der ^ other_der);
             ]
         in
         let failures =
           List.fold_left ( + ) 0
             [
               check "a new engine holds no bundle"
                 (String.equal (observe e0) "void");
               check "refresh stamps the current epoch"
                 (String.equal (observe fresh0) "fresh:0:1");
               check "rotate advances the epoch and degrades one step"
                 (String.equal (observe (Rotation.rotate fresh0)) "grace:0:1"
                 && Bundle.epoch_value
                      (Rotation.epoch (Rotation.rotate fresh0))
                    = 1);
               check "two rotations empty the bundle"
                 (String.equal
                    (observe (Rotation.rotate (Rotation.rotate fresh0)))
                    "void");
               check "tick degrades and keeps the epoch"
                 (String.equal (observe (Rotation.tick fresh0)) "grace:0:1"
                 && Bundle.epoch_value (Rotation.epoch (Rotation.tick fresh0))
                    = 0);
               check "refresh after rotate closes the gap to zero"
                 (String.equal
                    (observe
                       (Rotation.refresh
                          (Rotation.rotate fresh0)
                          ~roots:(Bundle.Roots [ root_der ])))
                    "fresh:1:1");
               check "a response refreshes from the matching domain's entry"
                 (Result.fold
                    (Rotation.refresh_of_response
                       (Rotation.rotate fresh0)
                       good)
                    ~error:(fun _ -> false)
                    ~ok:(fun st -> String.equal (observe st) "fresh:1:2"));
               check "a malformed spiffe_id anywhere fails closed"
                 (engine_errors_as "bad_svid_id:0:bad_scheme"
                    (Rotation.refresh_of_response fresh0
                       (response [ svid_entry "not-a-uri" root_der ])));
               check "no entry for the engine's domain is a typed failure"
                 (engine_errors_as "no_svid_for_domain"
                    (Rotation.refresh_of_response fresh0
                       (response [ svid_entry "spiffe://other.test/w" root_der ])));
               check "bad bundle bytes in the matching entry fail closed"
                 (engine_errors_as "bad_bundle:empty_bundle"
                    (Rotation.refresh_of_response fresh0
                       (response [ svid_entry "spiffe://example.org/wl" "" ])));
               check "accept_leaf on a bare engine has no usable bundle"
                 (Result.fold
                    (Rotation.accept_leaf e0 ~now:50L leaf_cert)
                    ~ok:(fun _ -> false)
                    ~error:(fun e ->
                      String.equal
                        (Rotation.accept_error_to_string e)
                        "no_usable_bundle"));
               check "accept_leaf validates through a fresh bundle"
                 (Result.fold
                    (Rotation.accept_leaf fresh0 ~now:50L leaf_cert)
                    ~error:(fun _ -> false)
                    ~ok:(fun id ->
                      Trust_domain.equal (Spiffe_id.trust_domain id) td));
               check "accept_leaf still validates through a grace bundle"
                 (Result.fold
                    (Rotation.accept_leaf (Rotation.tick fresh0) ~now:50L
                       leaf_cert)
                    ~error:(fun _ -> false)
                    ~ok:(fun id ->
                      Trust_domain.equal (Spiffe_id.trust_domain id) td));
               check "accept_leaf surfaces leaf errors"
                 (Result.fold
                    (Rotation.accept_leaf fresh0 ~now:200L leaf_cert)
                    ~ok:(fun _ -> false)
                    ~error:(fun e ->
                      String.equal
                        (Rotation.accept_error_to_string e)
                        "leaf:expired"));
             ]
         in
         exit (min failures 1))