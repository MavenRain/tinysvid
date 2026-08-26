open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- fake backend --------------------------------------------------- *)

(* Deterministic stand-in for M13: a signature is valid exactly when it
   is the MD5 of an algorithm tag, the signer's SPKI, and the message.
   The fixture builder below signs with the same formula. *)
module Fake : Sig_backend.S = struct
  let tag a =
    match a with
    | Sig_backend.Ed25519 -> "ed"
    | Sig_backend.Ecdsa_p256_sha256 -> "p2"

  let verify ~alg ~spki ~message ~signature =
    String.equal signature (Digest.string (tag alg ^ spki ^ message))
end

module C = Chain.Make (Fake)

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

let uri_san_name u = tlv "\x86" u

let san_ext uris =
  seq [ oid "\x55\x1d\x11"; octets (seq (List.map uri_san_name uris)) ]

let ku_ext bits = seq [ oid "\x55\x1d\x0f"; octets (tlv "\x03" bits) ]

let bc_ext ca =
  seq
    [
      oid "\x55\x1d\x13";
      octets (seq (if ca then [ tlv "\x01" "\xff" ] else []));
    ]

(* --- certificate fixtures ------------------------------------------- *)

let alg_ed = seq [ oid "\x2b\x65\x70" ]

let alg_unknown = seq [ oid "\x2a\x03" ]

let name s = seq [ tlv "\x0c" s ]

let spki key = seq [ alg_ed; tlv "\x03" ("\x00" ^ key) ]

let good_validity = seq [ utc "250101000000Z"; utc "260101000000Z" ]

let old_validity = seq [ utc "200101000000Z"; utc "210101000000Z" ]

let now = 1750000000L

let tbs ~issuer ~subject ~key ~validity ~exts =
  seq
    [
      tlv "\xa0" (tlv "\x02" "\x02");
      tlv "\x02" "\x01";
      alg_ed;
      name issuer;
      validity;
      name subject;
      spki key;
      tlv "\xa3" (seq exts);
    ]

let sign ~signer_key body = Digest.string ("ed" ^ spki signer_key ^ body)

let signed ?(alg = alg_ed) ~signer_key tbs_der =
  seq [ tbs_der; alg; tlv "\x03" ("\x00" ^ sign ~signer_key tbs_der) ]

let bad_signed tbs_der = seq [ tbs_der; alg_ed; tlv "\x03" "\x00wrong" ]

let ca_exts = [ bc_ext true; ku_ext "\x02\x04" ]

let wl = "spiffe://example.org/wl"

let leaf_exts = [ san_ext [ wl ]; ku_ext "\x07\x80"; bc_ext false ]

let ca_tbs ~issuer ~subject ~key ~validity =
  tbs ~issuer ~subject ~key ~validity ~exts:ca_exts

let root_der =
  signed ~signer_key:"K_ROOT"
    (ca_tbs ~issuer:"root" ~subject:"root" ~key:"K_ROOT"
       ~validity:good_validity)

let stranger_root_der =
  signed ~signer_key:"K_ELSE"
    (ca_tbs ~issuer:"elsewhere" ~subject:"elsewhere" ~key:"K_ELSE"
       ~validity:good_validity)

let ca1_der =
  signed ~signer_key:"K_ROOT"
    (ca_tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1" ~validity:good_validity)

let leaf_tbs ~issuer ~validity ~exts =
  tbs ~issuer ~subject:"leaf" ~key:"K_LEAF" ~validity ~exts

let leaf_der =
  signed ~signer_key:"K_CA1"
    (leaf_tbs ~issuer:"ca1" ~validity:good_validity ~exts:leaf_exts)

let leaf_direct_der =
  signed ~signer_key:"K_ROOT"
    (leaf_tbs ~issuer:"root" ~validity:good_validity ~exts:leaf_exts)

(* --- harness -------------------------------------------------------- *)

let fresh_at td = Bundle.refresh ~td ~epoch:(Bundle.Epoch 5)

let run td =
  let roots = Bundle.Roots [ root_der ] in
  let fresh = Bundle.Ufresh (fresh_at td ~roots) in
  let grace = Bundle.Ugrace (Bundle.to_grace (fresh_at td ~roots)) in
  let v ?(bundle = fresh) ?(now_epoch = Bundle.Epoch 5) chain =
    C.validate ~now ~now_epoch ~bundle ~chain
  in
  let ok_id r =
    Result.fold
      ~ok:(fun id -> String.equal (Spiffe_id.to_string id) wl)
      ~error:(fun e ->
        ignore e;
        false)
      r
  in
  let errs r expect =
    Result.fold
      ~ok:(fun id ->
        ignore id;
        false)
      ~error:(fun e -> String.equal (C.error_to_string e) expect)
      r
  in
  List.fold_left ( + ) 0
    [
      check "leaf + intermediate to bundle root validates"
        (ok_id (v [ leaf_der; ca1_der ]));
      check "leaf signed directly by a bundle root validates"
        (ok_id (v [ leaf_direct_der ]));
      check "three-deep path validates"
        (let ca2 =
           signed ~signer_key:"K_CA1"
             (ca_tbs ~issuer:"ca1" ~subject:"ca2" ~key:"K_CA2"
                ~validity:good_validity)
         in
         let leaf3 =
           signed ~signer_key:"K_CA2"
             (leaf_tbs ~issuer:"ca2" ~validity:good_validity ~exts:leaf_exts)
         in
         ok_id (v [ leaf3; ca2; ca1_der ]));
      check "fresh bundle one epoch behind is rejected"
        (errs (v ~now_epoch:(Bundle.Epoch 6) [ leaf_der; ca1_der ])
           "epoch_gap:1");
      check "grace bundle one epoch behind validates"
        (ok_id (v ~bundle:grace ~now_epoch:(Bundle.Epoch 6)
              [ leaf_der; ca1_der ]));
      check "grace bundle two epochs behind is rejected"
        (errs
           (v ~bundle:grace ~now_epoch:(Bundle.Epoch 7) [ leaf_der; ca1_der ])
           "epoch_gap:2");
      check "bundle epoch ahead of the node is rejected"
        (errs (v ~now_epoch:(Bundle.Epoch 4) [ leaf_der; ca1_der ])
           "epoch_gap:-1");
      check "empty chain is rejected" (errs (v []) "empty_chain");
      check "malformed intermediate names its position"
        (errs (v [ leaf_direct_der; "\x30" ]) "cert:1:der:truncated_length");
      check "tampered leaf signature is rejected"
        (errs
           (v
              [
                bad_signed
                  (leaf_tbs ~issuer:"ca1" ~validity:good_validity
                     ~exts:leaf_exts);
                ca1_der;
              ])
           "bad_signature:0");
      check "unsupported outer algorithm is rejected"
        (errs
           (v
              [
                signed ~alg:alg_unknown ~signer_key:"K_CA1"
                  (leaf_tbs ~issuer:"ca1" ~validity:good_validity
                     ~exts:leaf_exts);
                ca1_der;
              ])
           "unsupported_algorithm:0");
      check "issuer name not matching parent subject is rejected"
        (errs
           (v
              [
                signed ~signer_key:"K_CA1"
                  (leaf_tbs ~issuer:"other" ~validity:good_validity
                     ~exts:leaf_exts);
                ca1_der;
              ])
           "link_issuer:0");
      check "parent without cA is rejected"
        (let not_ca =
           signed ~signer_key:"K_ROOT"
             (tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1"
                ~validity:good_validity
                ~exts:[ bc_ext false; ku_ext "\x02\x04" ])
         in
         errs (v [ leaf_der; not_ca ]) "link_not_ca:0");
      check "parent without keyCertSign is rejected"
        (let no_sign =
           signed ~signer_key:"K_ROOT"
             (tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1"
                ~validity:good_validity
                ~exts:[ bc_ext true; ku_ext "\x07\x80" ])
         in
         errs (v [ leaf_der; no_sign ]) "link_missing_cert_sign:0");
      check "expired parent is rejected"
        (let stale =
           signed ~signer_key:"K_ROOT"
             (ca_tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1"
                ~validity:old_validity)
         in
         errs (v [ leaf_der; stale ]) "link_window:0");
      check "expired leaf is rejected"
        (errs
           (v
              [
                signed ~signer_key:"K_ROOT"
                  (leaf_tbs ~issuer:"root" ~validity:old_validity
                     ~exts:leaf_exts);
              ])
           "leaf:expired");
      check "foreign trust domain is rejected"
        (errs
           (v
              [
                signed ~signer_key:"K_ROOT"
                  (leaf_tbs ~issuer:"root" ~validity:good_validity
                     ~exts:
                       [
                         san_ext [ "spiffe://other.org/wl" ];
                         ku_ext "\x07\x80";
                         bc_ext false;
                       ]);
              ])
           "leaf:foreign_trust_domain");
      check "no bundle root anchors the chain"
        (let stranger =
           Bundle.Ufresh (fresh_at td ~roots:(Bundle.Roots [ stranger_root_der ]))
         in
         errs (v ~bundle:stranger [ leaf_direct_der ]) "no_matching_root");
      check "tampered intermediate signature loses its anchor"
        (let ca1_bad =
           bad_signed
             (ca_tbs ~issuer:"root" ~subject:"ca1" ~key:"K_CA1"
                ~validity:good_validity)
         in
         errs (v [ leaf_der; ca1_bad ]) "no_matching_root");
      check "unparseable bundle root is not a candidate"
        (let junk =
           Bundle.Ufresh (fresh_at td ~roots:(Bundle.Roots [ "not-der" ]))
         in
         errs (v ~bundle:junk [ leaf_direct_der ]) "no_matching_root");
      check "parse_full keeps the raw tbs, names, and signature"
        (X509.parse_full leaf_der
        |> Result.fold
             ~error:(fun e ->
               ignore e;
               false)
             ~ok:(fun (f : X509.full) ->
               String.equal f.tbs_raw
                 (leaf_tbs ~issuer:"ca1" ~validity:good_validity
                    ~exts:leaf_exts)
               && String.equal f.issuer (name "ca1")
               && String.equal f.subject (name "leaf")
               && String.equal f.spki (spki "K_LEAF")
               && String.equal f.sig_alg_oid "\x2b\x65\x70"
               && String.equal f.sig_value
                    (sign ~signer_key:"K_CA1"
                       (leaf_tbs ~issuer:"ca1" ~validity:good_validity
                          ~exts:leaf_exts))));
    ]

let () =
  let failures =
    Trust_domain.parse "example.org"
    |> Result.fold
         ~error:(fun te ->
           ignore te;
           1)
         ~ok:run
  in
  exit (min failures 1)
