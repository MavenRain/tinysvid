open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* --- tiny DER encoder for fixtures --------------------------------- *)

(* Total int-to-byte: a 256-byte table looked up through Seq, so no
   partial Char.chr and no raw indexing. Out-of-range collapses to a
   poison marker that makes the fixture fail loudly. *)
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

let gen_time s = tlv "\x18" s

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

let cert ~validity ~exts =
  let tbs =
    seq
      [
        tlv "\xa0" (tlv "\x02" "\x02");
        tlv "\x02" "\x01";
        seq [];
        seq [];
        validity;
        seq [];
        seq [];
        tlv "\xa3" (seq exts);
      ]
  in
  seq [ tbs; seq []; tlv "\x03" "\x00" ]

let wl = "spiffe://example.org/wl"

let good_validity = seq [ utc "250101000000Z"; utc "260101000000Z" ]

let good_cert =
  cert ~validity:good_validity
    ~exts:[ san_ext [ wl ]; ku_ext "\x07\x80"; bc_ext false ]

let parses s f = X509.parse s |> Result.fold ~ok:f ~error:(fun _ -> false)

let rejects_as s name =
  X509.parse s
  |> Result.fold
       ~ok:(fun _ -> false)
       ~error:(fun e -> String.equal (X509.error_to_string e) name)

let usage_string c =
  List.map
    (fun u ->
      match u with
      | Svid.Digital_signature -> "ds"
      | Svid.Key_cert_sign -> "kcs"
      | Svid.Crl_sign -> "crl"
      | Svid.Key_agreement -> "ka"
      | Svid.Other_usage -> "other")
    c.Svid.key_usage
  |> String.concat ","

let () =
  let failures =
    List.fold_left ( + ) 0
      [
        check "leaf extracts san, window, flags"
          (parses good_cert (fun c ->
               List.equal String.equal c.Svid.san_uris [ wl ]
               && Int64.equal c.Svid.not_before 1735689600L
               && Int64.equal c.Svid.not_after 1767225600L
               && (not c.Svid.is_ca)
               && String.equal (usage_string c) "ds"));
        check "generalized-time validity"
          (parses
             (cert
                ~validity:
                  (seq
                     [ gen_time "20250101000000Z"; gen_time "20260101000000Z" ])
                ~exts:[ san_ext [ wl ] ])
             (fun c ->
               Int64.equal c.Svid.not_before 1735689600L
               && Int64.equal c.Svid.not_after 1767225600L));
        check "utc pivot: 49 is 2049, 50 is 1950"
          (parses
             (cert
                ~validity:(seq [ utc "500101000000Z"; utc "490101000000Z" ])
                ~exts:[ san_ext [ wl ] ])
             (fun c ->
               Int64.equal c.Svid.not_before (-631152000L)
               && Int64.equal c.Svid.not_after 2493072000L));
        check "ca cert extracts is_ca and cert-sign"
          (parses
             (cert ~validity:good_validity
                ~exts:[ san_ext [ wl ]; ku_ext "\x00\x06"; bc_ext true ])
             (fun c ->
               c.Svid.is_ca && String.equal (usage_string c) "kcs,crl"));
        check "unknown usage bits map to other"
          (parses
             (cert ~validity:good_validity
                ~exts:[ san_ext [ wl ]; ku_ext "\x00\xa1" ])
             (fun c -> String.equal (usage_string c) "ds,other"));
        check "no extensions extracts empty"
          (parses
             (seq
                [
                  seq
                    [
                      tlv "\x02" "\x01";
                      seq [];
                      seq [];
                      good_validity;
                      seq [];
                      seq [];
                    ];
                  seq [];
                  tlv "\x03" "\x00";
                ])
             (fun c ->
               List.length c.Svid.san_uris = 0
               && (not c.Svid.is_ca)
               && List.length c.Svid.key_usage = 0));
        check "dns-only san extracts no uris"
          (parses
             (cert ~validity:good_validity
                ~exts:
                  [
                    seq
                      [
                        oid "\x55\x1d\x11";
                        octets (seq [ tlv "\x82" "example.org" ]);
                      ];
                  ])
             (fun c -> List.length c.Svid.san_uris = 0));
        check "critical flag in extension accepted"
          (parses
             (cert ~validity:good_validity
                ~exts:
                  [
                    seq
                      [
                        oid "\x55\x1d\x11";
                        tlv "\x01" "\xff";
                        octets (seq [ uri_san_name wl ]);
                      ];
                  ])
             (fun c -> List.equal String.equal c.Svid.san_uris [ wl ]));
        check "truncated cert is a der error"
          (rejects_as "\x30\x03\x02\x01" "der:truncated_value:3:2");
        check "non-sequence top level rejected"
          (rejects_as "\x04\x03abc" "cert_shape");
        check "two top-level children rejected"
          (rejects_as (seq [ seq []; seq [] ]) "cert_shape");
        check "short tbs rejected"
          (rejects_as
             (seq [ seq [ tlv "\x02" "\x01" ]; seq []; tlv "\x03" "\x00" ])
             "tbs_shape");
        check "month 13 rejected"
          (rejects_as
             (cert
                ~validity:(seq [ utc "251301000000Z"; utc "260101000000Z" ])
                ~exts:[])
             "bad_time");
        check "missing z suffix rejected"
          (rejects_as
             (cert
                ~validity:(seq [ utc "250101000000"; utc "260101000000Z" ])
                ~exts:[])
             "bad_time");
        check "utc with generalized width rejected"
          (rejects_as
             (cert
                ~validity:(seq [ utc "20250101000000Z"; utc "260101000000Z" ])
                ~exts:[])
             "bad_time");
        check "integer validity time rejected"
          (rejects_as
             (cert
                ~validity:(seq [ tlv "\x02" "\x01"; utc "260101000000Z" ])
                ~exts:[])
             "time_tag:2");
        check "three validity times rejected"
          (rejects_as
             (cert
                ~validity:
                  (seq
                     [
                       utc "250101000000Z";
                       utc "260101000000Z";
                       utc "270101000000Z";
                     ])
                ~exts:[])
             "validity_shape");
        check "non-ff boolean rejected"
          (rejects_as
             (cert ~validity:good_validity
                ~exts:
                  [
                    seq
                      [
                        oid "\x55\x1d\x13";
                        octets (seq [ tlv "\x01" "\x01" ]);
                      ];
                  ])
             "bool_shape");
        check "empty bit string rejected"
          (rejects_as
             (cert ~validity:good_validity
                ~exts:[ seq [ oid "\x55\x1d\x0f"; octets (tlv "\x03" "") ] ])
             "key_usage_shape");
        check "unused-bit count over 7 rejected"
          (rejects_as
             (cert ~validity:good_validity
                ~exts:
                  [ seq [ oid "\x55\x1d\x0f"; octets (tlv "\x03" "\x08\x80") ] ])
             "key_usage_shape");
        check "end-to-end: parsed leaf validates against bundle"
          (Trust_domain.parse "example.org"
          |> Result.fold
               ~error:(fun _ -> false)
               ~ok:(fun td ->
                 let b =
                   Bundle.of_fresh
                     (Bundle.refresh ~td ~epoch:(Bundle.Epoch 0)
                        ~roots:(Bundle.Roots [ "root-der" ]))
                 in
                 Bundle.usable b
                 |> Option.fold ~none:false ~some:(fun bundle ->
                        X509.parse good_cert
                        |> Result.fold
                             ~error:(fun _ -> false)
                             ~ok:(fun c ->
                               Svid.validate_leaf ~now:1750000000L ~bundle c
                               |> Result.fold
                                    ~ok:(fun id ->
                                      String.equal (Spiffe_id.to_string id) wl)
                                    ~error:(fun _ -> false)))));
      ]
  in
  exit (min failures 1)
