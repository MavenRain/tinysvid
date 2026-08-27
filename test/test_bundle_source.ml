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

let roots_are expected r =
  Result.fold r
    ~error:(fun _ -> false)
    ~ok:(fun (Bundle.Roots got) -> List.equal String.equal got expected)

let errors_as expected r =
  Result.fold r
    ~ok:(fun _ -> false)
    ~error:(fun e -> String.equal (Bundle_source.error_to_string e) expected)

let () =
  let failures =
    List.fold_left ( + ) 0
      [
        check "one certificate parses to one root"
          (roots_are [ root_der ]
             (Bundle_source.roots_of_der_concat root_der));
        check "two certificates keep their order"
          (roots_are [ root_der; other_der ]
             (Bundle_source.roots_of_der_concat (root_der ^ other_der)));
        check "the empty bundle rejects"
          (errors_as "empty_bundle" (Bundle_source.roots_of_der_concat ""));
        check "a truncated tail rejects the whole bundle"
          (Result.fold
             (Bundle_source.roots_of_der_concat (root_der ^ "\x30\x05"))
             ~ok:(fun _ -> false)
             ~error:(fun e ->
               match e with
               | Bundle_source.Bad_der _ -> true
               | Bundle_source.Empty_bundle | Bundle_source.Bad_certificate _
                 ->
                   false));
        check "a non-certificate first node rejects at index 0"
          (Result.fold
             (Bundle_source.roots_of_der_concat (octets "zz" ^ root_der))
             ~ok:(fun _ -> false)
             ~error:(fun e ->
               match e with
               | Bundle_source.Bad_certificate { index; err = _ } -> index = 0
               | Bundle_source.Empty_bundle | Bundle_source.Bad_der _ -> false));
        check "a bad second certificate rejects at index 1"
          (Result.fold
             (Bundle_source.roots_of_der_concat (root_der ^ seq []))
             ~ok:(fun _ -> false)
             ~error:(fun e ->
               match e with
               | Bundle_source.Bad_certificate { index; err = _ } -> index = 1
               | Bundle_source.Empty_bundle | Bundle_source.Bad_der _ -> false));
      ]
  in
  exit (min failures 1)
