(* X.509 field extraction for SVID validation (RFC 5280 section 4.1),
   over the total DER walker. Extracts exactly what Svid.validate_leaf
   consumes: URI SANs, the validity window as epoch seconds, the
   basicConstraints cA flag, and the keyUsage bits. Everything else in
   the certificate is walked past, not interpreted. Signature checking
   is a later milestone (M13/M14). *)

type error =
  | Der of Der.error
  | Cert_shape
  | Tbs_shape
  | Validity_shape
  | Time_tag of int
  | Bad_time
  | Extensions_shape
  | Extension_shape
  | Bool_shape
  | Key_usage_shape
  | San_shape

let error_to_string e =
  match e with
  | Der d -> "der:" ^ Der.error_to_string d
  | Cert_shape -> "cert_shape"
  | Tbs_shape -> "tbs_shape"
  | Validity_shape -> "validity_shape"
  | Time_tag n -> Printf.sprintf "time_tag:%d" n
  | Bad_time -> "bad_time"
  | Extensions_shape -> "extensions_shape"
  | Extension_shape -> "extension_shape"
  | Bool_shape -> "bool_shape"
  | Key_usage_shape -> "key_usage_shape"
  | San_shape -> "san_shape"

let der r = Result.map_error (fun e -> Der e) r

let is_universal (h : Der.header) =
  match h.cls with
  | Der.Universal -> true
  | Der.Application | Der.Context_specific | Der.Private_class -> false

let is_context (h : Der.header) =
  match h.cls with
  | Der.Context_specific -> true
  | Der.Universal | Der.Application | Der.Private_class -> false

let is_seq (n : Der.tlv) =
  is_universal n.header && n.header.constructed && n.header.number = 16

let is_prim (n : Der.tlv) num =
  is_universal n.header && (not n.header.constructed) && n.header.number = num

let is_context_cons (n : Der.tlv) num =
  is_context n.header && n.header.constructed && n.header.number = num

let seq_children shape node =
  match () with
  | () when is_seq node -> der (Der.children node)
  | () -> Error shape

(* Object identifiers arrive as raw content octets; the three extension
   ids below are compared as bytes, no arc decoding needed.
   2.5.29.17 subjectAltName, 2.5.29.19 basicConstraints,
   2.5.29.15 keyUsage. *)
let san_oid = "\x55\x1d\x11"

let bc_oid = "\x55\x1d\x13"

let ku_oid = "\x55\x1d\x0f"

(* --- time ----------------------------------------------------------- *)

(* n ASCII digits off the head of a char list. *)
let digits n l =
  let rec go n acc l =
    match () with
    | () when n = 0 -> Some (acc, l)
    | () -> (
        match l with
        | [] -> None
        | c :: tl ->
            let d = Char.code c - 48 in
            if d >= 0 && d <= 9 then go (n - 1) ((acc * 10) + d) tl else None)
  in
  go n 0 l

(* Days since 1970-01-01 for a proleptic-Gregorian civil date, valid for
   any year the two ASN.1 time types can carry (1950..9999). Divisors
   are the calendar constants 400, 5, 4, 100: never zero. *)
let days_from_civil ~y ~m ~d =
  let y' = if m <= 2 then y - 1 else y in
  let era = y' / 400 (* @total-accessor *) in
  let yoe = y' - (era * 400) in
  let mp = if m > 2 then m - 3 else m + 9 in
  let doy = (((153 * mp) + 2) / 5) (* @total-accessor *) + d - 1 in
  let doe =
    (yoe * 365) + (yoe / 4) - (yoe / 100) (* @total-accessor *) + doy
  in
  (era * 146097) + doe - 719468

let epoch ~y ~m ~d ~hh ~mm ~ss =
  Int64.of_int
    ((days_from_civil ~y ~m ~d * 86400) + (hh * 3600) + (mm * 60) + ss)

let in_range v lo hi = v >= lo && v <= hi

(* Shared tail of both time forms: MMDDHHMMSS then a literal Z and
   nothing after it. *)
let finish_time y rest =
  Option.bind (digits 2 rest) (fun (m, r) ->
      Option.bind (digits 2 r) (fun (d, r) ->
          Option.bind (digits 2 r) (fun (hh, r) ->
              Option.bind (digits 2 r) (fun (mm, r) ->
                  Option.bind (digits 2 r) (fun (ss, r) ->
                      match r with
                      | [ 'Z' ] ->
                          if
                            in_range m 1 12 && in_range d 1 31
                            && in_range hh 0 23 && in_range mm 0 59
                            && in_range ss 0 59
                          then Some (epoch ~y ~m ~d ~hh ~mm ~ss)
                          else None
                      | not_z ->
                          ignore not_z;
                          None)))))

(* UTCTime YYMMDDHHMMSSZ with the RFC 5280 pivot (YY < 50 is 20YY),
   GeneralizedTime YYYYMMDDHHMMSSZ. *)
let parse_time (node : Der.tlv) =
  let cs = String.to_seq node.value |> List.of_seq in
  match () with
  | () when is_prim node 23 ->
      Option.bind (digits 2 cs) (fun (yy, rest) ->
          let y = if yy < 50 then 2000 + yy else 1900 + yy in
          finish_time y rest)
      |> Option.to_result ~none:Bad_time
  | () when is_prim node 24 ->
      Option.bind (digits 4 cs) (fun (y, rest) -> finish_time y rest)
      |> Option.to_result ~none:Bad_time
  | () -> Error (Time_tag node.header.number)

(* --- extensions ----------------------------------------------------- *)

let parse_bool s =
  match String.to_seq s |> List.of_seq with
  | [ c ] -> (
      let b = Char.code c in
      match () with
      | () when b = 0xff -> Ok true
      | () when b = 0x00 -> Ok false
      | () -> Error Bool_shape)
  | not_one_byte ->
      ignore not_one_byte;
      Error Bool_shape

(* BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... } *)
let parse_basic_constraints v =
  Result.bind (der (Der.parse_exact v)) (fun node ->
      Result.bind (seq_children Bool_shape node) (fun kids ->
          match kids with
          | [] -> Ok false
          | first :: _rest ->
              if is_prim first 1 then parse_bool first.value else Ok false))

(* KeyUsage ::= BIT STRING; bit 0 digitalSignature, bit 4 keyAgreement,
   bit 5 keyCertSign, bit 6 cRLSign. Any other set bit maps to
   Other_usage. *)
let parse_key_usage v =
  Result.bind (der (Der.parse_exact v)) (fun node ->
      match () with
      | () when not (is_prim node 3) -> Error Key_usage_shape
      | () -> (
          match String.to_seq node.value |> List.of_seq with
          | [] -> Error Key_usage_shape
          | unused :: data -> (
              match () with
              | () when Char.code unused > 7 -> Error Key_usage_shape
              | () -> (
                  match data with
                  | [] -> Ok []
                  | b0 :: more ->
                      let b = Char.code b0 in
                      let known =
                        List.filter_map
                          (fun (mask, u) ->
                            if b land mask <> 0 then Some u else None)
                          [
                            (0x80, Svid.Digital_signature);
                            (0x08, Svid.Key_agreement);
                            (0x04, Svid.Key_cert_sign);
                            (0x02, Svid.Crl_sign);
                          ]
                      in
                      let other =
                        b land 0x71 <> 0
                        || List.exists (fun c -> Char.code c <> 0) more
                      in
                      Ok (if other then known @ [ Svid.Other_usage ] else known)
                  ))))

(* SubjectAltName ::= SEQUENCE OF GeneralName; a URI is the primitive
   context tag 6 (IA5String). Other name forms are walked past. *)
let parse_san v =
  Result.bind (der (Der.parse_exact v)) (fun node ->
      Result.bind (seq_children San_shape node) (fun names ->
          Ok
            (List.filter_map
               (fun (n : Der.tlv) ->
                 if
                   is_context n.header
                   && (not n.header.constructed)
                   && n.header.number = 6
                 then Some n.value
                 else None)
               names)))

(* Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
   extnValue OCTET STRING } *)
let ext_oid_value ext =
  Result.bind (seq_children Extension_shape ext) (fun kids ->
      let shaped oid v =
        match () with
        | () when is_prim oid 6 && is_prim v 4 ->
            Ok (oid.Der.value, v.Der.value)
        | () -> Error Extension_shape
      in
      match kids with
      | [ oid; v ] -> shaped oid v
      | [ oid; _critical; v ] -> shaped oid v
      | other_shape ->
          ignore other_shape;
          Error Extension_shape)

let ext_step acc ext =
  Result.bind acc (fun (san, ca, ku) ->
      Result.bind (ext_oid_value ext) (fun (oid, v) ->
          match () with
          | () when String.equal oid san_oid ->
              parse_san v |> Result.map (fun uris -> (uris, ca, ku))
          | () when String.equal oid bc_oid ->
              parse_basic_constraints v |> Result.map (fun c -> (san, c, ku))
          | () when String.equal oid ku_oid ->
              parse_key_usage v |> Result.map (fun u -> (san, ca, u))
          | () -> Ok (san, ca, ku)))

(* extensions [3] EXPLICIT SEQUENCE OF Extension, optional. A leaf with
   no extensions extracts as no SANs, not a CA, no usage bits; the
   SVID-level requirements are Svid.validate_leaf's to enforce. *)
let parse_extensions tail =
  List.find_opt (fun n -> is_context_cons n 3) tail
  |> Option.fold
       ~none:(Ok ([], false, []))
       ~some:(fun extn ->
         Result.bind (der (Der.children extn)) (fun inner ->
             Result.bind
               (match inner with
               | [ s ] -> Ok s
               | not_single ->
                   ignore not_single;
                   Error Extensions_shape)
               (fun s ->
                 Result.bind (seq_children Extensions_shape s) (fun exts ->
                     List.fold_left ext_step (Ok ([], false, [])) exts))))

(* --- certificate ---------------------------------------------------- *)

let drop_version kids =
  match kids with
  | v :: rest -> if is_context_cons v 0 then rest else kids
  | [] -> []

let tbs_fields fields =
  match fields with
  | _serial :: _sigalg :: _issuer :: validity :: _subject :: _spki :: tail ->
      Ok (validity, tail)
  | too_short ->
      ignore too_short;
      Error Tbs_shape

let validity_times vkids =
  match vkids with
  | [ nb; na ] ->
      Result.bind (parse_time nb) (fun nbe ->
          parse_time na |> Result.map (fun nae -> (nbe, nae)))
  | not_two ->
      ignore not_two;
      Error Validity_shape

let parse s : (Svid.cert, error) result =
  Result.bind (der (Der.parse_exact s)) (fun cert ->
      Result.bind (seq_children Cert_shape cert) (fun top ->
          Result.bind
            (match top with
            | [ tbs; _alg; _sigval ] -> Ok tbs
            | not_three ->
                ignore not_three;
                Error Cert_shape)
            (fun tbs ->
              Result.bind (seq_children Tbs_shape tbs) (fun tbs_kids ->
                  Result.bind (tbs_fields (drop_version tbs_kids))
                    (fun (validity, tail) ->
                      Result.bind (seq_children Validity_shape validity)
                        (fun vkids ->
                          Result.bind (validity_times vkids)
                            (fun (not_before, not_after) ->
                              Result.map
                                (fun (san_uris, is_ca, key_usage) ->
                                  {
                                    Svid.san_uris;
                                    not_before;
                                    not_after;
                                    is_ca;
                                    key_usage;
                                  })
                                (parse_extensions tail))))))))
