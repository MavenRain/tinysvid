(* DER tag-length-value walker, total over string input (X.690 sections
   8.1, 10.1). Input becomes a char list once; every step consumes from
   the head, so no index arithmetic and no partial String access. DER
   restrictions enforced here: definite lengths only, minimal length
   encoding, single-byte tags (high-tag-number form rejected; X.509 never
   uses it). Lengths above four bytes are rejected, which caps a value at
   2^32 - 1 bytes: far beyond any certificate. *)

type tag_class = Universal | Application | Context_specific | Private_class

type header = { cls : tag_class; constructed : bool; number : int }

(* raw is the node's exact input octets (tag, length, value): chain
   validation signs and verifies over raw tbsCertificate bytes, and DER
   is canonical, so keeping the span beats re-encoding. *)
type tlv = { header : header; value : string; raw : string }

type error =
  | Truncated_header
  | Truncated_length
  | Truncated_value of { need : int; have : int }
  | High_tag_number
  | Indefinite_length
  | Non_minimal_length
  | Length_overflow of int
  | Trailing_bytes of int
  | Not_constructed

let error_to_string e =
  match e with
  | Truncated_header -> "truncated_header"
  | Truncated_length -> "truncated_length"
  | Truncated_value { need; have } ->
      Printf.sprintf "truncated_value:%d:%d" need have
  | High_tag_number -> "high_tag_number"
  | Indefinite_length -> "indefinite_length"
  | Non_minimal_length -> "non_minimal_length"
  | Length_overflow n -> Printf.sprintf "length_overflow:%d" n
  | Trailing_bytes n -> Printf.sprintf "trailing_bytes:%d" n
  | Not_constructed -> "not_constructed"

(* take n l = Some (first n bytes, rest), None when l is shorter. *)
let take n l =
  let rec go n acc l =
    match () with
    | () when n <= 0 -> Some (List.rev acc, l)
    | () -> (
        match l with [] -> None | c :: tl -> go (n - 1) (c :: acc) tl)
  in
  go n [] l

let tag_class_of_byte b =
  let bits = b lsr 6 in
  match () with
  | () when bits = 0 -> Universal
  | () when bits = 1 -> Application
  | () when bits = 2 -> Context_specific
  | () -> Private_class

(* Length octets, X.690 8.1.3, with the DER 10.1 minimality rules:
   short form under 0x80; long form 0x81..0x84 with no leading zero
   octet and a value that does not fit the short form. 0x80 is the
   BER indefinite form, forbidden in DER. *)
let parse_length bytes =
  match bytes with
  | [] -> Error Truncated_length
  | l0 :: rest -> (
      let b = Char.code l0 in
      match () with
      | () when b < 0x80 -> Ok (b, [ l0 ], rest)
      | () when b = 0x80 -> Error Indefinite_length
      | () -> (
          let n = b land 0x7f in
          match () with
          | () when n > 4 -> Error (Length_overflow n)
          | () ->
              take n rest
              |> Option.to_result ~none:Truncated_length
              |> Result.map (fun (len_bytes, tl) ->
                     ( List.fold_left
                         (fun acc c -> (acc lsl 8) lor Char.code c)
                         0 len_bytes,
                       len_bytes, tl ))
              |> Fun.flip Result.bind (fun (len, len_bytes, tl) ->
                     let leading_zero =
                       match len_bytes with
                       | c :: _ -> Char.code c = 0
                       | [] -> true
                     in
                     match () with
                     | () when leading_zero || len < 0x80 ->
                         Error Non_minimal_length
                     | () -> Ok (len, l0 :: len_bytes, tl))))

(* One TLV off the head of the byte list; returns the node and the rest. *)
let parse_node bytes =
  match bytes with
  | [] -> Error Truncated_header
  | t :: rest -> (
      let tb = Char.code t in
      let number = tb land 0x1f in
      match () with
      | () when number = 0x1f -> Error High_tag_number
      | () ->
          Result.bind (parse_length rest) (fun (len, len_octets, tl) ->
              take len tl
              |> Option.to_result
                   ~none:(Truncated_value { need = len; have = List.length tl })
              |> Result.map (fun (v, tl') ->
                     ( {
                         header =
                           {
                             cls = tag_class_of_byte tb;
                             constructed = tb land 0x20 <> 0;
                             number;
                           };
                         value = List.to_seq v |> String.of_seq;
                         raw =
                           List.to_seq ((t :: len_octets) @ v)
                           |> String.of_seq;
                       },
                       tl' ))))

(* Every TLV consumes at least the tag byte, so the list shrinks and the
   recursion terminates. *)
let parse_nodes bytes =
  let rec go acc bytes =
    match bytes with
    | [] -> Ok (List.rev acc)
    | _ :: _ ->
        Result.bind (parse_node bytes) (fun (node, rest) ->
            go (node :: acc) rest)
  in
  go [] bytes

let bytes_of_string s = String.to_seq s |> List.of_seq

(* One TLV plus any remaining input. *)
let parse_one s =
  parse_node (bytes_of_string s)
  |> Result.map (fun (node, rest) -> (node, List.to_seq rest |> String.of_seq))

(* Exactly one TLV spanning the whole input. *)
let parse_exact s =
  Result.bind (parse_one s) (fun (node, rest) ->
      let n = String.length rest in
      match () with
      | () when n = 0 -> Ok node
      | () -> Error (Trailing_bytes n))

(* All TLVs until the input is exhausted. *)
let parse_all s = parse_nodes (bytes_of_string s)

(* Child nodes of a constructed value. *)
let children node =
  match node.header.constructed with
  | false -> Error Not_constructed
  | true -> parse_all node.value
