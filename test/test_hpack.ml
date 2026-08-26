open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

(* hex text with spaces, exactly as printed in RFC 7541 Appendix C *)
let hex_val c =
  match () with
  | () when c >= '0' && c <= '9' -> Some (Char.code c - 48)
  | () when c >= 'a' && c <= 'f' -> Some (Char.code c - 87)
  | () -> None

let of_hex s =
  let rec go acc l =
    match l with
    | [] -> Some acc
    | a :: b :: rest ->
        Option.bind (hex_val a) (fun ha ->
            Option.bind (hex_val b) (fun hb ->
                go (acc ^ H2.byte ((ha * 16) + hb)) rest))
    | _ :: [] -> None
  in
  String.to_seq s
  |> Seq.filter (fun c -> c <> ' ')
  |> List.of_seq |> go ""
  |> Option.fold ~none:"" ~some:Fun.id

let headers_eq =
  List.equal (fun (a, b) (c, d) -> String.equal a c && String.equal b d)

let ok_headers r expected =
  Result.fold ~error:(fun _ -> false)
    ~ok:(fun (hs, _) -> headers_eq hs expected)
    r

let ok_dyn r entries size =
  Result.fold ~error:(fun _ -> false)
    ~ok:(fun (_, d) ->
      headers_eq d.Hpack.entries entries && d.Hpack.size = size)
    r

let is_err p r = Result.fold ~ok:(fun _ -> false) ~error:p r

let is_truncated r =
  is_err
    (fun e ->
      match e with
      | Hpack.Truncated -> true
      | Hpack.Integer_too_large | Hpack.Bad_index _ | Hpack.Bad_padding
      | Hpack.Eos_in_string | Hpack.Table_broken
      | Hpack.Table_update_too_large _ ->
          false)
    r

let is_too_large r =
  is_err
    (fun e ->
      match e with
      | Hpack.Integer_too_large -> true
      | Hpack.Truncated | Hpack.Bad_index _ | Hpack.Bad_padding
      | Hpack.Eos_in_string | Hpack.Table_broken
      | Hpack.Table_update_too_large _ ->
          false)
    r

let is_bad_index n r =
  is_err
    (fun e ->
      match e with
      | Hpack.Bad_index i -> i = n
      | Hpack.Truncated | Hpack.Integer_too_large | Hpack.Bad_padding
      | Hpack.Eos_in_string | Hpack.Table_broken
      | Hpack.Table_update_too_large _ ->
          false)
    r

let is_bad_padding r =
  is_err
    (fun e ->
      match e with
      | Hpack.Bad_padding -> true
      | Hpack.Truncated | Hpack.Integer_too_large | Hpack.Bad_index _
      | Hpack.Eos_in_string | Hpack.Table_broken
      | Hpack.Table_update_too_large _ ->
          false)
    r

let is_eos r =
  is_err
    (fun e ->
      match e with
      | Hpack.Eos_in_string -> true
      | Hpack.Truncated | Hpack.Integer_too_large | Hpack.Bad_index _
      | Hpack.Bad_padding | Hpack.Table_broken
      | Hpack.Table_update_too_large _ ->
          false)
    r

let is_update_too_large r =
  is_err
    (fun e ->
      match e with
      | Hpack.Table_update_too_large _ -> true
      | Hpack.Truncated | Hpack.Integer_too_large | Hpack.Bad_index _
      | Hpack.Bad_padding | Hpack.Eos_in_string | Hpack.Table_broken ->
          false)
    r

let int_is ~prefix hex n rest_len =
  Hpack.decode_prefix_int ~prefix (Der.bytes_of_string (of_hex hex))
  |> Result.fold ~error:(fun _ -> false)
       ~ok:(fun (v, rest) -> v = n && List.length rest = rest_len)

let rt_int prefix n =
  Hpack.decode_prefix_int ~prefix
    (Der.bytes_of_string (H2.encode_prefix_int ~prefix n))
  |> Result.fold ~error:(fun _ -> false) ~ok:(fun (v, rest) -> v = n && rest = [])

let huff_is hex s =
  Hpack.decode_huffman (of_hex hex)
  |> Result.fold ~error:(fun _ -> false) ~ok:(String.equal s)

let huff_rt s =
  Hpack.encode_huffman s
  |> Option.fold ~none:false ~some:(fun e ->
         Hpack.decode_huffman e
         |> Result.fold ~error:(fun _ -> false) ~ok:(String.equal s))

let dyn0 cap = Hpack.empty_dyn ~cap
let block ~cap d hex = Hpack.decode_header_block ~max_cap:cap d (of_hex hex)
let next ~cap prev hex = Result.bind prev (fun (_, d) -> block ~cap d hex)

(* RFC 7541 Appendix C.3 (plain) and C.4 (Huffman) request sequences *)
let req1 = [ (":method", "GET"); (":scheme", "http"); (":path", "/"); (":authority", "www.example.com") ]
let req2 = req1 @ [ ("cache-control", "no-cache") ]
let req3 =
  [ (":method", "GET"); (":scheme", "https"); (":path", "/index.html");
    (":authority", "www.example.com"); ("custom-key", "custom-value") ]

let req_dyn1 = [ (":authority", "www.example.com") ]
let req_dyn2 = ("cache-control", "no-cache") :: req_dyn1
let req_dyn3 = ("custom-key", "custom-value") :: req_dyn2

let c3_1 = block ~cap:4096 (dyn0 4096) "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"
let c3_2 = next ~cap:4096 c3_1 "8286 84be 5808 6e6f 2d63 6163 6865"
let c3_3 = next ~cap:4096 c3_2 "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65"
let c4_1 = block ~cap:4096 (dyn0 4096) "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"
let c4_2 = next ~cap:4096 c4_1 "8286 84be 5886 a8eb 1064 9cbf"
let c4_3 = next ~cap:4096 c4_2 "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf"

(* Appendix C.6 response sequence, table capacity 256, with eviction *)
let date1 = "Mon, 21 Oct 2013 20:13:21 GMT"
let date2 = "Mon, 21 Oct 2013 20:13:22 GMT"
let url = "https://www.example.com"
let cookie = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"

let resp1 =
  [ (":status", "302"); ("cache-control", "private"); ("date", date1); ("location", url) ]
let resp2 =
  [ (":status", "307"); ("cache-control", "private"); ("date", date1); ("location", url) ]
let resp3 =
  [ (":status", "200"); ("cache-control", "private"); ("date", date2); ("location", url);
    ("content-encoding", "gzip"); ("set-cookie", cookie) ]

let resp_dyn1 =
  [ ("location", url); ("date", date1); ("cache-control", "private"); (":status", "302") ]
let resp_dyn2 =
  [ (":status", "307"); ("location", url); ("date", date1); ("cache-control", "private") ]
let resp_dyn3 = [ ("set-cookie", cookie); ("content-encoding", "gzip"); ("date", date2) ]

let c6_1 = block ~cap:256 (dyn0 256) "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3"
let c6_2 = next ~cap:256 c6_1 "4883 640e ffc1 c0bf"
let c6_3 = next ~cap:256 c6_2 "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07"

let all_bytes_rt =
  List.init 256 Fun.id |> List.for_all (fun i -> huff_rt (H2.byte i))

let static_is i name value =
  Hpack.lookup (dyn0 0) i
  |> Option.fold ~none:false ~some:(fun (n, v) ->
         String.equal n name && String.equal v value)

let () =
  let failures =
    List.fold_left
      (fun acc (name, ok) -> acc + check name ok)
      0
      [
        (* prefix integers, RFC C.1 *)
        ("int 10 in 5-bit prefix", int_is ~prefix:5 "0a" 10 0);
        ("int 1337 in 5-bit prefix", int_is ~prefix:5 "1f9a 0a" 1337 0);
        ("int 42 in 8-bit prefix", int_is ~prefix:8 "2a" 42 0);
        ("int trailing bytes stay", int_is ~prefix:5 "0aff" 10 1);
        ("int pattern bits masked", int_is ~prefix:5 "ea" 10 0);
        ( "int roundtrip grid",
          List.for_all
            (fun p ->
              List.for_all (rt_int p)
                [ 0; 1; 30; 31; 32; 127; 128; 255; 256; 16383; 16384; 100000 ])
            [ 1; 4; 5; 7; 8 ] );
        ( "int continuation too long",
          is_too_large
            (Hpack.decode_prefix_int ~prefix:5
               (Der.bytes_of_string (of_hex "1f80 8080 8080 01"))) );
        ( "int truncated after first byte",
          is_truncated
            (Hpack.decode_prefix_int ~prefix:5 (Der.bytes_of_string (of_hex "1f"))) );
        ( "int truncated mid continuation",
          is_truncated
            (Hpack.decode_prefix_int ~prefix:5
               (Der.bytes_of_string (of_hex "1f80"))) );
        (* Huffman, RFC C.4 and C.6 string vectors *)
        ("huffman www.example.com", huff_is "f1e3 c2e5 f23a 6ba0 ab90 f4ff" "www.example.com");
        ("huffman no-cache", huff_is "a8eb 1064 9cbf" "no-cache");
        ("huffman custom-key", huff_is "25a8 49e9 5ba9 7d7f" "custom-key");
        ("huffman custom-value", huff_is "25a8 49e9 5bb8 e8b4 bf" "custom-value");
        ("huffman 302", huff_is "6402" "302");
        ("huffman private", huff_is "aec3 771a 4b" "private");
        ("huffman empty", huff_is "" "");
        ("huffman zero plus ones pad", huff_is "07" "0");
        ( "huffman encode pins table",
          Hpack.encode_huffman "www.example.com"
          |> Option.fold ~none:false
               ~some:(String.equal (of_hex "f1e3 c2e5 f23a 6ba0 ab90 f4ff")) );
        ("huffman roundtrip all 256 bytes", all_bytes_rt);
        ("huffman roundtrip date", huff_rt "Mon, 21 Oct 2013 20:13:21 GMT");
        ("huffman zero pad rejected", is_bad_padding (Hpack.decode_huffman (of_hex "00")));
        ("huffman eos rejected", is_eos (Hpack.decode_huffman (of_hex "ffff fffc")));
        ("huffman long pad rejected", is_bad_padding (Hpack.decode_huffman (of_hex "ffff")));
        ("huffman eight ones pad rejected", is_bad_padding (Hpack.decode_huffman (of_hex "ff")));
        (* static table *)
        ("static 2 is :method GET", static_is 2 ":method" "GET");
        ("static 8 is :status 200", static_is 8 ":status" "200");
        ("static 61 is www-authenticate", static_is 61 "www-authenticate" "");
        ("static 0 is out of range", Hpack.lookup (dyn0 0) 0 = None);
        ("static 62 empty dynamic is out of range", Hpack.lookup (dyn0 0) 62 = None);
        (* dynamic table units *)
        ( "dyn insert then evict oldest",
          let d = Hpack.empty_dyn ~cap:100 in
          let d = Hpack.dyn_insert d ("aaaa", "bbbb") in
          let d = Hpack.dyn_insert d ("cccc", "dddd") in
          let d = Hpack.dyn_insert d ("eeee", "ffff") in
          headers_eq d.Hpack.entries [ ("eeee", "ffff"); ("cccc", "dddd") ]
          && d.Hpack.size = 80 );
        ( "dyn resize evicts",
          let d = Hpack.empty_dyn ~cap:100 in
          let d = Hpack.dyn_insert d ("aaaa", "bbbb") in
          let d = Hpack.dyn_insert d ("cccc", "dddd") in
          let d = Hpack.dyn_resize d 40 in
          headers_eq d.Hpack.entries [ ("cccc", "dddd") ] && d.Hpack.size = 40 );
        ( "dyn oversize entry empties table",
          let d = Hpack.empty_dyn ~cap:50 in
          let d = Hpack.dyn_insert d ("aaaa", "bbbb") in
          let d = Hpack.dyn_insert d (String.make 30 'x', "y") in
          d.Hpack.entries = [] && d.Hpack.size = 0 );
        ( "dyn lookup newest first",
          let d = Hpack.empty_dyn ~cap:4096 in
          let d = Hpack.dyn_insert d ("old", "1") in
          let d = Hpack.dyn_insert d ("new", "2") in
          Hpack.lookup d 62
          |> Option.fold ~none:false ~some:(fun (n, v) ->
                 String.equal n "new" && String.equal v "2") );
        (* header block sequences *)
        ("C.3.1 headers", ok_headers c3_1 req1);
        ("C.3.1 table", ok_dyn c3_1 req_dyn1 57);
        ("C.3.2 headers", ok_headers c3_2 req2);
        ("C.3.2 table", ok_dyn c3_2 req_dyn2 110);
        ("C.3.3 headers", ok_headers c3_3 req3);
        ("C.3.3 table", ok_dyn c3_3 req_dyn3 164);
        ("C.4.1 headers", ok_headers c4_1 req1);
        ("C.4.1 table", ok_dyn c4_1 req_dyn1 57);
        ("C.4.2 headers", ok_headers c4_2 req2);
        ("C.4.2 table", ok_dyn c4_2 req_dyn2 110);
        ("C.4.3 headers", ok_headers c4_3 req3);
        ("C.4.3 table", ok_dyn c4_3 req_dyn3 164);
        ("C.6.1 headers", ok_headers c6_1 resp1);
        ("C.6.1 table", ok_dyn c6_1 resp_dyn1 222);
        ("C.6.2 headers", ok_headers c6_2 resp2);
        ("C.6.2 table", ok_dyn c6_2 resp_dyn2 222);
        ("C.6.3 headers", ok_headers c6_3 resp3);
        ("C.6.3 table", ok_dyn c6_3 resp_dyn3 215);
        (* block level errors and size updates *)
        ("indexed 0 rejected", is_bad_index 0 (block ~cap:4096 (dyn0 4096) "80"));
        ("indexed past tables rejected", is_bad_index 126 (block ~cap:4096 (dyn0 4096) "fe"));
        ( "size update within cap",
          block ~cap:4096 (dyn0 4096) "3f09"
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun (hs, d) -> hs = [] && d.Hpack.cap = 40) );
        ( "size update over cap rejected",
          is_update_too_large (block ~cap:256 (dyn0 256) "3fe1 1f") );
        ("truncated literal rejected", is_truncated (block ~cap:4096 (dyn0 4096) "4003 6162"));
        ( "never-indexed decodes without insert",
          block ~cap:4096 (dyn0 4096) "1008 7061 7373 776f 7264 0673 6563 7265 74"
          |> Result.fold ~error:(fun _ -> false)
               ~ok:(fun (hs, d) ->
                 headers_eq hs [ ("password", "secret") ] && d.Hpack.entries = []) );
      ]
  in
  exit (min failures 1)
