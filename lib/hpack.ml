(* M24 stage A: HPACK decoder (RFC 7541). The M22 encoder in H2 emits
   header blocks; this module reads them: prefix integers (section 5.1),
   Huffman-coded string literals (section 5.2 and Appendix B), the
   static and dynamic tables (sections 2.3 and 4), the four field
   representations, and the table-size update (section 6). Pure: input
   becomes a char list once (the Der idiom) and every step consumes
   from the head. The two tables are extracted from the RFC text by a
   script, not typed by hand; the tests hold them to the Appendix C
   vectors and to the Kraft equality (the code is complete), and the
   trie build fails closed on any prefix conflict. *)

type error =
  | Truncated
  | Integer_too_large
  | Bad_index of int
  | Bad_padding
  | Eos_in_string
  | Table_broken
  | Table_update_too_large of { requested : int; cap : int }

let error_to_string e =
  match e with
  | Truncated -> "truncated"
  | Integer_too_large -> "integer_too_large"
  | Bad_index i -> Printf.sprintf "bad_index:%d" i
  | Bad_padding -> "bad_padding"
  | Eos_in_string -> "eos_in_string"
  | Table_broken -> "table_broken"
  | Table_update_too_large { requested; cap } ->
      Printf.sprintf "table_update_too_large:%d:%d" requested cap

let string_of_chars = Der.string_of_chars

let uncons cs =
  match cs with [] -> Error Truncated | c :: rest -> Ok (c, rest)

(* --- prefix integers (section 5.1) ----------------------------------- *)

(* The continuation loop stops after five bytes (shift 28): every value
   a header block can carry fits, and a longer chain is a reject, not
   an overflow. *)
let decode_prefix_int ~prefix cs =
  let prefix = Stdlib.min 8 (Stdlib.max 1 prefix) in
  let cap = (1 lsl prefix) - 1 in
  Result.bind (uncons cs) (fun (b0, r0) ->
      let v = Char.code b0 land cap in
      match () with
      | () when v < cap -> Ok (v, r0)
      | () ->
          let rec go acc shift cs =
            match () with
            | () when shift > 28 -> Error Integer_too_large
            | () ->
                Result.bind (uncons cs) (fun (b, rest) ->
                    let x = Char.code b in
                    let acc = acc + ((x land 0x7f) lsl shift) in
                    match () with
                    | () when x land 0x80 <> 0 -> go acc (shift + 7) rest
                    | () -> Ok (acc, rest))
          in
          go cap 0 r0)

(* --- Huffman code (section 5.2, Appendix B) -------------------------- *)

(* (symbol, bit length, code) per Appendix B; symbol 256 is EOS. *)
let huffman_codes =
  [
    (0, 13, 0x1ff8);
    (1, 23, 0x7fffd8);
    (2, 28, 0xfffffe2);
    (3, 28, 0xfffffe3);
    (4, 28, 0xfffffe4);
    (5, 28, 0xfffffe5);
    (6, 28, 0xfffffe6);
    (7, 28, 0xfffffe7);
    (8, 28, 0xfffffe8);
    (9, 24, 0xffffea);
    (10, 30, 0x3ffffffc);
    (11, 28, 0xfffffe9);
    (12, 28, 0xfffffea);
    (13, 30, 0x3ffffffd);
    (14, 28, 0xfffffeb);
    (15, 28, 0xfffffec);
    (16, 28, 0xfffffed);
    (17, 28, 0xfffffee);
    (18, 28, 0xfffffef);
    (19, 28, 0xffffff0);
    (20, 28, 0xffffff1);
    (21, 28, 0xffffff2);
    (22, 30, 0x3ffffffe);
    (23, 28, 0xffffff3);
    (24, 28, 0xffffff4);
    (25, 28, 0xffffff5);
    (26, 28, 0xffffff6);
    (27, 28, 0xffffff7);
    (28, 28, 0xffffff8);
    (29, 28, 0xffffff9);
    (30, 28, 0xffffffa);
    (31, 28, 0xffffffb);
    (32, 6, 0x14);
    (33, 10, 0x3f8);
    (34, 10, 0x3f9);
    (35, 12, 0xffa);
    (36, 13, 0x1ff9);
    (37, 6, 0x15);
    (38, 8, 0xf8);
    (39, 11, 0x7fa);
    (40, 10, 0x3fa);
    (41, 10, 0x3fb);
    (42, 8, 0xf9);
    (43, 11, 0x7fb);
    (44, 8, 0xfa);
    (45, 6, 0x16);
    (46, 6, 0x17);
    (47, 6, 0x18);
    (48, 5, 0x0);
    (49, 5, 0x1);
    (50, 5, 0x2);
    (51, 6, 0x19);
    (52, 6, 0x1a);
    (53, 6, 0x1b);
    (54, 6, 0x1c);
    (55, 6, 0x1d);
    (56, 6, 0x1e);
    (57, 6, 0x1f);
    (58, 7, 0x5c);
    (59, 8, 0xfb);
    (60, 15, 0x7ffc);
    (61, 6, 0x20);
    (62, 12, 0xffb);
    (63, 10, 0x3fc);
    (64, 13, 0x1ffa);
    (65, 6, 0x21);
    (66, 7, 0x5d);
    (67, 7, 0x5e);
    (68, 7, 0x5f);
    (69, 7, 0x60);
    (70, 7, 0x61);
    (71, 7, 0x62);
    (72, 7, 0x63);
    (73, 7, 0x64);
    (74, 7, 0x65);
    (75, 7, 0x66);
    (76, 7, 0x67);
    (77, 7, 0x68);
    (78, 7, 0x69);
    (79, 7, 0x6a);
    (80, 7, 0x6b);
    (81, 7, 0x6c);
    (82, 7, 0x6d);
    (83, 7, 0x6e);
    (84, 7, 0x6f);
    (85, 7, 0x70);
    (86, 7, 0x71);
    (87, 7, 0x72);
    (88, 8, 0xfc);
    (89, 7, 0x73);
    (90, 8, 0xfd);
    (91, 13, 0x1ffb);
    (92, 19, 0x7fff0);
    (93, 13, 0x1ffc);
    (94, 14, 0x3ffc);
    (95, 6, 0x22);
    (96, 15, 0x7ffd);
    (97, 5, 0x3);
    (98, 6, 0x23);
    (99, 5, 0x4);
    (100, 6, 0x24);
    (101, 5, 0x5);
    (102, 6, 0x25);
    (103, 6, 0x26);
    (104, 6, 0x27);
    (105, 5, 0x6);
    (106, 7, 0x74);
    (107, 7, 0x75);
    (108, 6, 0x28);
    (109, 6, 0x29);
    (110, 6, 0x2a);
    (111, 5, 0x7);
    (112, 6, 0x2b);
    (113, 7, 0x76);
    (114, 6, 0x2c);
    (115, 5, 0x8);
    (116, 5, 0x9);
    (117, 6, 0x2d);
    (118, 7, 0x77);
    (119, 7, 0x78);
    (120, 7, 0x79);
    (121, 7, 0x7a);
    (122, 7, 0x7b);
    (123, 15, 0x7ffe);
    (124, 11, 0x7fc);
    (125, 14, 0x3ffd);
    (126, 13, 0x1ffd);
    (127, 28, 0xffffffc);
    (128, 20, 0xfffe6);
    (129, 22, 0x3fffd2);
    (130, 20, 0xfffe7);
    (131, 20, 0xfffe8);
    (132, 22, 0x3fffd3);
    (133, 22, 0x3fffd4);
    (134, 22, 0x3fffd5);
    (135, 23, 0x7fffd9);
    (136, 22, 0x3fffd6);
    (137, 23, 0x7fffda);
    (138, 23, 0x7fffdb);
    (139, 23, 0x7fffdc);
    (140, 23, 0x7fffdd);
    (141, 23, 0x7fffde);
    (142, 24, 0xffffeb);
    (143, 23, 0x7fffdf);
    (144, 24, 0xffffec);
    (145, 24, 0xffffed);
    (146, 22, 0x3fffd7);
    (147, 23, 0x7fffe0);
    (148, 24, 0xffffee);
    (149, 23, 0x7fffe1);
    (150, 23, 0x7fffe2);
    (151, 23, 0x7fffe3);
    (152, 23, 0x7fffe4);
    (153, 21, 0x1fffdc);
    (154, 22, 0x3fffd8);
    (155, 23, 0x7fffe5);
    (156, 22, 0x3fffd9);
    (157, 23, 0x7fffe6);
    (158, 23, 0x7fffe7);
    (159, 24, 0xffffef);
    (160, 22, 0x3fffda);
    (161, 21, 0x1fffdd);
    (162, 20, 0xfffe9);
    (163, 22, 0x3fffdb);
    (164, 22, 0x3fffdc);
    (165, 23, 0x7fffe8);
    (166, 23, 0x7fffe9);
    (167, 21, 0x1fffde);
    (168, 23, 0x7fffea);
    (169, 22, 0x3fffdd);
    (170, 22, 0x3fffde);
    (171, 24, 0xfffff0);
    (172, 21, 0x1fffdf);
    (173, 22, 0x3fffdf);
    (174, 23, 0x7fffeb);
    (175, 23, 0x7fffec);
    (176, 21, 0x1fffe0);
    (177, 21, 0x1fffe1);
    (178, 22, 0x3fffe0);
    (179, 21, 0x1fffe2);
    (180, 23, 0x7fffed);
    (181, 22, 0x3fffe1);
    (182, 23, 0x7fffee);
    (183, 23, 0x7fffef);
    (184, 20, 0xfffea);
    (185, 22, 0x3fffe2);
    (186, 22, 0x3fffe3);
    (187, 22, 0x3fffe4);
    (188, 23, 0x7ffff0);
    (189, 22, 0x3fffe5);
    (190, 22, 0x3fffe6);
    (191, 23, 0x7ffff1);
    (192, 26, 0x3ffffe0);
    (193, 26, 0x3ffffe1);
    (194, 20, 0xfffeb);
    (195, 19, 0x7fff1);
    (196, 22, 0x3fffe7);
    (197, 23, 0x7ffff2);
    (198, 22, 0x3fffe8);
    (199, 25, 0x1ffffec);
    (200, 26, 0x3ffffe2);
    (201, 26, 0x3ffffe3);
    (202, 26, 0x3ffffe4);
    (203, 27, 0x7ffffde);
    (204, 27, 0x7ffffdf);
    (205, 26, 0x3ffffe5);
    (206, 24, 0xfffff1);
    (207, 25, 0x1ffffed);
    (208, 19, 0x7fff2);
    (209, 21, 0x1fffe3);
    (210, 26, 0x3ffffe6);
    (211, 27, 0x7ffffe0);
    (212, 27, 0x7ffffe1);
    (213, 26, 0x3ffffe7);
    (214, 27, 0x7ffffe2);
    (215, 24, 0xfffff2);
    (216, 21, 0x1fffe4);
    (217, 21, 0x1fffe5);
    (218, 26, 0x3ffffe8);
    (219, 26, 0x3ffffe9);
    (220, 28, 0xffffffd);
    (221, 27, 0x7ffffe3);
    (222, 27, 0x7ffffe4);
    (223, 27, 0x7ffffe5);
    (224, 20, 0xfffec);
    (225, 24, 0xfffff3);
    (226, 20, 0xfffed);
    (227, 21, 0x1fffe6);
    (228, 22, 0x3fffe9);
    (229, 21, 0x1fffe7);
    (230, 21, 0x1fffe8);
    (231, 23, 0x7ffff3);
    (232, 22, 0x3fffea);
    (233, 22, 0x3fffeb);
    (234, 25, 0x1ffffee);
    (235, 25, 0x1ffffef);
    (236, 24, 0xfffff4);
    (237, 24, 0xfffff5);
    (238, 26, 0x3ffffea);
    (239, 23, 0x7ffff4);
    (240, 26, 0x3ffffeb);
    (241, 27, 0x7ffffe6);
    (242, 26, 0x3ffffec);
    (243, 26, 0x3ffffed);
    (244, 27, 0x7ffffe7);
    (245, 27, 0x7ffffe8);
    (246, 27, 0x7ffffe9);
    (247, 27, 0x7ffffea);
    (248, 27, 0x7ffffeb);
    (249, 28, 0xffffffe);
    (250, 27, 0x7ffffec);
    (251, 27, 0x7ffffed);
    (252, 27, 0x7ffffee);
    (253, 27, 0x7ffffef);
    (254, 27, 0x7fffff0);
    (255, 26, 0x3ffffee);
    (256, 30, 0x3fffffff);
  ]

type trie = Empty | Leaf of int | Node of trie * trie

(* Insert one code, most significant bit first. None on any conflict: a
   leaf met early, or a code that ends on a node. *)
let insert ~sym ~len ~code trie =
  let rec go depth t =
    match () with
    | () when depth = len -> (
        match t with Empty -> Some (Leaf sym) | Leaf _ | Node _ -> None)
    | () -> (
        let bit = (code lsr (len - depth - 1)) land 1 in
        match t with
        | Leaf _ -> None
        | Empty ->
            go (depth + 1) Empty
            |> Option.map (fun child ->
                   if bit = 0 then Node (child, Empty) else Node (Empty, child))
        | Node (l, r) ->
            if bit = 0 then
              go (depth + 1) l |> Option.map (fun l' -> Node (l', r))
            else go (depth + 1) r |> Option.map (fun r' -> Node (l, r')))
  in
  go 0 trie

let huffman_trie =
  List.fold_left
    (fun acc (sym, len, code) -> Option.bind acc (insert ~sym ~len ~code))
    (Some Empty) huffman_codes

(* Walk the trie bit by bit. After the last full code, the residue must
   be at most seven bits and all ones: the longest permitted padding,
   a strict prefix of EOS (section 5.2). A decoded EOS is a reject. *)
let decode_huffman s =
  Result.bind (Option.to_result ~none:Table_broken huffman_trie) (fun root ->
      let step st bit =
        Result.bind st (fun (node, depth, ones, acc) ->
            Result.bind
              (match node with
              | Node (l, r) -> Ok (if bit = 0 then l else r)
              | Leaf _ | Empty -> Error Bad_padding)
              (fun child ->
                match child with
                | Leaf sym ->
                    if sym = 256 then Error Eos_in_string
                    else Ok (root, 0, true, sym :: acc)
                | Node _ -> Ok (child, depth + 1, ones && bit = 1, acc)
                | Empty -> Error Bad_padding))
      in
      Result.bind
        (Der.bytes_of_string s
        |> List.fold_left
             (fun st c ->
               List.fold_left
                 (fun st i -> step st ((Char.code c lsr i) land 1))
                 st
                 [ 7; 6; 5; 4; 3; 2; 1; 0 ])
             (Ok (root, 0, true, [])))
        (fun (_, depth, ones, acc) ->
          match () with
          | () when depth <= 7 && ones ->
              Ok (List.rev acc |> List.fold_left (fun s sym -> s ^ H2.byte sym) "")
          | () -> Error Bad_padding))

let huffman_code_of sym = List.find_opt (fun (s, _, _) -> s = sym) huffman_codes

let rec drain out buf nbits =
  match () with
  | () when nbits >= 8 -> drain (out ^ H2.byte (buf lsr (nbits - 8))) buf (nbits - 8)
  | () -> (out, buf land ((1 lsl nbits) - 1), nbits)

(* The encoder side, used by the tests to pin the table by roundtrip.
   None cannot happen on byte input: symbols 0..255 are all present. *)
let encode_huffman s =
  Der.bytes_of_string s
  |> List.fold_left
       (fun acc c ->
         Option.bind acc (fun (out, buf, nbits) ->
             huffman_code_of (Char.code c)
             |> Option.map (fun (_, len, code) ->
                    drain out ((buf lsl len) lor code) (nbits + len))))
       (Some ("", 0, 0))
  |> Option.map (fun (out, buf, nbits) ->
         match () with
         | () when nbits = 0 -> out
         | () -> out ^ H2.byte ((buf lsl (8 - nbits)) lor ((1 lsl (8 - nbits)) - 1)))

(* --- static table (section 2.3.1, Appendix A) ------------------------ *)

let static_table =
  [
    (":authority", "");
    (":method", "GET");
    (":method", "POST");
    (":path", "/");
    (":path", "/index.html");
    (":scheme", "http");
    (":scheme", "https");
    (":status", "200");
    (":status", "204");
    (":status", "206");
    (":status", "304");
    (":status", "400");
    (":status", "404");
    (":status", "500");
    ("accept-charset", "");
    ("accept-encoding", "gzip, deflate");
    ("accept-language", "");
    ("accept-ranges", "");
    ("accept", "");
    ("access-control-allow-origin", "");
    ("age", "");
    ("allow", "");
    ("authorization", "");
    ("cache-control", "");
    ("content-disposition", "");
    ("content-encoding", "");
    ("content-language", "");
    ("content-length", "");
    ("content-location", "");
    ("content-range", "");
    ("content-type", "");
    ("cookie", "");
    ("date", "");
    ("etag", "");
    ("expect", "");
    ("expires", "");
    ("from", "");
    ("host", "");
    ("if-match", "");
    ("if-modified-since", "");
    ("if-none-match", "");
    ("if-range", "");
    ("if-unmodified-since", "");
    ("last-modified", "");
    ("link", "");
    ("location", "");
    ("max-forwards", "");
    ("proxy-authenticate", "");
    ("proxy-authorization", "");
    ("range", "");
    ("referer", "");
    ("refresh", "");
    ("retry-after", "");
    ("server", "");
    ("set-cookie", "");
    ("strict-transport-security", "");
    ("transfer-encoding", "");
    ("user-agent", "");
    ("vary", "");
    ("via", "");
    ("www-authenticate", "");
  ]

let static_len = List.length static_table

(* --- dynamic table (section 4) --------------------------------------- *)

type dyn = { entries : (string * string) list; size : int; cap : int }

let empty_dyn ~cap = { entries = []; size = 0; cap }
let entry_size (name, value) = String.length name + String.length value + 32

let rec evict d =
  match () with
  | () when d.size <= d.cap -> d
  | () -> (
      match List.rev d.entries with
      | [] -> { d with size = 0 }
      | last :: rev_rest ->
          evict
            {
              d with
              entries = List.rev rev_rest;
              size = d.size - entry_size last;
            })

(* An entry larger than the whole table empties it and is not inserted
   (section 4.4). *)
let dyn_insert d hv =
  let s = entry_size hv in
  match () with
  | () when s > d.cap -> { d with entries = []; size = 0 }
  | () -> evict { d with entries = hv :: d.entries; size = d.size + s }

let dyn_resize d cap = evict { d with cap }

(* One index space: 1..61 static, 62 up dynamic, newest first
   (section 2.3.3). Zero and out of range are None. *)
let lookup d i =
  match () with
  | () when i >= 1 && i <= static_len -> List.nth_opt static_table (i - 1)
  | () when i > static_len -> List.nth_opt d.entries (i - 1 - static_len)
  | () -> None

(* --- string literals (section 5.2) ----------------------------------- *)

let decode_string cs =
  Result.bind (uncons cs) (fun (b0, _) ->
      let huff = Char.code b0 land 0x80 <> 0 in
      Result.bind (decode_prefix_int ~prefix:7 cs) (fun (len, rest) ->
          Result.bind
            (Der.take len rest |> Option.to_result ~none:Truncated)
            (fun (body, rest) ->
              let raw = string_of_chars body in
              if huff then decode_huffman raw |> Result.map (fun s -> (s, rest))
              else Ok (raw, rest))))

(* --- field representations (section 6) ------------------------------- *)

(* One literal field, shared by the three literal forms: a name index in
   the given prefix, or zero then a literal name, then the value. *)
let decode_literal ~prefix d cs =
  Result.bind (decode_prefix_int ~prefix cs) (fun (i, rest) ->
      match () with
      | () when i = 0 ->
          Result.bind (decode_string rest) (fun (name, r1) ->
              decode_string r1 |> Result.map (fun (value, r2) -> ((name, value), r2)))
      | () ->
          Result.bind
            (lookup d i |> Option.to_result ~none:(Bad_index i))
            (fun (name, _) ->
              decode_string rest |> Result.map (fun (value, r1) -> ((name, value), r1))))

(* Decode one whole header block. Returns the fields in order and the
   dynamic table after the block. max_cap bounds a table-size update:
   the SETTINGS_HEADER_TABLE_SIZE this side advertised (section 4.2).
   The never-indexed form (0001) decodes like the without-indexing form
   (0000); the marker only constrains re-encoding, which we do not do. *)
let decode_header_block ~max_cap d s =
  let rec go acc d cs =
    match cs with
    | [] -> Ok (List.rev acc, d)
    | c :: _ -> (
        let b = Char.code c in
        match () with
        | () when b land 0x80 <> 0 ->
            Result.bind (decode_prefix_int ~prefix:7 cs) (fun (i, rest) ->
                Result.bind
                  (lookup d i |> Option.to_result ~none:(Bad_index i))
                  (fun hv -> go (hv :: acc) d rest))
        | () when b land 0xc0 = 0x40 ->
            Result.bind (decode_literal ~prefix:6 d cs) (fun (hv, rest) ->
                go (hv :: acc) (dyn_insert d hv) rest)
        | () when b land 0xe0 = 0x20 ->
            Result.bind (decode_prefix_int ~prefix:5 cs) (fun (cap, rest) ->
                match () with
                | () when cap > max_cap ->
                    Error (Table_update_too_large { requested = cap; cap = max_cap })
                | () -> go acc (dyn_resize d cap) rest)
        | () ->
            Result.bind (decode_literal ~prefix:4 d cs) (fun (hv, rest) ->
                go (hv :: acc) d rest))
  in
  go [] d (Der.bytes_of_string s)
