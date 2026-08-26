(* M22: minimal HTTP/2 framing for one client-streaming RPC (RFC 9113
   section 4), plus the gRPC message envelope and the request-side
   header-block encoder (RFC 7541). Pure string-in, string-out codecs:
   input becomes a char list once (the Der idiom) and every step consumes
   from the head, so no index arithmetic and no partial String access.
   Decoding of received header blocks (HPACK integer and string readers,
   dynamic table) is deferred to M24; this module only emits them. *)

type frame_type =
  | Data
  | Headers
  | Priority
  | Rst_stream
  | Settings
  | Push_promise
  | Ping
  | Goaway
  | Window_update
  | Continuation
  | Unknown of int

let frame_type_to_byte t =
  match t with
  | Data -> 0x0
  | Headers -> 0x1
  | Priority -> 0x2
  | Rst_stream -> 0x3
  | Settings -> 0x4
  | Push_promise -> 0x5
  | Ping -> 0x6
  | Goaway -> 0x7
  | Window_update -> 0x8
  | Continuation -> 0x9
  | Unknown b -> b land 0xff

let frame_type_of_byte b =
  match () with
  | () when b = 0x0 -> Data
  | () when b = 0x1 -> Headers
  | () when b = 0x2 -> Priority
  | () when b = 0x3 -> Rst_stream
  | () when b = 0x4 -> Settings
  | () when b = 0x5 -> Push_promise
  | () when b = 0x6 -> Ping
  | () when b = 0x7 -> Goaway
  | () when b = 0x8 -> Window_update
  | () when b = 0x9 -> Continuation
  | () -> Unknown (b land 0xff)

type frame = { typ : frame_type; flags : int; stream_id : int; payload : string }

type error =
  | Payload_too_long of int
  | Bad_stream_id of int
  | Bad_flags of int
  | Incomplete of { need : int; have : int }
  | Settings_length of int
  | Bad_envelope_flag of int

let error_to_string e =
  match e with
  | Payload_too_long n -> Printf.sprintf "payload_too_long:%d" n
  | Bad_stream_id n -> Printf.sprintf "bad_stream_id:%d" n
  | Bad_flags n -> Printf.sprintf "bad_flags:%d" n
  | Incomplete { need; have } -> Printf.sprintf "incomplete:%d:%d" need have
  | Settings_length n -> Printf.sprintf "settings_length:%d" n
  | Bad_envelope_flag n -> Printf.sprintf "bad_envelope_flag:%d" n

(* The HTTP/2 default SETTINGS_MAX_FRAME_SIZE (RFC 9113 section 6.5.2).
   Until a peer raises it, larger payloads are a protocol error, so the
   encoder never emits one. *)
let max_frame_payload = 16384

let max_stream_id = 0x7fffffff

let client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

(* --- byte emission (the test_chain byte_table idiom) ----------------- *)

let byte_table =
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

(* One byte of output; the low eight bits of n. The land keeps Seq.drop
   in range, so the none branch is unreachable and total anyway. *)
let byte n =
  String.to_seq byte_table
  |> Seq.drop (n land 0xff)
  |> Seq.uncons
  |> Option.fold ~none:"" ~some:(fun (c, _) -> String.make 1 c)

let be16 n = byte (n lsr 8) ^ byte n
let be24 n = byte (n lsr 16) ^ byte (n lsr 8) ^ byte n
let be32 n = byte (n lsr 24) ^ byte (n lsr 16) ^ byte (n lsr 8) ^ byte n

(* --- byte consumption ------------------------------------------------ *)

let string_of_chars l = List.to_seq l |> String.of_seq

let be_int bytes =
  List.fold_left (fun acc c -> (acc lsl 8) lor Char.code c) 0 bytes

(* First n bytes as a big-endian int plus the rest; None when short. *)
let take_be n cs =
  Der.take n cs |> Option.map (fun (bs, rest) -> (be_int bs, rest))

(* --- frame codec ----------------------------------------------------- *)

let encode_frame f =
  let plen = String.length f.payload in
  match () with
  | () when plen > max_frame_payload -> Error (Payload_too_long plen)
  | () when f.stream_id < 0 || f.stream_id > max_stream_id ->
      Error (Bad_stream_id f.stream_id)
  | () when f.flags < 0 || f.flags > 0xff -> Error (Bad_flags f.flags)
  | () ->
      Ok
        (be24 plen
        ^ byte (frame_type_to_byte f.typ)
        ^ byte f.flags ^ be32 f.stream_id ^ f.payload)

(* The 9-byte header split: 24-bit length, type byte, flags byte, 31-bit
   stream id. The take chain cannot run short on a 9-byte list, so the
   caller maps a None to the same Incomplete it raised for the take 9. *)
let split_header hdr =
  Option.bind (take_be 3 hdr) (fun (plen, r1) ->
      Option.bind (take_be 1 r1) (fun (tb, r2) ->
          Option.bind (take_be 1 r2) (fun (flags, r3) ->
              take_be 4 r3
              |> Option.map (fun (sid, _) ->
                     (* the top bit of the stream id is reserved: masked
                        off on decode (RFC 9113 section 4.1) *)
                     (plen, tb, flags, sid land max_stream_id)))))

let decode_frame s =
  let cs = Der.bytes_of_string s in
  let have = List.length cs in
  Result.bind
    (Der.take 9 cs |> Option.to_result ~none:(Incomplete { need = 9; have }))
    (fun (hdr, rest) ->
      Result.bind
        (split_header hdr
        |> Option.to_result ~none:(Incomplete { need = 9; have }))
        (fun (plen, tb, flags, stream_id) ->
          Der.take plen rest
          |> Option.to_result ~none:(Incomplete { need = 9 + plen; have })
          |> Result.map (fun (pay, remaining) ->
                 ( {
                     typ = frame_type_of_byte tb;
                     flags;
                     stream_id;
                     payload = string_of_chars pay;
                   },
                   string_of_chars remaining ))))

(* --- SETTINGS payload codec (RFC 9113 section 6.5.1) ----------------- *)

(* Six bytes per setting: 16-bit id, 32-bit value, big-endian. Ids and
   values are masked to their field widths by the byte emitters. *)
let encode_settings pairs =
  List.fold_left (fun acc (id, v) -> acc ^ be16 id ^ be32 v) "" pairs

let decode_settings s =
  let n = String.length s in
  match () with
  | () when n mod 6 <> 0 -> Error (Settings_length n)
  | () ->
      let rec go acc cs =
        match cs with
        | [] -> Ok (List.rev acc)
        | _ :: _ ->
            (* the multiple-of-6 gate above makes a short take here
               unreachable, so the None maps to the same reject *)
            Result.bind
              (Option.bind (take_be 2 cs) (fun (id, r1) ->
                   take_be 4 r1 |> Option.map (fun (v, r2) -> (id, v, r2)))
              |> Option.to_result ~none:(Settings_length n))
              (fun (id, v, rest) -> go ((id, v) :: acc) rest)
      in
      go [] (Der.bytes_of_string s)

let settings_initial = { typ = Settings; flags = 0; stream_id = 0; payload = "" }
let settings_ack = { typ = Settings; flags = 0x1; stream_id = 0; payload = "" }

(* --- gRPC message envelope ------------------------------------------- *)

(* One flag byte (0 plain, 1 compressed), 4-byte big-endian body length,
   body. Any other flag byte is a typed reject on both sides. *)
let encode_envelope ~flag body =
  match () with
  | () when flag <> 0 && flag <> 1 -> Error (Bad_envelope_flag flag)
  | () -> Ok (byte flag ^ be32 (String.length body) ^ body)

let decode_envelope s =
  let cs = Der.bytes_of_string s in
  let have = List.length cs in
  Result.bind
    (Der.take 5 cs |> Option.to_result ~none:(Incomplete { need = 5; have }))
    (fun (hdr, rest) ->
      Result.bind
        (Option.bind (take_be 1 hdr) (fun (flag, r1) ->
             take_be 4 r1 |> Option.map (fun (len, _) -> (flag, len)))
        |> Option.to_result ~none:(Incomplete { need = 5; have }))
        (fun (flag, len) ->
          match () with
          | () when flag <> 0 && flag <> 1 -> Error (Bad_envelope_flag flag)
          | () ->
              Der.take len rest
              |> Option.to_result ~none:(Incomplete { need = 5 + len; have })
              |> Result.map (fun (body, tl) ->
                     (flag, string_of_chars body, string_of_chars tl))))

(* --- request-side header-block encoder (RFC 7541) -------------------- *)

(* Prefix-integer encoder, RFC 7541 section 5.1, with a parameterized
   prefix width in [1, 8]. The pattern bits of the first byte are zero;
   a caller with flag bits ORs them in. Negative input is clamped to 0:
   every caller passes a string length. *)
let encode_prefix_int ~prefix n =
  let prefix = Stdlib.min 8 (Stdlib.max 1 prefix) in
  let n = Stdlib.max 0 n in
  let cap = (1 lsl prefix) - 1 in
  match () with
  | () when n < cap -> byte n
  | () ->
      let rec go acc rem =
        match () with
        | () when rem < 0x80 -> acc ^ byte rem
        | () -> go (acc ^ byte (0x80 lor (rem land 0x7f))) (rem lsr 7)
      in
      go (byte cap) (n - cap)

(* Each header is a literal field without indexing with a new name
   (RFC 7541 section 6.2.2): a 0x00 type byte, then name and value as
   plain literal strings (Huffman bit clear, 7-bit length prefix).
   Decoding of received header blocks is deferred to M24. *)
let encode_header_block headers =
  List.fold_left
    (fun acc (name, value) ->
      acc ^ "\x00"
      ^ encode_prefix_int ~prefix:7 (String.length name)
      ^ name
      ^ encode_prefix_int ~prefix:7 (String.length value)
      ^ value)
    "" headers
