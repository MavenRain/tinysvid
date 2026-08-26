(* SPIFFE ID: spiffe://<trust-domain>[/<segment>]*, per SPIFFE-ID spec
   sections 2.2-2.3. Segments take [a-zA-Z0-9._-], never "." or "..",
   never empty; the whole ID takes at most 2048 bytes. *)

type t = { td : Trust_domain.t; segments : string list }

type error =
  | Bad_scheme
  | Trust_domain_error of Trust_domain.error
  | Empty_segment
  | Dot_segment of string
  | Bad_segment_char of char
  | Too_long of int

let scheme = "spiffe://"

let max_len = 2048

let is_segment_char c =
  (c >= 'a' && c <= 'z')
  || (c >= 'A' && c <= 'Z')
  || (c >= '0' && c <= '9')
  || Char.equal c '.' || Char.equal c '_' || Char.equal c '-'

let check_segment seg =
  match () with
  | () when String.length seg = 0 -> Error Empty_segment
  | () when String.equal seg "." || String.equal seg ".." ->
      Error (Dot_segment seg)
  | () ->
      String.fold_left
        (fun acc c ->
          Result.bind acc (fun () ->
              if is_segment_char c then Ok () else Error (Bad_segment_char c)))
        (Ok ()) seg
      |> Result.map (fun () -> seg)

let check_segments segs =
  List.fold_left
    (fun acc seg ->
      Result.bind acc (fun l ->
          check_segment seg |> Result.map (fun s -> s :: l)))
    (Ok []) segs
  |> Result.map List.rev

let parse s =
  let n = String.length s in
  let plen = String.length scheme in
  match () with
  | () when n > max_len -> Error (Too_long n)
  | () when not (String.starts_with ~prefix:scheme s) -> Error Bad_scheme
  | () -> (
      let rest = String.to_seq s |> Seq.drop plen |> String.of_seq in
      match String.split_on_char '/' rest with
      | [] -> Error Bad_scheme
      | td_str :: segs ->
          Result.bind
            (Trust_domain.parse td_str
            |> Result.map_error (fun e -> Trust_domain_error e))
            (fun td ->
              check_segments segs |> Result.map (fun segments -> { td; segments })))

let trust_domain id = id.td

let segments id = id.segments

let to_string id =
  scheme ^ Trust_domain.to_string id.td
  ^ List.fold_left (fun acc seg -> acc ^ "/" ^ seg) "" id.segments

let equal a b =
  Trust_domain.equal a.td b.td
  && List.equal String.equal a.segments b.segments

let error_to_string e =
  match e with
  | Bad_scheme -> "bad_scheme"
  | Trust_domain_error te -> "trust_domain:" ^ Trust_domain.error_to_string te
  | Empty_segment -> "empty_segment"
  | Dot_segment s -> "dot_segment:" ^ s
  | Bad_segment_char c -> Printf.sprintf "bad_segment_char:%c" c
  | Too_long n -> Printf.sprintf "too_long:%d" n
