(* SPIFFE trust-domain name, per SPIFFE-ID spec section 2.1:
   1..255 characters from [a-z0-9._-]. *)

type t = Td of string

type error = Empty | Too_long of int | Bad_char of char

let max_len = 255

let is_td_char c =
  (c >= 'a' && c <= 'z')
  || (c >= '0' && c <= '9')
  || Char.equal c '.' || Char.equal c '_' || Char.equal c '-'

let parse s =
  let n = String.length s in
  match () with
  | () when n = 0 -> Error Empty
  | () when n > max_len -> Error (Too_long n)
  | () ->
      String.fold_left
        (fun acc c ->
          Result.bind acc (fun () ->
              if is_td_char c then Ok () else Error (Bad_char c)))
        (Ok ()) s
      |> Result.map (fun () -> Td s)

let to_string (Td s) = s

let equal (Td a) (Td b) = String.equal a b

let error_to_string e =
  match e with
  | Empty -> "empty"
  | Too_long n -> Printf.sprintf "too_long:%d" n
  | Bad_char c -> Printf.sprintf "bad_char:%c" c
