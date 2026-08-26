open Tinysvid

let check name ok =
  Printf.printf "%s %s\n" (if ok then "ok  " else "FAIL") name;
  Bool.to_int (not ok)

let parses_exact s f =
  Der.parse_exact s |> Result.fold ~ok:f ~error:(fun _ -> false)

let rejects_as s name =
  Der.parse_exact s
  |> Result.fold
       ~ok:(fun _ -> false)
       ~error:(fun e -> String.equal (Der.error_to_string e) name)

let is_universal n (node : Der.tlv) =
  (match node.header.cls with
  | Der.Universal -> true
  | Der.Application | Der.Context_specific | Der.Private_class -> false)
  && node.header.number = n

let is_context n (node : Der.tlv) =
  (match node.header.cls with
  | Der.Context_specific -> true
  | Der.Universal | Der.Application | Der.Private_class -> false)
  && node.header.number = n

let () =
  let long_value = String.make 0x80 'x' in
  let failures =
    List.fold_left ( + ) 0
      [
        check "primitive integer"
          (parses_exact "\x02\x01\x05" (fun node ->
               is_universal 2 node
               && (not node.header.constructed)
               && String.equal node.value "\x05"));
        check "empty null value"
          (parses_exact "\x05\x00" (fun node ->
               is_universal 5 node && String.equal node.value ""));
        check "sequence children"
          (parses_exact "\x30\x06\x02\x01\x01\x02\x01\x02" (fun node ->
               node.header.constructed
               && Der.children node
                  |> Result.fold
                       ~ok:(fun kids ->
                         List.length kids = 2
                         && List.for_all (is_universal 2) kids)
                       ~error:(fun _ -> false)));
        check "context-specific constructed tag"
          (parses_exact "\xa0\x03\x02\x01\x07" (fun node ->
               is_context 0 node && node.header.constructed));
        check "long-form 0x81 length"
          (parses_exact ("\x04\x81\x80" ^ long_value) (fun node ->
               is_universal 4 node && String.length node.value = 0x80));
        check "long-form 0x82 length"
          (parses_exact
             ("\x04\x82\x01\x00" ^ String.make 0x100 'y')
             (fun node -> String.length node.value = 0x100));
        check "empty input rejected" (rejects_as "" "truncated_header");
        check "missing length rejected" (rejects_as "\x02" "truncated_length");
        check "truncated length bytes rejected"
          (rejects_as "\x04\x82\x01" "truncated_length");
        check "truncated value rejected"
          (rejects_as "\x02\x03\x01" "truncated_value:3:1");
        check "indefinite length rejected"
          (rejects_as "\x30\x80\x02\x01\x01\x00\x00" "indefinite_length");
        check "non-minimal 0x81 0x7f rejected"
          (rejects_as "\x04\x81\x7f" "non_minimal_length");
        check "leading-zero length rejected"
          (rejects_as ("\x04\x82\x00\x80" ^ long_value) "non_minimal_length");
        check "five length bytes rejected"
          (rejects_as "\x04\x85\x01\x00\x00\x00\x00" "length_overflow:5");
        check "high tag number rejected"
          (rejects_as "\x1f\x81\x00\x01\x00" "high_tag_number");
        check "trailing bytes rejected"
          (rejects_as "\x02\x01\x05\x00" "trailing_bytes:1");
        check "children of primitive rejected"
          (Der.parse_exact "\x02\x01\x05"
          |> Result.fold
               ~ok:(fun node ->
                 Der.children node
                 |> Result.fold
                      ~ok:(fun _ -> false)
                      ~error:(fun e ->
                        String.equal (Der.error_to_string e) "not_constructed"))
               ~error:(fun _ -> false));
        check "parse_all two siblings"
          (Der.parse_all "\x02\x01\x01\x02\x01\x02"
          |> Result.fold
               ~ok:(fun nodes -> List.length nodes = 2)
               ~error:(fun _ -> false));
        check "parse_one returns rest"
          (Der.parse_one "\x02\x01\x05\x04\x00"
          |> Result.fold
               ~ok:(fun (node, rest) ->
                 is_universal 2 node && String.equal rest "\x04\x00")
               ~error:(fun _ -> false));
        check "nested constructed depth two"
          (parses_exact "\x30\x05\xa0\x03\x02\x01\x2a" (fun node ->
               Der.children node
               |> Result.fold
                    ~ok:(fun kids ->
                      List.for_all
                        (fun k ->
                          is_context 0 k
                          && Der.children k
                             |> Result.fold
                                  ~ok:(List.for_all (is_universal 2))
                                  ~error:(fun _ -> false))
                        kids
                      && List.length kids = 1)
                    ~error:(fun _ -> false)));
      ]
  in
  exit (min failures 1)
