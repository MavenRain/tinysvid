(* Signature verification backend as a module type (M13). The core stays
   stdlib-only: real Ed25519 and ECDSA-P256 implementations live outside
   the library and plug into Chain.Make. The core names the algorithm,
   carries the byte inputs, and trusts the backend's boolean verdict. *)

type algorithm = Ed25519 | Ecdsa_p256_sha256

(* signatureAlgorithm OIDs as raw content octets: id-Ed25519 1.3.101.112
   (RFC 8410 section 3), ecdsa-with-SHA256 1.2.840.10045.4.3.2 (RFC 5758
   section 3.2). *)
let ed25519_oid = "\x2b\x65\x70"

let ecdsa_p256_sha256_oid = "\x2a\x86\x48\xce\x3d\x04\x03\x02"

let algorithm_of_oid o =
  match () with
  | () when String.equal o ed25519_oid -> Some Ed25519
  | () when String.equal o ecdsa_p256_sha256_oid -> Some Ecdsa_p256_sha256
  | () -> None

module type S = sig
  (* verify ~alg ~spki ~message ~signature: spki is the signer's
     SubjectPublicKeyInfo as raw DER, message the raw tbsCertificate
     octets, signature the signatureValue BIT STRING content with the
     unused-bits octet already stripped (and required zero). A backend
     must return false, never diverge, on malformed key or signature
     bytes. *)
  val verify :
    alg:algorithm -> spki:string -> message:string -> signature:string -> bool
end
