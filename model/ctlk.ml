(* CTL operators as least/greatest fixpoints of monotone maps on Sub(1). *)

let ef ~post univ phi = Sub.lfp (fun x -> Sub.join phi (Modal.ex ~post univ x))

let af ~post univ phi = Sub.lfp (fun x -> Sub.join phi (Modal.ax ~post univ x))

let eg ~post univ phi = Sub.gfp univ (fun x -> Sub.meet phi (Modal.ex ~post univ x))

let ag ~post univ phi = Sub.gfp univ (fun x -> Sub.meet phi (Modal.ax ~post univ x))

let eu ~post univ phi psi =
  Sub.lfp (fun x -> Sub.join psi (Sub.meet phi (Modal.ex ~post univ x)))
