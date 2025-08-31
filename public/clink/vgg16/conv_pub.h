// #pragma once

#include "argument/a1.h";

namespace clink::vgg16 {
struct ConvProof {
  std::vector<G1> com_t0, com_t2;
  std::array<G1,2> com_u;
  argument::A1::Proof sm_proof;

  bool operator==(ConvProof const& b) const {
    return com_t0 == b.com_t0 && sm_proof == b.sm_proof &&
           com_t2 == b.com_t2 && com_u == b.com_u;
  }

  bool operator!=(ConvProof const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.ConvProof", ("0", com_t0), ("2", com_t2),
                       ("u", com_u), ("p", sm_proof));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.ConvProof", ("0", com_t0), ("2", com_t2),
                       ("u", com_u), ("p", sm_proof));
  }
};
}  // namespace clink::vgg16