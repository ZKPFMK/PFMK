#pragma once

#include <memory>

#include "./context.h"
#include "./image_com.h"
#include "./r1cs_pub.h"
#include "circuit/vgg16/vgg16.h"

namespace clink::vgg16 {

struct ReluBnProof {
  std::vector<G1> com_t0, com_t2, com_w;
  std::array<G1, 2> com_ab;

  argument::A1::Proof sm_proof;

  bool operator==(ReluBnProof const& b) const {
    return com_w == b.com_w && com_t0 == b.com_t0 && com_t2 == b.com_t2 && com_ab == b.com_ab;
  }

  bool operator!=(ReluBnProof const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.ReluBnProof", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("w", com_w), ("p", sm_proof));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.ReluBnProof", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("w", com_w), ("p", sm_proof));
  }
};

// 0: combined_in
// 1: combined_out
// even: in
// odd: out
inline void ReluBnBuildImages(ProveContext const& context,
                              std::vector<Fr> & combined_in_x,
                              std::vector<Fr> & combined_out_x) {
  Tick tick(__FN__);
  auto const& const_images = context.const_images();
  combined_in_x.resize(ReluBn_offsets.back());
  combined_out_x.resize(ReluBn_offsets.back());
  for (size_t order = 0; order < kReluBnLayers.size(); ++order) {
    auto layer = kReluBnLayers[order];
    std::copy(const_images[layer]->data.begin(), const_images[layer]->data.end(), combined_in_x.begin() + ReluBn_offsets[order]);
    std::copy(const_images[layer + 1]->data.begin(), const_images[layer + 1]->data.end(), combined_out_x.begin() + ReluBn_offsets[order]);
  }
}

}  // namespace clink::vgg16