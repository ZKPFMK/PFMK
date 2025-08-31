#pragma once

#include <memory>

#include "./image_com.h"
#include "./para_com.h"
#include "./r1cs_pub.h"
#include "circuit/vgg16/vgg16.h"

namespace clink::vgg16 {

struct PoolingProof {
  std::vector<G1> com_t0, com_t2, com_w;
  std::array<G1, 2> com_ab;

  argument::A1::Proof sm_proof;

  bool operator==(PoolingProof const& b) const {
    return com_w == b.com_w && com_t0 == b.com_t0 && com_t2 == b.com_t2 && com_ab == b.com_ab;
  }

  bool operator!=(PoolingProof const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.PoolingProof", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("w", com_w), ("p", sm_proof));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.PoolingProof", ("0", com_t0), ("2", com_t2),
                       ("c", com_ab), ("w", com_w), ("p", sm_proof));
  }
};

inline void PoolingAbcdToData(std::vector<Fr> const& a,
                              std::vector<Fr> const& b,
                              std::vector<Fr> const& c,
                              std::vector<Fr> const& d,
                              std::vector<std::vector<Fr>> & ret) {
  Tick tick(__FN__);
  size_t total_size = 0;
  for (size_t i = 0; i < kPoolingLayers.size(); ++i) {
    total_size += kImageInfos[kPoolingLayers[i]].size();
  }

  assert(a.size() == b.size() && b.size() == c.size() && c.size() == d.size() && total_size == a.size() << 2);
  ret.resize(kPoolingLayers.size());

  size_t offset = 0;
  for (size_t l = 0; l < kPoolingLayers.size(); ++l) {
    auto C = kImageInfos[kPoolingLayers[l]].C;
    auto D = kImageInfos[kPoolingLayers[l]].D;
    auto DD = D * D;
    auto CDD = C * DD;
    auto D_2 = D / 2;
    auto DD_4 = DD / 4;
    ret[l].resize(CDD);
    for (size_t i = 0; i < C; ++i) {
      for (size_t j = 0; j < D_2; ++j) {
        for (size_t k = 0; k < D_2; ++k) {
          auto idx = offset + (j * D_2 + k) * C + i;
          ret[l][(2 * j * D + 2 * k) * C + i] = a[idx];
          ret[l][(2 * j * D + 2 * k + 1) * C + i] = b[idx];
          ret[l][((2 * j + 1) * D + 2 * k) * C + i] = c[idx];
          ret[l][((2 * j + 1) * D + 2 * k + 1) * C + i] = d[idx];
        }
      }
    }
    offset += C * DD_4;
  }
}

inline void PoolingImageToAbcd(ProveContext const& context,
                               std::vector<Fr> & a,
                               std::vector<Fr> & b,
                               std::vector<Fr> & c,
                               std::vector<Fr> & d) {
  Tick tick(__FN__);
  size_t total_size = 0;
  for (size_t i = 0; i < kPoolingLayers.size(); ++i) {
    total_size += context.const_images()[kPoolingLayers[i]]->data.size();
  }

  a.resize(total_size / 4);
  b.resize(total_size / 4);
  c.resize(total_size / 4);
  d.resize(total_size / 4);

  size_t offset = 0;
  for (size_t l = 0; l < kPoolingLayers.size(); ++l) {
    auto C = context.const_images()[kPoolingLayers[l]]->C();
    auto D = context.const_images()[kPoolingLayers[l]]->D();
    auto DD = D * D;
    auto D_2 = D / 2;
    auto DD_4 = DD / 4;
    auto const& x = context.const_images()[kPoolingLayers[l]]->data;
    for (size_t i = 0; i < C; ++i) {
      for (size_t j = 0; j < D_2; ++j) {
        for (size_t k = 0; k < D_2; ++k) {
          auto idx = offset + (j * D_2 + k) * C + i;
          a[idx] = x[(2 * j * D + 2 * k) * C + i];
          b[idx] = x[(2 * j * D + 2 * k + 1) * C + i];
          c[idx] = x[((2 * j + 1) * D + 2 * k) * C + i];
          d[idx] = x[((2 * j + 1) * D + 2 * k + 1) * C + i];
        }
      }
    }
    offset += C * DD_4;
  }
}
}  // namespace clink::vgg16