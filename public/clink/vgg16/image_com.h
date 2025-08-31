#pragma once

#include "./infer.h"

namespace clink::vgg16 {

struct ImageCommitmentPub {
  std::array<G1, 35> com_x;

  ImageCommitmentPub() {}

  ImageCommitmentPub(std::string const& file) {
    CHECK(YasLoadBin(file, *this), file);
  }

  bool operator==(ImageCommitmentPub const& b) const { return com_x == b.com_x; }

  bool operator!=(ImageCommitmentPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.image.compub", ("x", com_x));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.image.compub", ("x", com_x));
  }
};

  struct ImageCommitmentSec {
    std::array<Fr, 35> r_com_x;

    ImageCommitmentSec() {}

    ImageCommitmentSec(std::string const& file) {
      CHECK(YasLoadBin(file, *this), file);
    }

    bool operator==(ImageCommitmentSec const& b) const { return r_com_x == b.r_com_x; }

    bool operator!=(ImageCommitmentSec const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("vgg16.image.comsec", ("x", r_com_x));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("vgg16.image.comsec", ("x", r_com_x));
    }
  };

//continue
inline void ComputePerImageCommitment(
                std::array<std::unique_ptr<Image>, 35> const& images,
                ImageCommitmentPub& pub, ImageCommitmentSec& sec) {
  Tick tick(__FN__);
  sec.r_com_x[0] = FrZero();
  pub.com_x[0] = G1Zero();
  // 第一个输入的图片为公开值, 无需承诺
  auto parallel_f = [&images, &pub, &sec](int64_t i) {
    auto const& x = (*images[i]).data;
    auto & com_x = pub.com_x[i];
    auto & r_com_x = sec.r_com_x[i];
    r_com_x = FrRand();
    com_x = pc::ComputeCom(x, r_com_x);
  };
  parallel::For<int64_t>(1, images.size(), parallel_f);
}

}  // namespace clink::vgg16