#pragma once

#include "./auxi_pub.h"

namespace clink::vgg16 {

struct BnCommitmentPub {
  G1 com_mu;
  G1 com_alpha;
  G1 com_beta;

  bool operator==(BnCommitmentPub const& b) const {
    return com_mu == b.com_mu && com_alpha == b.com_alpha && com_beta == b.com_beta;
  }

  bool operator!=(BnCommitmentPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.bn", ("m", com_mu),
                      ("a", com_alpha), ("b", com_beta));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.bn", ("m", com_mu),
                      ("a", com_alpha), ("b", com_beta));
  }
};

struct BnCommitmentSec {
  Fr r_com_mu;
  Fr r_com_alpha;
  Fr r_com_beta;
  bool operator==(BnCommitmentSec const& b) const {
    return r_com_mu == b.r_com_mu && r_com_alpha == b.r_com_alpha && r_com_beta == b.r_com_beta;
  }

  bool operator!=(BnCommitmentSec const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.bn", ("m", r_com_mu), ("a", r_com_alpha),
                       ("b", r_com_beta));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.bn", ("m", r_com_mu), ("a", r_com_alpha),
                       ("b", r_com_beta));
  }
};

struct ConvCommitmentPub {
  //conv共有13层, 每一个卷积核对应位置上进行承诺, 13 * 9 * KCDD
  std::array<std::vector<G1>, 13> com_coef; //每层K个承诺
  std::array<G1, 13> com_bias; //一层一个承诺

  bool operator==(ConvCommitmentPub const& b) const {
    return com_coef == b.com_coef && com_bias == b.com_bias;
  }

  bool operator!=(ConvCommitmentPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.conv", ("c", com_coef), ("b", com_bias));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.conv", ("c", com_coef), ("b", com_bias));
  }
};

struct ConvCommitmentSec {
  std::array<std::vector<Fr>, 13> r_com_coef;
  std::array<Fr, 13> r_com_bias;

  bool operator==(ConvCommitmentSec const& b) const {
    return r_com_coef == b.r_com_coef && r_com_bias == b.r_com_bias;
  }

  bool operator!=(ConvCommitmentSec const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.conv", ("c", r_com_coef), ("b", r_com_bias));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.conv", ("c", r_com_coef), ("b", r_com_bias));
  }
};

struct DenseCommitmentPub {
  // 512 * 512, 每一行进行承诺
  std::array<G1, 512> com_d0;
  // 10 * 512, 每一行进行承诺
  std::array<G1, 10> com_d1;

  template <size_t Order>
  auto const& get() const {
    static_assert(Order == 0 || Order == 1, "invalid Order");
    if constexpr (Order == 0)
      return com_d0;
    else
      return com_d1;
  }

  bool operator==(DenseCommitmentPub const& b) const {
    return com_d0 == b.com_d0 && com_d1 == b.com_d1;
  }

  bool operator!=(DenseCommitmentPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.dense", ("d0", com_d0), ("d1", com_d1));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.compub.dense", ("d0", com_d0), ("d1", com_d1));
  }
};

struct DenseCommitmentSec {
  std::array<Fr, 512> r_com_d0;
  std::array<Fr, 10> r_com_d1;

  template <size_t Order>
  auto const& get() const {
    static_assert(Order == 0 || Order == 1, "invalid Order");
    if constexpr (Order == 0)
      return r_com_d0;
    else
      return r_com_d1;
  }

  bool operator==(DenseCommitmentSec const& b) const {
    return r_com_d0 == b.r_com_d0 && r_com_d1 == b.r_com_d1;
  }

  bool operator!=(DenseCommitmentSec const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.dense", ("d0", r_com_d0), ("d1", r_com_d1));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec.dense", ("d0", r_com_d0), ("d1", r_com_d1));
  }
};

struct ParaCommitmentPub {
  BnCommitmentPub bn;
  ConvCommitmentPub conv;
  DenseCommitmentPub dense;

  ParaCommitmentPub() {}

  ParaCommitmentPub(std::string const& file) {
    if (!YasLoadBin(file, *this)) {
      throw std::invalid_argument("invalid para commitment pub file: " + file);
    }
  }

  bool operator==(ParaCommitmentPub const& b) const {
    return bn == b.bn && conv == b.conv && dense == b.dense;
  }

  bool operator!=(ParaCommitmentPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.compub", ("b", bn), ("c", conv),
                       ("d", dense));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.compub", ("b", bn), ("c", conv),
                       ("d", dense));
  }
};

struct ParaCommitmentSec {
  BnCommitmentSec bn;
  ConvCommitmentSec conv;
  DenseCommitmentSec dense;

  ParaCommitmentSec() {}

  ParaCommitmentSec(std::string const& file) {
    if (!YasLoadBin(file, *this)) {
      throw std::invalid_argument("invalid para commitment sec file: " + file);
    }
  }

  bool operator==(ParaCommitmentSec const& b) const {
    return bn == b.bn && conv == b.conv && dense == b.dense;
  }

  bool operator!=(ParaCommitmentSec const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec", ("b", bn), ("c", conv),
                       ("d", dense));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para.comsec", ("b", bn), ("c", conv),
                       ("d", dense));
  }
};

inline void ComputeBnCommitment(std::array<Para::BnLayer, 14> const& para,
                                AuxiPub const& auxi, BnCommitmentPub& pub,
                                BnCommitmentSec& sec) {
  Tick tick(__FN__);
  sec.r_com_alpha = FrRand();
  sec.r_com_beta = FrRand();
  sec.r_com_mu = FrRand();

  //4736为输出通道总数量(BatchNormal层)
  // combine alpha,beta,mu
  std::vector<Fr> all_alpha, all_beta, all_mu;
  all_alpha.reserve(4736);
  all_beta.reserve(4736);
  all_mu.reserve(4736);

  for (auto const& i : para) {
    all_alpha.insert(all_alpha.end(), i.alpha.begin(), i.alpha.end());
    all_beta.insert(all_beta.end(), i.beta.begin(), i.beta.end());
    all_mu.insert(all_mu.end(), i.mu.begin(), i.mu.end());
  }

  pub.com_alpha = pc::ComputeCom(all_alpha.size(), auxi.para_u_bn().first,
                             all_alpha.data(), sec.r_com_alpha);

  pub.com_beta = pc::ComputeCom(all_beta.size(), auxi.para_u_bn().first,
                            all_beta.data(), sec.r_com_beta);

  pub.com_mu = pc::ComputeCom(all_mu.size(), auxi.para_u_bn().first,
                            all_mu.data(), sec.r_com_mu);
}

/**
 * 卷积参数的承诺, 需要对每一层卷积单独承诺:
 *    卷积参数: 9C * K
 *    bias参数: 1 * K
 */
inline void ComputeConvCommitment(std::array<Para::ConvLayer, 13> const& para,
                                  ConvCommitmentPub& pub,
                                  ConvCommitmentSec& sec) {
  Tick tick(__FN__);
  auto parallel_f = [&para, &pub, &sec](int64_t o) { //第o个卷积, 一共13个卷积
    auto C = kConvLayerInfos[o].C; //输入通道
    auto K = kConvLayerInfos[o].K; //输出通道

    auto const& layer = para[o]; //conv的参数
    auto& com_coef = pub.com_coef[o]; // 列承诺, K
    auto& com_bias = pub.com_bias[o];  // 1
    auto& r_com_coef = sec.r_com_coef[o]; //9
    auto& r_com_bias = sec.r_com_bias[o]; //1

    com_coef.resize(K);
    r_com_coef.resize(K);

    FrRand(r_com_coef);
    r_com_bias = FrRand();

    auto parallel_c = [&com_coef, &layer, &r_com_coef](int64_t j) { // 第j列(承诺)
      auto const& coefs = layer.coefs;
      auto get_coef = [&coefs, &j](int64_t i) -> Fr const& {
        return coefs[i][j];
      };
      com_coef[j] = pc::ComputeCom(9 * layer.C(), get_coef, r_com_coef[j]);
    };
    parallel::For(K, parallel_c);

    auto const& bias = layer.bias;
    com_bias = pc::ComputeCom(bias, r_com_bias);
  };

  parallel::For((int64_t)para.size(), parallel_f);
}

inline void ComputeDenseCommitment(std::array<Para::DenseLayer, 2> const& para,
                                   DenseCommitmentPub& pub,
                                   DenseCommitmentSec& sec) {
  Tick tick(__FN__);
  FrRand(sec.r_com_d0.data(), sec.r_com_d0.size());
  FrRand(sec.r_com_d1.data(), sec.r_com_d1.size());

  assert(para[0].weight.size() == pub.com_d0.size());
  for (size_t i = 0; i < para[0].weight.size(); ++i) {
    auto const& w = para[0].weight[i];
    pub.com_d0[i] = pc::ComputeCom(w, sec.r_com_d0[i]);
  }

  assert(para[1].weight.size() == pub.com_d1.size());
  for (size_t i = 0; i < para[1].weight.size(); ++i) {
    auto const& w = para[1].weight[i];
    pub.com_d1[i] = pc::ComputeCom(w, sec.r_com_d1[i]);
  }
}

inline void ComputeParaCommitment(Para const& para, AuxiPub const& auxi,
                                  ParaCommitmentPub& pub,
                                  ParaCommitmentSec& sec) {
  Tick tick(__FN__);
  ComputeBnCommitment(para.bn_layers(), auxi, pub.bn, sec.bn);
  ComputeConvCommitment(para.conv_layers(), pub.conv, sec.conv);
  ComputeDenseCommitment(para.dense_layers(), pub.dense, sec.dense);
}
}  // namespace clink::vgg16