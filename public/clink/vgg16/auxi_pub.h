#pragma once

#include "./para_fr.h"

namespace clink::vgg16 {

class AuxiPub {
 public:
  AuxiPub() {
    Tick tick(__FN__);
    InitPtr();

    ComputeParaBn(*para_u_bn_);
  }

  AuxiPub(std::string const& file) {
    Tick tick(__FN__);
    InitPtr();

    CHECK(YasLoadBin(file, *this), file);
  }

  bool operator==(AuxiPub const& b) const {
    return *para_u_bn_ == *b.para_u_bn_;
  }

  bool operator!=(AuxiPub const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.auxi", ("b", *para_u_bn_));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.auxi", ("b", *para_u_bn_));
  }

  // para bn
  std::pair<G1 const*, G1 const*> para_u_bn() const {
    return std::make_pair(para_u_bn_->data(),
                          para_u_bn_->data() + para_u_bn_->size());
  }

 private:
  //4736为输出通道总数量(BatchNormal层)
  std::unique_ptr<std::array<G1, 4736>> para_u_bn_;


 private:
  void InitPtr() {
    //batchnormal共有4736个输出通道
    para_u_bn_.reset(new std::array<G1, 4736>);
  }

  /**
   * 每一层中的输出通道各使用一个承诺
   */
  void ComputeParaBn(std::array<G1, 4736>& u) {
    size_t constexpr kCount = 14; //BatchNormal共有14层

    u.fill(G1Zero());

    // 前i层的输出元素数量 (输出大小 * 输出通道)
    std::array<size_t, kCount> g_offsets = {
        {0, 65536, 131072, 163840, 196608, 212992, 229376, 245760, 253952,
         262144, 270336, 272384, 274432, 276480}};

    // 前i层的输出通道总数
    // BN中输出通道总数 4736
    std::array<size_t, kCount> u_offsets = {{0, 64, 128, 256, 384, 640, 896,
                                             1152, 1664, 2176, 2688, 3200, 3712,
                                             4224}};
    // 各层输出通道(=输入通道)
    std::array<size_t, kCount> range_i = { //C
        {64, 64, 128, 128, 256, 256, 256, 512, 512, 512, 512, 512, 512, 512}};

    // 各层输出大小
    std::array<size_t, kCount> range_j = { //DD
        {1024, 1024, 256, 256, 64, 64, 64, 16, 16, 16, 4, 4, 4, 1}};

    for (size_t k = 0; k < kCount; ++k) { //第几个BN层
      for (size_t i = 0; i < range_j[k]; ++i) {
        VectorAdd(u.data()+u_offsets[k], range_i[k], u.data()+u_offsets[k], pc::PcG()+g_offsets[k]+i*range_i[k]);
      }
    }
  }

  //反序列化
  bool Load(std::string const& file) {
    try {
      yas::file_istream is(file.c_str());
      yas::binary_iarchive<yas::file_istream, YasBinF()> ia(is);
      ia.serialize(*this);
      return true;
    } catch (std::exception& e) {
      std::cerr << e.what() << "\n";
      return false;
    }
  }
};

};  // namespace clink::vgg16