#pragma once

#include "clink/adapt.h"
#include "./image_com.h"
#include "./infer.h"
#include "./conv_prove.h"
#include "./dense_prove.h"
#include "./pooling_prove.h"
#include "./relubn_prove.h"
#include "clink/pod.h"

namespace clink::vgg16 {

  /**
   * -2.87922;-12.1531;6.91548;10.5677;4.28436;5.72458;-0.843376;-6.08809;2.95418;-9.37892;
   */
inline bool InferAndCommit(dbl::Image const& test_image,
                           std::string const& working_path) {
  Tick tick(__FN__);  
  try {
    //参数反序列化
    Para para(working_path + "/sec/para");
    std::array<std::unique_ptr<Image>, 35> images;
    //计算每一层的输出
    Infer(para, test_image, images);
    
    size_t img_size = 0;
    // 将每一层的输出保存文件: working/sec/image_i
    for (size_t i = 0; i < images.size(); ++i) {
      std::string file = working_path + "/sec";
      fs::create_directories(file);
      file += "/image_" + std::to_string(i);
      fs::remove(file);
      yas::file_ostream os(file.c_str());
      yas::binary_oarchive<yas::file_ostream, YasBinF()> oa(os);
      oa.serialize(*images[i]);
    }

    //对每一层的输出进行承诺
    ImageCommitmentPub image_com_pub;
    ImageCommitmentSec image_com_sec;
    ComputePerImageCommitment(images, image_com_pub, image_com_sec);
    YasSaveBin(working_path + "/pub/image_com_pub", image_com_pub);
    YasSaveBin(working_path + "/sec/image_com_sec", image_com_sec);
    return true;
  } catch (std::exception& e) {
    std::cerr << e.what() << "\n";
    return false;
  }
}

struct Proof {
  ConvProof conv;
  ReluBnProof relubn;
  PoolingProof pooling;
  DenseProof dense1;
  DenseProof dense2;

  // Pod::ProvedData pod_data;

  argument::A4::Proof sub_proof;

  Proof(std::string const& file) {
    Tick tick(__FN__);
    if (!YasLoadBin(file, *this)) {
      throw std::invalid_argument("invalid proof file: " + file);
    }
  }
  Proof() {}

  bool operator==(Proof const& b) const {
    return conv == b.conv && relubn == b.relubn && pooling == b.pooling &&
           dense1 == b.dense1 && dense2 == b.dense2 && sub_proof == b.sub_proof;
  }

  bool operator!=(Proof const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.Proof", ("c", conv), ("r", relubn),
                       ("p", pooling), ("d1", dense1), ("d2", dense2),
                       ("sp", sub_proof));
  }
  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.Proof", ("c", conv), ("r", relubn),
                       ("p", pooling), ("d1", dense1), ("d2", dense2),
                       ("sp", sub_proof));
  }
};

inline bool Prove(h256_t seed, dbl::Image const& test_image,
                  std::string const& working_path, Proof& proof) {
  Tick tick(__FN__);
  //计算模型中每一层的输出, 并承诺
  if (!InferAndCommit(test_image, working_path)) return false;

  //参数, 输入信息(承诺 + 打开)
  ProveContext context(working_path);
  std::vector<parallel::VoidTask> prove_tasks;

  // conv
  AdaptProveItem prove_item(10);

  prove_tasks.emplace_back([&context, &seed, &proof, &prove_item]() {
    ConvProve(seed, context, proof.conv, prove_item.in[0], prove_item.sec[0], prove_item.in[1], prove_item.sec[1]);
  });

  prove_tasks.emplace_back([&context, &seed, &proof, &prove_item]() {
    ReluBnProve(seed, context, proof.relubn, prove_item, prove_item.in[2], prove_item.sec[2], prove_item.in[3], prove_item.sec[3]);
  });

  prove_tasks.emplace_back([&context, &seed, &proof, &prove_item]() {
    PoolingProve(seed, context, proof.pooling, prove_item.in[4], prove_item.sec[4], prove_item.in[5], prove_item.sec[5]);
  });

  prove_tasks.emplace_back([&context, &seed, &proof, &prove_item]() {
    DenseProve<0>(seed, context, proof.dense1, prove_item.in[6], prove_item.sec[6], prove_item.in[7], prove_item.sec[7]);
  });

  prove_tasks.emplace_back([&context, &seed, &proof, &prove_item]() {
    DenseProve<1>(seed, context, proof.dense2, prove_item.in[8], prove_item.sec[8], prove_item.in[9], prove_item.sec[9]);
  });

  {
    // 生成证据
    Tick subtick("prepare proveinput");
    auto f1 = [&prove_tasks](int64_t i) { prove_tasks[i](); };
    parallel::For(prove_tasks.size(), f1);
  } 

  AdaptProve(seed, prove_item, proof.sub_proof);


  // Pod::CommitedData commited_data(
  //     context.const_images()[34]->data, 
  //     context.image_com_sec().r_com_x[34], 
  //     context.image_com_pub().com_x[34]
  // );
  // Pod::EncryptAndProve(proof.pod_data, seed, commited_data);

  return true;
}

}  // namespace clink::vgg16
