#pragma once

#include "../details.h"
#include "circuit/vgg16/vgg16.h"
#include "./auxi_pub.h"
#include "./context.h"
#include "./prove.h"
#include "./verify.h"

namespace clink::vgg16 {
inline bool Publish(std::string const& para_path,
                    std::string const& working_path) {
  Tick tick(__FN__);

  //参数目录是否存在
  if (para_path.empty() || !fs::is_directory(para_path)) {
    std::cerr << "Open publish_dir " << para_path << " failed\n";
    return false;
  }

  //创建承诺目pub及sec目录
  std::string pub_path = working_path + "/pub";
  std::string sec_path = working_path + "/sec";
  if (!fs::is_directory(pub_path) && !fs::create_directories(pub_path)) {
    std::cerr << "Create " << pub_path << " failed\n";
    return false;
  }
  if (!fs::is_directory(sec_path) && !fs::create_directories(sec_path)) {
    std::cerr << "Create " << sec_path << " failed\n";
    return false;
  }

  try {
    // 将参数序列化
    dbl::Para dbl_para(para_path);
    std::unique_ptr<Para> para(new Para(dbl_para));
    if (!YasSaveBin(sec_path + "/para", *para)) {
      std::cerr << "save para failed\n";
      return false;
    }

    // 计算辅助参数
    std::unique_ptr<AuxiPub> auxi(new AuxiPub);
    if (!YasSaveBin(pub_path + "/auxi", *auxi)) {
      std::cerr << "save auxi failed\n";
      return false;
    }

    //计算参数的承诺
    ParaCommitmentPub com_pub;
    ParaCommitmentSec com_sec;
    ComputeParaCommitment(*para, *auxi, com_pub, com_sec);
    if (!YasSaveBin(pub_path + "/para_com_pub", com_pub)) {
      std::cerr << "save com_pub failed\n";
      return false;
    }
    if (!YasSaveBin(sec_path + "/para_com_sec", com_sec)) {
      std::cerr << "save com_sec failed\n";
      return false;
    }
    return true;
  } catch (std::exception& e) {
    std::cerr << e.what() << "\n";
    return false;
  }
}

inline bool TestProve(std::string const& test_image_path,
                      std::string const& working_path) {
  Tick tick(__FN__);
  h256_t seed = misc::RandH256();
  
  //将图片加载
  dbl::Image test_image(kImageInfos[0]);
  if (!dbl::LoadTestImage(test_image_path, test_image)) {
    return false;
  }

  Proof proof;
  if (!Prove(seed, test_image, working_path, proof)) return false;
  yas::mem_ostream os;
  yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
  oa.serialize(proof);
  std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
  yas::mem_istream is(os.get_intrusive_buffer());
  yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
  Proof proof2;
  ia.serialize(proof2);
  if (proof != proof2) {
    assert(false);
    std::cout << "oops, serialize check failed\n";
    return false;
  }
  bool success = Verify(seed, working_path + "/pub", proof);
  std::cout << Tick::GetIndentString() << success << "\n\n\n\n\n\n";
  return success;
}

inline bool Test() {
  std::string working_path = "/home/dj/program/gitwork/PFMK/data/vgg16/working";
  std::string features_path = "/home/dj/program/gitwork/PFMK/data/vgg16/features";
  std::string test_image_path = "/home/dj/program/gitwork/PFMK/data/vgg16/test_image";
  
  //创建working目录
  if (!fs::is_directory(working_path) &&
      !fs::create_directories(working_path)) {
    std::cerr << "Create " << working_path << " failed\n";
    return false;
  }

  boost::system::error_code ec;
  if (!fs::is_directory(working_path + "/pub", ec) ||
      !fs::is_directory(working_path + "/sec", ec)) {
    Publish(features_path, working_path);
  }
  
  return TestProve(test_image_path, working_path);
}

}  // namespace clink::vgg16