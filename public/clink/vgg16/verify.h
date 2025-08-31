#pragma once

#include "clink/adapt.h"
// #include "./conv_verify.h"
// #include "./dense_verify.h"
#include "./image_com.h"
// #include "./pooling_verify.h"
#include "./prove.h"
// #include "./relubn_verify.h"

namespace clink::vgg16 {

inline bool Verify(h256_t seed, std::string const& pub_path, Proof const& proof) {
  Tick tick(__FN__);
  VerifyContext context(pub_path);

  std::vector<parallel::BoolTask> verify_tasks;

  AdaptVerifyItem verify_item(10);

  verify_tasks.emplace_back([&context, &seed, &proof, &verify_item]() {
    return ConvVerify(seed, context, proof.conv, verify_item);
  });

  verify_tasks.emplace_back([&context, &seed, &proof, &verify_item]() {
    return ReluBnVerify(seed, context, proof.relubn, verify_item);
  });

//   // pooling
  verify_tasks.emplace_back([&context, &seed, &proof, &verify_item]() {
    return PoolingVerify(seed, context, proof.pooling, verify_item);
  });

// //   dense0
  verify_tasks.emplace_back([&context, &seed, &proof, &verify_item]() {
    return DenseVerify<0>(seed, context, proof.dense1, verify_item);
  });

// //   dense1
   verify_tasks.emplace_back([&context, &seed, &proof, &verify_item]() {
    return DenseVerify<1>(seed, context, proof.dense2, verify_item);
  });


  bool all_success = false;
  auto f1 = [&verify_tasks](int64_t i) { return verify_tasks[i](); };
  parallel::For(&all_success, verify_tasks.size(), f1);
  CHECK(all_success, "verify failed");

  all_success &= AdaptVerify(seed, verify_item, proof.sub_proof);
  CHECK(all_success, "verify failed");

  // all_success &= Pod::VerifyAndBuy(seed, 10, proof.pod_data);
  // CHECK(all_success, "verify failed");

  return all_success;
}
}  // namespace clink::vgg16
