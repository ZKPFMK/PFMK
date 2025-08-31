#pragma once

#include <memory>
#include <vector>

namespace clink::vgg16 {
std::vector<std::vector<Fr>> pool_a, pool_b, pool_c;
std::vector<std::vector<Fr>> rlbn_a, rlbn_b, rlbn_c;
struct R1csSec {
  std::vector<Fr> r_com_w;
  std::vector<std::vector<Fr>> mutable w;
};

}  // namespace clink::vgg16