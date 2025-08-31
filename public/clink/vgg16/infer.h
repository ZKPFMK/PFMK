#pragma once

#include "./para_com.h"
#include "circuit/fixed_point/fixed_point.h"

namespace clink::vgg16 {

// input type: <D,N>
// output type: <D, 2N>
inline void InferConv(Para::ConvLayer const& layer, 
                      Image const& input_image,
                      Image & output_image) {
  Tick tick(__FN__);
  namespace fp = circuit::fp;
  size_t const C = layer.C();
  size_t const D = layer.D;
  size_t const K = layer.K();

  assert(input_image.D() == D);
  assert(input_image.C() == C);
  assert(output_image.D() == D);
  assert(output_image.C() == K);

  std::vector<std::vector<Fr>> y;
  auto const& x = input_image.matrix;
  auto const& w = layer.coefs;
  auto const& b = layer.bias;
  MatrixMul(x, w, y);
  
  auto parallel_f = [&y, &b, &output_image](size_t i){
    size_t row = i / y[0].size(), col = i % y[0].size();
    output_image.data[i] = y[row][col] + b[col];
  };
  parallel::For(output_image.size(), parallel_f);
  output_image.transform();

  return;
}

// input type: <D,2N>
// output type: <D,N>
inline void InferReluBn(Para::BnLayer const& layer,
                        Image const& input_image,
                        Image& output_image) {
  Tick tick(__FN__);
  namespace fp = circuit::fp;
  auto const& input_data = input_image.data;
  auto& output_data = output_image.data;
  size_t C = input_image.C();

  auto parallel_f = [&C, &output_data, &input_data, &layer](size_t i){
    size_t row = i / C, col = i % C;
    auto const& mu = layer.mu[col];
    auto const& beta = layer.beta[col];
    auto const& alpha = layer.alpha[col];

    auto& in_data = input_data[i];
    auto& out_data = output_data[i];
    out_data = fp::ReducePrecision<8, 24 * 2, 24>(in_data);
    out_data = out_data.isNegative() ? 0 : out_data;
    out_data = alpha * (out_data - mu) + beta * fp::RationalConst<8, 24>().kFrN;
    out_data = fp::ReducePrecision<8, 24 * 2, 24>(out_data);
  };
  parallel::For(input_data.size(), parallel_f);

  output_image.transform();
}

// input type: <D,N>
// output type: <D,N>
inline void InferMaxPooling(Image const& input_image, Image& output_image) {
  Tick tick(__FN__);
  namespace fp = circuit::fp;
  
  auto FrDN = fp::RationalConst<8, 24>().kFrDN;
  auto parallel_f = [&input_image, &output_image, &FrDN](size_t idx){
    auto& output_data = output_image.data;
    auto const& input_data = input_image.data;
    
    size_t C = output_image.C(), D = output_image.D(), DD = output_image.matrix.size();
    size_t i = idx / C, j = idx % C;

    std::array<Fr, 4> rect_fr;
    size_t row = i / D, col = i % D;
    rect_fr[0] = input_data[(row * 2 * input_image.D() + col * 2) * C + j] + FrDN;
    rect_fr[1] = input_data[(row * 2 * input_image.D() + col * 2 + 1) * C + j] + FrDN;
    rect_fr[2] = input_data[((row * 2 + 1) * input_image.D() + col * 2) * C + j] + FrDN;
    rect_fr[3] = input_data[((row * 2 + 1) * input_image.D() + col * 2 + 1) * C + j] + FrDN;
    std::array<mpz_class, 4> rect_mpz;
    rect_mpz[0] = rect_fr[0].getMpz();
    rect_mpz[1] = rect_fr[1].getMpz();
    rect_mpz[2] = rect_fr[2].getMpz();
    rect_mpz[3] = rect_fr[3].getMpz();
    mpz_class max_value = *std::max_element(rect_mpz.begin(), rect_mpz.end());
    output_data[i * C + j].setMpz(max_value);
    output_data[i * C + j] = output_data[i * C + j] - FrDN;
  };
  parallel::For(output_image.size(), parallel_f);

  output_image.transform();
  return;
}

// input type: <D,N>
// output type: <D,2N>
inline void InferDense(Para::DenseLayer const& layer,
                       Image const& input_image,
                       Image& output_image) {
  Tick tick(__FN__);
  namespace fp = circuit::fp;
  auto const& input_data = input_image.data;
  auto& output_data = output_image.data;
  for (size_t i = 0; i < output_data.size(); ++i) {
    output_data[i] = std::inner_product(
        input_data.begin(), input_data.end(), layer.weight[i].begin(), 
        fp::RationalConst<8, 24>().kFrN * layer.weight[i].back());
  }
}

inline void Infer(Para const& para, dbl::Image const& dbl_image,
                  std::array<std::unique_ptr<Image>, 35>& images) {
  Tick tick(__FN__);
  images[0].reset(new Image(dbl_image));
  for (size_t i = 1; i < images.size(); ++i) {
    images[i].reset(new Image(kImageInfos[i]));
  }

  InferConv(para.conv_layer(0), *images[0], *images[1]);

  InferReluBn(para.bn_layer(0), *images[1], *images[2]);

  InferConv(para.conv_layer(1), *images[2], *images[3]);

  InferReluBn(para.bn_layer(1), *images[3], *images[4]);

  InferMaxPooling(*images[4], *images[5]);

  InferConv(para.conv_layer(2), *images[5], *images[6]);

  InferReluBn(para.bn_layer(2), *images[6], *images[7]);

  InferConv(para.conv_layer(3), *images[7], *images[8]);

  InferReluBn(para.bn_layer(3), *images[8], *images[9]);

  InferMaxPooling(*images[9], *images[10]);

  InferConv(para.conv_layer(4), *images[10], *images[11]);

  InferReluBn(para.bn_layer(4), *images[11], *images[12]);

  InferConv(para.conv_layer(5), *images[12], *images[13]);

  InferReluBn(para.bn_layer(5), *images[13], *images[14]);

  InferConv(para.conv_layer(6), *images[14], *images[15]);

  InferReluBn(para.bn_layer(6), *images[15], *images[16]);

  InferMaxPooling(*images[16], *images[17]);

  InferConv(para.conv_layer(7), *images[17], *images[18]);

  InferReluBn(para.bn_layer(7), *images[18], *images[19]);

  InferConv(para.conv_layer(8), *images[19], *images[20]);

  InferReluBn(para.bn_layer(8), *images[20], *images[21]);

  InferConv(para.conv_layer(9), *images[21], *images[22]);

  InferReluBn(para.bn_layer(9), *images[22], *images[23]);

  InferMaxPooling(*images[23], *images[24]);

  InferConv(para.conv_layer(10), *images[24], *images[25]);

  InferReluBn(para.bn_layer(10), *images[25], *images[26]);

  InferConv(para.conv_layer(11), *images[26], *images[27]);

  InferReluBn(para.bn_layer(11), *images[27], *images[28]);

  InferConv(para.conv_layer(12), *images[28], *images[29]);

  InferReluBn(para.bn_layer(12), *images[29], *images[30]);

  InferMaxPooling(*images[30], *images[31]);

  InferDense(para.dense_layer(0), *images[31], *images[32]);

  InferReluBn(para.bn_layer(13), *images[32], *images[33]);

  InferDense(para.dense_layer(1), *images[33], *images[34]);

  images[34]->dump<8, 24 + 24>();
}

};  // namespace clink::vgg16