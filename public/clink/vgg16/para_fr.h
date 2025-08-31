#pragma once

#include "./para_dbl.h"
#include "ecc/ecc.h"
#include "misc/misc.h"
#include "utils/fst.h"

namespace clink {
namespace vgg16 {

struct Para {
  struct ConvLayer {
    ConvLayer() {}
    ConvLayer(ConvLayerInfo const& info) : order(info.order), D(info.D) {
      coefs.resize(9*info.C, std::vector<Fr>(info.K));
      bias.resize(info.K);
    }

    ConvLayer(dbl::Para::ConvLayer const& dbl) : order(dbl.order), D(dbl.D) {
      namespace fp = circuit::fp;
      coefs.resize(9*dbl.C(), std::vector<Fr>(dbl.K()));
      bias.resize(dbl.K());
      size_t c =C();

      auto parallel_f = [this, &dbl](size_t idx){
        size_t row = idx / coefs[0].size() , col = idx % coefs[0].size(), i = col;
        size_t j = row / 9, k = row % 9, l = k % 3;
        k = k / 3;
        coefs[row][col] = fp::DoubleToRational<8, 24>(dbl.coefs[i][j][k][l]);

        if(row == 0){
          bias[col] = fp::DoubleToRational<8, 24>(dbl.bias[col]) * fp::RationalConst<8, 24>().kFrN;
        }
      };
      parallel::For(coefs.size() * coefs[0].size(), parallel_f);
    }

    bool operator==(ConvLayer const& b) const {
      return order == b.order && D == b.D && coefs == b.coefs && bias == b.bias;
    }

    bool operator!=(ConvLayer const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("vgg16.para.conv", ("o", order), ("d", D),
                         ("c", coefs), ("b", bias));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("vgg16.para.conv", ("o", order), ("d", D),
                         ("c", coefs), ("b", bias));
    }

    size_t order; //第几个卷积层
    size_t D; //输入大小 = 输出大小
    // size=9C * K, K:输出通道, C: 输入通道
    std::vector<std::vector<Fr>> coefs; //
    std::vector<Fr> bias;  // size=K
    size_t K() const { return bias.size(); }     //输出通道
    size_t C() const { return coefs.size() / 9; } //输入通道
  };

  struct BnLayer {
    BnLayer() {}
    BnLayer(BnLayerInfo const& info) : order(info.order) {
      mu.resize(info.C);
      alpha.resize(info.C);
      beta.resize(info.C);
    }
    BnLayer(dbl::Para::BnLayer const& dbl) : order(dbl.order) {
      namespace fp = circuit::fp;
      mu.resize(dbl.mu.size());
      alpha.resize(dbl.alpha.size());
      beta.resize(dbl.beta.size());

      auto parallel_f = [this, &dbl](size_t i){
        mu[i] = fp::DoubleToRational<8, 24>(dbl.mu[i]);
        alpha[i] = fp::DoubleToRational<8, 24>(dbl.alpha[i]);
        beta[i] = fp::DoubleToRational<8, 24>(dbl.beta[i]);
      };
      parallel::For(mu.size(), parallel_f);
    }

    bool operator==(BnLayer const& b) const {
      return order == b.order && mu == b.mu && alpha == b.alpha &&
             beta == b.beta;
    }

    bool operator!=(BnLayer const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("vgg16.para.bn", ("o", order), ("m", mu), ("a", alpha),
                         ("b", beta));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("vgg16.para.bn", ("o", order), ("m", mu), ("a", alpha),
                         ("b", beta));
    }

    size_t order;
    std::vector<Fr> mu;
    std::vector<Fr> alpha;
    std::vector<Fr> beta;
  };

  struct DenseLayer {
    DenseLayer() {}
    DenseLayer(DenseLayerInfo const& info) : order(info.order) {
      weight.resize(info.type_count);
      for (auto& i : weight) {
        i.resize(info.input_count + 1);
      }
    }
    DenseLayer(dbl::Para::DenseLayer const& dbl) : order(dbl.order) {
      namespace fp = circuit::fp;
      weight.resize(dbl.weight.size(), std::vector<Fr>(dbl.weight[0].size()));

      auto parallel_f = [this, &dbl](size_t idx){
        size_t i = idx / weight[0].size(), j = idx % weight[0].size();
        weight[i][j] = fp::DoubleToRational<8, 24>(dbl.weight[i][j]);
      };
      parallel::For(weight.size() * weight[0].size(), parallel_f);
    }
    bool operator==(DenseLayer const& b) const {
      return order == b.order && weight == b.weight;
    }

    bool operator!=(DenseLayer const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("vgg16.para.dense", ("o", order), ("w", weight));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("vgg16.para.dense", ("o", order), ("w", weight));
    }
    size_t order;
    std::vector<std::vector<Fr>> weight;
  };

  bool operator==(Para const& b) const {
    for (size_t i = 0; i < conv_layers_.size(); ++i) {
      if (conv_layer(i) != b.conv_layer(i)) return false;
    }
    for (size_t i = 0; i < bn_layers_.size(); ++i) {
      if (bn_layer(i) != b.bn_layer(i)) return false;
    }
    for (size_t i = 0; i < dense_layers_.size(); ++i) {
      if (dense_layer(i) != b.dense_layer(i)) return false;
    }

    return true;
  }

  bool operator!=(Para const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.para", ("c", conv_layers_), ("b", bn_layers_),
                       ("d", dense_layers_));
  }

  template <typename Ar>
  void serialize(Ar& ar) {
    ar& YAS_OBJECT_NVP("vgg16.para", ("c", conv_layers_), ("b", bn_layers_),
                       ("d", dense_layers_));
  }

  BnLayer const& bn_layer(size_t order) const { return bn_layers_[order]; }

  ConvLayer const& conv_layer(size_t order) const {
    return conv_layers_[order];
  }

  DenseLayer const& dense_layer(size_t order) const {
    return dense_layers_[order];
  }

  std::array<ConvLayer, 13> const& conv_layers() const { return conv_layers_; }

  std::array<BnLayer, 14> const& bn_layers() const { return bn_layers_; }

  std::array<DenseLayer, 2> const& dense_layers() const {
    return dense_layers_;
  }

  Para() {}

  Para(dbl::Para const& dbl_para) {
    Tick tick(__FN__);
    auto parallel_f = [this, &dbl_para](size_t i){
      if(i < kConvLayerInfos.size()){
        conv_layers_[i] = ConvLayer(dbl_para.conv_layer(i));
      }
      if(i < kDenseLayerInfos.size()){
         dense_layers_[i] = DenseLayer(dbl_para.dense_layer(i));
      }
      bn_layers_[i] = BnLayer(dbl_para.bn_layer(i));
    };
    parallel::For(kBnLayerInfos.size(), parallel_f);
  }

  Para(std::string const& file) {
    Tick tick(__FN__);
    if (!Load(file)) {
      throw std::invalid_argument("invalid para file: " + file);
    }
  }

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

  bool Save(std::string const& file) const {
    Tick tick(__FN__);
    try {
      boost::system::error_code dummy;
      fs::remove(file, dummy);
      yas::file_ostream os(file.c_str());
      yas::binary_oarchive<yas::file_ostream, YasBinF()> oa(os);
      oa.serialize(*this);
    } catch (std::exception& e) {
      std::cerr << e.what() << "\n";
      return false;
    }

#ifdef _DEBUG_CHECK
    try {
      Para check(file);
      if (check != *this) {
        std::cout << "oops\n";
        return false;
      }
    } catch (std::exception& e) {
      std::cerr << e.what() << "\n";
      return false;
    }
#endif

    return true;
  }

 private:
  std::array<ConvLayer, 13> conv_layers_;
  std::array<BnLayer, 14> bn_layers_;
  std::array<DenseLayer, 2> dense_layers_;
};

struct Image {
  size_t const _D;
  size_t const order;
  std::vector<std::vector<int>> position; //DD * 9
  std::vector<std::vector<Fr>> matrix;    //DD * C9, 用来作为conv的输入
  std::vector<Fr> data; //用来作为承诺, 格式为 DD*C

  void transform() { //用来作为conv的输入以及内积证明, DD*C
    size_t c = C();
    auto parallel_f = [this, &c](size_t idx){
      size_t i = idx / matrix[0].size(), j = idx % matrix[0].size(), row = j / 9, col = j % 9;
      matrix[i][j] = position[i][col] == -1 ? FrZero() : data[position[i][col] * c + row];
    };
    parallel::For(matrix.size() * matrix[0].size(), parallel_f);
  }

  inline std::vector<Fr> rev_transform(std::vector<std::vector<Fr>> const& a) const { // DD*C
    assert(a.size() == matrix.size() && a[0].size() == matrix[0].size());
    size_t c = C();
    std::vector<Fr> ret(data.size(), FrZero());
    for(size_t i=0; i<a.size(); i++){ //dd
      for(size_t j=0; j<a[0].size(); j++){ //c9
        size_t row = j / 9, col = j % 9;
        if(position[i][col] != -1) {
          ret[position[i][col] * c + row] += a[i][j];
        }
      }
    }
    return ret;
  }

  inline std::vector<std::vector<Fr>> reshape() const{
    size_t c = C();
    std::vector<std::vector<Fr>> ret(position.size());
    for(size_t i=0; i<ret.size(); i++){
      ret[i] = std::vector<Fr>(data.begin() + i * c, data.begin() + (i+1) * c);
    }
    return ret;
  }

  void Init(){ //填充position
    auto d = D(), dd = matrix.size();
    position.resize(dd, std::vector<int>(9));

    auto parallel_f = [this, &d, &dd](size_t idx){
      size_t i = idx / 9, j = idx % 9;
      size_t subrow1 = i / d;  //索引
      size_t subcol1 = i % d;
      size_t subrow2 = j / 3;
      size_t subcol2 = j % 3;
      size_t row = subrow1 + subrow2;
      size_t col = subcol1 + subcol2;
      if (row == 0 || col == 0 || row == (d + 1) || col == (d + 1)) {
        position[i][j] = -1;
      } else {
        position[i][j] = (row - 1) * d + (col - 1);
      }
    };
    parallel::For(dd * 9, parallel_f);
  }

  Image(ImageInfo const& info)
      : _D(info.D),
        order(info.order),
        data(info.D *info.D * info.C),
        matrix(info.D *info.D, std::vector<Fr>(info.C * 9)){
    Init();
  }

  Image(dbl::Image const& dbl)
      : _D(dbl.D()),
        order(dbl.order),
        data(dbl.D() * dbl.D() * dbl.C()),
        matrix(dbl.D() * dbl.D(), std::vector<Fr>(dbl.C() * 9)){
    Init();
    namespace fp = circuit::fp;
    size_t c = C(), dd = matrix.size();
    
    auto parallel_f = [this, &dbl, &c, &dd](size_t idx){
      size_t row = idx / c, col = idx % c;
      data[idx] = fp::DoubleToRational<8, 24>(dbl.data[col * dd + row]);
    };
    parallel::For(data.size(), parallel_f);

    transform();
  }

  bool operator==(Image const& b) const {
    return order == b.order && data == b.data && C() == b.C() && D() == b.D() && position == b.position;
    
  }

  bool operator!=(Image const& b) const { return !(*this == b); }

  template <typename Ar>
  void serialize(Ar& ar) const {
    ar& YAS_OBJECT_NVP("vgg16.image", ("d", data), ("m", matrix));
  }
  template <typename Ar>
  void serialize(Ar& ar) { //用于填充data
    ar& YAS_OBJECT_NVP("vgg16.image", ("d", data), ("m", matrix));
    auto c = C();
    auto d = D();
    if (c * d * d != data.size()) throw std::runtime_error("oops");
  }

  size_t size() const { return data.size(); }
  size_t C() const { return matrix[0].size() / 9; }
  size_t D() const { return _D; }

  template <size_t D, size_t N>
  void dump() const {
    namespace fp = circuit::fp;
    for (auto const& i : data) {
      double di = fp::RationalToDouble<D, N>(i);
      std::cout << di << "\t";
    }
    std::cout << "\n\n";
  }
};
}  // namespace vgg16
}  // namespace clink