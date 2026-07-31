#pragma once

#include "public.h"

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4191)
#endif

#include <mcl/bn256.hpp>
#include <mcl/window_method.hpp>

#include "./types.h"
#include "log/tick.h"
#include "misc/misc.h"
#include "parallel/parallel.h"


#ifdef _WIN32
#pragma warning(pop)
#endif

typedef std::function<Fr const&(int64_t i)> GetRefFr;
typedef std::function<G1 const&(int64_t i)> GetRefG1;


// returns ceil(log2(n)), so ((size_t)1)<<log2(n) is the smallest power of
// 2, that is not less than n.
inline size_t CeilLog2(size_t n) {
  size_t r = ((n & (n - 1)) == 0 ? 0 : 1);  // add 1 if n is not power of 2
  while (n > 1) {
    n >>= 1;
    r++;
  }
  return r;
}


inline void InitEcc() {
  std::cout << "init mcl in main\n";
  mcl::bn::CurveParam cp = mcl::BN_SNARK1;
  mcl::bn256::initPairing(cp);
  // Fr::setETHserialization(true);
  // Fp::setETHserialization(true);
  // Fr::setIoMode(mcl::IoMode::IoSerialize);
  // G1::setIoMode(mcl::IoMode::IoSerialize);
  // G2::setIoMode(mcl::IoMode::IoSerialize);
}

inline void FpRand(Fp* f) {
  uint8_t buf[32];
  misc::RandomBytes(buf, 32);
  f->setArrayMask(buf, 32);
}

inline Fp FpRand() {
  Fp r;
  FpRand(&r);
  return r;
}

inline Fp2 Fp2Rand() { return Fp2(FpRand(), FpRand()); }

inline void FrRand(Fr* f) {
  uint8_t buf[32];
  misc::RandomBytes(buf, 32);
  f->setArrayMask(buf, 32);
}

inline Fr FrRand() {
  Fr r;
  FrRand(&r);
  return r;
}

inline void FrRand(Fr* r, size_t n) {
  std::vector<uint8_t> h(n * 32);

  auto parallel_f = [&h, n](int64_t i) mutable {
    misc::RandomBytes(h.data() + 8 * i * n, 8 * n);
  };
  parallel::For(4LL, parallel_f);

  auto parallel_f2 = [&h, r](int64_t i) mutable {
    r[i].setArrayMask(h.data() + i * 32, 32);
  };
  parallel::For((int64_t)n, parallel_f2);
}

inline void FrRand(std::vector<Fr>& r) { FrRand(r.data(), r.size()); }

inline void FrRand(std::vector<Fr*>& f) {
  auto n = f.size();
  std::vector<uint8_t> h(n * 32);

  auto parallel_f = [&h, n](int64_t i) mutable {
    misc::RandomBytes(h.data() + 8 * i * n, 8 * n);
  };
  parallel::For(4LL, parallel_f);

  auto parallel_f2 = [&h, &f](int64_t i) mutable {
    f[i]->setArrayMask(h.data() + i * 32, 32);
  };
  parallel::For((int64_t)n, parallel_f2);
}

inline Fr FrInv(Fr const& r) {
  Fr r_inv;
  Fr::inv(r_inv, r);
  return r_inv;
}

inline void FrInv(Fr* begin, uint64_t count) {
  assert(count > 0);

  std::vector<Fr> prod(count);

  Fr acc(1);

  for (size_t i = 0; i < count; ++i) {
    assert(!begin[i].isZero());
    prod[i] = acc;
    acc *= begin[i];
  }

  Fr acc_inverse = FrInv(acc);

  for (int64_t i = (int64_t)count - 1; i >= 0; --i) {
    Fr old_el = begin[i];
    begin[i] = acc_inverse * prod[i];
    acc_inverse *= old_el;
  }
}

inline void FrInv(std::vector<Fr>& vec) { FrInv(vec.data(), vec.size()); }

inline G1 G1Rand() {
  G1 out;
  bool b;
  for (;;) {
    mcl::bn256::mapToG1(&b, out, FpRand());
    if (b) break;
  }
  return out;
}

inline void G1Rand(G1* r, size_t n) {
  bool b;
  Fp f;
  for (size_t i = 0; i < n; ++i) {
    for (;;) {
      FpRand(&f);
      mcl::bn256::mapToG1(&b, r[i], f);
      if (b) break;
    }
  }
}

inline void G1Rand(std::vector<G1>& g) { return G1Rand(g.data(), g.size()); }

inline G2 G2Rand() {
  G2 out;
  bool b;
  for (;;) {
    mcl::bn256::mapToG2(&b, out, Fp2Rand());
    if (b) break;
  }
  return out;
}

inline Fr const& FrZero() {
  static auto z = []() {
    Fr f;
    f.clear();
    return f;
  };
  static auto f = z();
  return f;
}

inline void FrZero(Fr* r, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    r[i].clear();
    assert(r[i] == Fr(0));
  }
}

inline void FrZero(std::vector<Fr>& r) { return FrZero(r.data(), r.size()); }

inline Fr const& FrOne() {
  static auto const f = Fr(1);
  return f;
}

inline G1 const& G1Zero() {
  static auto z = []() {
    G1 r;
    r.clear();
    return r;
  };
  static auto g = z();
  return g;
}

inline void G1Zero(G1* r, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    r[i].clear();
  }
}

inline void G1Zero(std::vector<G1>& r) { return G1Zero(r.data(), r.size()); }

inline G1 const& G1One() {
  static const G1 g(Fp(1), Fp(2));
  return g;
}

inline G2 const& G2Zero() {
  static auto z = []() {
    G2 r;
    r.clear();
    return r;
  };
  static const auto g = z();
  return g;
}

inline void G2Zero(G2* r, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    r[i].clear();
  }
}

inline G2 const& G2One() {
  static const G2 r(
      Fp2("1085704699902305713594457076223282948137075635957851808699051999328"
          "5655852781",
          "1155973203298638710799100402139228578392581286182119253091740315145"
          "2391805634"),
      Fp2("8495653923123431417604973247489272438418190587263600148770280649306"
          "958101930",
          "4082367875863433681332203403145435568316851327593401208105741076214"
          "120093531"));
  return r;
}

template <typename G>
G const& GZero() {
  static auto z = []() {
    G r;
    r.clear();
    return r;
  };
  static const auto g = z();
  return g;
}

// opportunistic fr mul
inline Fr OpFrMul(Fr const& a, Fr const& b, bool check1 = false) {
  if (a.isZero() || b.isZero()) return FrZero();
  if (check1) {
    if (a.isOne()) return b;
    if (b.isOne()) return a;
  }
  return a * b;
}

inline Fr OpFrAdd(Fr const& a, Fr const& b) {
  if (a.isZero()) return b;
  if (b.isZero()) return a;
  return a + b;
}

inline G1 MapToG1(Fp t) {
  G1 r;
  bool b;
  for (;;) {
    mcl::bn256::mapToG1(&b, r, t);
    if (b) break;
    t = t + 1;
  }
  return r;
}

inline G1 MapToG1(void const* b, size_t n) {
  G1 r;
  mcl::bn256::hashAndMapToG1(r, b, n);
  return r;
}

inline G1 MapToG1(std::string const& s) {
  G1 r;
  mcl::bn256::hashAndMapToG1(r, s.data(), s.size());
  return r;
}

inline void MapToG1(std::string const& s, G1* r) {
  mcl::bn256::hashAndMapToG1(*r, s.data(), s.size());
}

inline G1Ptr MapToG1Ptr(void const* b, size_t n) {
  G1Ptr r = std::make_shared<G1>();
  mcl::bn256::hashAndMapToG1(*r, b, n);
  return r;
}

inline G1Ptr MapToG1Ptr(std::string const& s) {
  G1Ptr r = std::make_shared<G1>();
  mcl::bn256::hashAndMapToG1(*r, s.data(), s.size());
  return r;
}

inline G2 MapToG2(Fp2 t) {
  G2 r;
  bool b;
  for (;;) {
    mcl::bn256::mapToG2(&b, r, t);
    if (b) break;
    t = t + 1;
  }
  return r;
}

inline G2 MapToG2(void const* b, size_t n) {
  G2 r;
  mcl::bn256::hashAndMapToG2(r, b, n);
  return r;
}

inline G2 MapToG2(std::string const& s) {
  G2 r;
  mcl::bn256::hashAndMapToG2(r, s.data(), s.size());
  return r;
}

// because the Fr is 254bits, so we only use 31bytes
inline Fr BinToFr31(void const* start, void const* end) {
  assert((end > start) && ((uint8_t*)end - (uint8_t*)start) <= 31);
  uint8_t buf[32];
  size_t len = (uint8_t*)end - (uint8_t*)start;
  len = std::min<size_t>(len, 31);
  memcpy(buf, start, len);
  memset(buf + len, 0, sizeof(buf) - len);

  Fr fr;
  fr.deserialize(buf, 32);

  return fr;
}

inline Fr MapToFr(void const* b, size_t n) {
  CryptoPP::Keccak_256 hash;
  h256_t digest;
  hash.Update((uint8_t const*)b, n);
  hash.Final(digest.data());
  return BinToFr31(digest.data(), digest.data() + 31);
}

inline Fr MapToFr(uint64_t b) {
  auto b_big = boost::endian::native_to_big(b);
  return MapToFr((uint8_t const*)&b_big, sizeof(b_big));
}

// inner product
inline G1 MultiExp(G1 const* g, Fr const* f, size_t n) {
  G1 r = G1Zero();
  for (size_t i = 0; i < n; ++i) {
    r += g[i] * f[i];
  }
  return r;
}

// a * g + b * g
inline G1 MultiExp(G1 const& g, Fr const& a, G1 const& h, Fr const& b) {
  return g * a + h * b;
}

inline G1 MultiExp(G1 const* g, Fr const* a, G1 const* h, Fr const* b,
                   size_t n) {
  auto r1 = MultiExp(g, a, n);
  auto r2 = MultiExp(h, b, n);
  return r1 + r2;
}

struct FrW {
  Fr v;

  FrW() { v = FrZero(); }                   // 零初始化
  explicit FrW(const Fr& x) : v(x) {}
  FrW(const FrW&) = default;
  FrW& operator=(const FrW&) = default;

  // 复合赋值
  FrW& operator+=(const FrW& b){ v += b.v; return *this; }
  FrW& operator-=(const FrW& b){ v -= b.v; return *this; }
  FrW& operator*=(const FrW& b){ Fr t; Fr::mul(t, v, b.v); v = t; return *this; }
};

// 二元运算（仅对 FrW 与 FrW，避免被 mcl 的模板抢走）
inline FrW operator+(const FrW& a, const FrW& b){ FrW r; r.v = a.v; r.v += b.v; return r; }
inline FrW operator-(const FrW& a, const FrW& b){ FrW r; r.v = a.v; r.v -= b.v; return r; }
inline FrW operator*(const FrW& a, const FrW& b){ FrW r; Fr::mul(r.v, a.v, b.v); return r; }
inline bool operator==(const FrW& a, const FrW& b){ return a.v == b.v; }
inline bool operator!=(const FrW& a, const FrW& b){ return !(a==b); }

namespace Eigen {
template<> struct NumTraits<Fr> 
    : GenericNumTraits<Fr> 
{
    typedef Fr Real;
    typedef Fr NonInteger;
    typedef Fr Nested;
    
    enum {
        IsComplex = 0,
        IsInteger = 0,
        IsSigned = 1,
        RequireInitialization = 1,
        ReadCost = 1,
        AddCost = 3,
        MulCost = 3,
    };

  static inline Real epsilon()         { return FrZero(); }
  static inline Real dummy_precision() { return FrZero(); }
};
} // namespace Eigen

using MatrixFr = Eigen::Matrix<FrW, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>;
using ColVectorFr = Eigen::Matrix<FrW, Eigen::Dynamic, 1>;
using RowVectorFr = Eigen::Matrix<FrW, 1, Eigen::Dynamic>;

// ========================================================================
// FlatMatrix: Row-major contiguous memory layout matrix
// ========================================================================
struct FlatMatrix {
  int64_t rows_ = 0;
  int64_t cols_ = 0;
  std::vector<Fr> data_;

  FlatMatrix() = default;
  FlatMatrix(int64_t rows, int64_t cols)
      : rows_(rows), cols_(cols), data_(rows * cols) {}
  FlatMatrix(int64_t rows, int64_t cols, Fr const& fill_value)
      : rows_(rows), cols_(cols), data_(rows * cols, fill_value) {}

  int64_t rows() const { return rows_; }
  int64_t cols() const { return cols_; }
  bool empty() const { return rows_ == 0 || cols_ == 0; }

  Fr& operator()(int64_t i, int64_t j) { return data_[i * cols_ + j]; }
  Fr const& operator()(int64_t i, int64_t j) const { return data_[i * cols_ + j]; }

  Fr* row_ptr(int64_t i) { return data_.data() + i * cols_; }
  Fr const* row_ptr(int64_t i) const { return data_.data() + i * cols_; }

  std::vector<Fr> col(int64_t j) const {
    std::vector<Fr> result(rows_);
    auto parallel_f = [this, &result, j](int64_t i) {
      result[i] = data_[i * cols_ + j];
    };
    parallel::For(rows_, parallel_f);
    return result;
  }

  std::vector<Fr> row(int64_t i) const {
    std::vector<Fr> result(cols_);
    Fr const* ptr = row_ptr(i);
    std::copy(ptr, ptr + cols_, result.begin());
    return result;
  }

  // Fill entire matrix with a value
  void fill(Fr const& value) {
    auto parallel_f = [this, &value](int64_t i) {
      data_[i] = value;
    };
    parallel::For((int64_t)data_.size(), parallel_f);
  }

  // Resize and zero-fill
  void resize(int64_t rows, int64_t cols) {
    rows_ = rows;
    cols_ = cols;
    data_.assign(rows * cols, FrZero());
  }

  // Element-wise addition: this += other
  FlatMatrix& operator+=(FlatMatrix const& other) {
    assert(rows_ == other.rows_ && cols_ == other.cols_);
    auto parallel_f = [this, &other](int64_t i) {
      data_[i] += other.data_[i];
    };
    parallel::For((int64_t)data_.size(), parallel_f);
    return *this;
  }

  // Row-vector addition: row(i) += vec
  void addToRow(int64_t i, std::vector<Fr> const& vec) {
    assert((int64_t)vec.size() == cols_);
    Fr* ptr = row_ptr(i);
    for (int64_t j = 0; j < cols_; ++j) {
      ptr[j] += vec[j];
    }
  }

  // Row-vector scaled addition: row(i) += vec * scalar
  void addScaledToRow(int64_t i, std::vector<Fr> const& vec, Fr const& scalar) {
    assert((int64_t)vec.size() == cols_);
    Fr* ptr = row_ptr(i);
    for (int64_t j = 0; j < cols_; ++j) {
      ptr[j] += vec[j] * scalar;
    }
  }

  // Scalar multiply entire row: row(i) *= scalar
  void scaleRow(int64_t i, Fr const& scalar) {
    Fr* ptr = row_ptr(i);
    for (int64_t j = 0; j < cols_; ++j) {
      ptr[j] *= scalar;
    }
  }

  bool operator==(FlatMatrix const& other) const {
    if (rows_ != other.rows_ || cols_ != other.cols_) return false;
    for (size_t i = 0; i < data_.size(); ++i) {
      if (data_[i] != other.data_[i]) return false;
    }
    return true;
  }

  bool operator!=(FlatMatrix const& other) const { return !(*this == other); }

  static FlatMatrix FromVecVec(std::vector<std::vector<Fr>> const& vv) {
    if (vv.empty()) return FlatMatrix();
    int64_t rows = (int64_t)vv.size();
    int64_t cols = (int64_t)vv[0].size();
    FlatMatrix mat(rows, cols);
    auto parallel_f = [&vv, &mat, cols](int64_t i) {
      mat.data_[i] = vv[i / cols][i % cols];
    };
    parallel::For(rows * cols, parallel_f);
    return mat;
  }
};

inline void ConvertFlatToMat(FlatMatrix const& a, MatrixFr & ret){
  auto parallel_f = [&a, &ret](int64_t i) {
    int64_t row = i / a.cols(), col = i % a.cols();
    ret(row, col) = FrW(a(row, col));
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
}

inline void ConvertVecToMat(FlatMatrix const& a, MatrixFr & ret){
  auto parallel_f = [&a, &ret](int64_t i) {
    int64_t row = i / a.cols(), col = i % a.cols();
    ret(row, col) = FrW(a(row, col));
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
}

inline void ConvertVecToMat(std::vector<Fr> const& a, RowVectorFr & ret){
  auto parallel_f = [&a, &ret](int64_t i) {
    ret(i) = FrW(a[i]);
  };
  parallel::For(a.size(), parallel_f);
}

inline void ConvertVecToMat(std::vector<Fr> const& a, ColVectorFr & ret){
  auto parallel_f = [&a, &ret](int64_t i) {
    ret(i) = FrW(a[i]);
  };
  parallel::For(a.size(), parallel_f);
}

inline void ConvertMatToVec(FlatMatrix & ret, MatrixFr const& a){
  ret.resize(a.rows(), a.cols());
  auto parallel_f = [&a, &ret](int64_t i) {
    int64_t row = i / ret.cols(), col = i % ret.cols();
    ret(row, col) = a(row, col).v;
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
}

inline void ConvertMatToVec(std::vector<Fr> & ret, RowVectorFr const& a){
  ret.resize(a.cols());
  auto parallel_f = [&a, &ret](int64_t i) {
    ret[i] = a(i).v;
  };
  parallel::For(a.cols(), parallel_f);
}

inline void ConvertMatToVec(std::vector<Fr> & ret, ColVectorFr const& a){
  ret.resize(a.rows());
  auto parallel_f = [&a, &ret](int64_t i) {
    ret[i] = a(i).v;
  };
  parallel::For(a.rows(), parallel_f);
}

inline Fr InnerProduct(Fr const* a, Fr const* b, size_t n) {
  if (n == 0) return FrZero();
  if (n == 1) return a[0] * b[0];

  std::vector<Fr> rets(n);
  auto parallel_f = [a, b, &rets](int64_t i) { rets[i] = a[i] * b[i]; };
  parallel::For(n, parallel_f);
  return parallel::Accumulate(rets.begin(), rets.end(), FrZero());
}

inline Fr Sum(std::vector<Fr> const& a){
  assert(!a.empty());
  return parallel::Accumulate(a.begin(), a.end(), FrZero());
}

inline Fr InnerProduct(std::vector<Fr> const& a, FlatMatrix const& b, size_t j) {
  assert((int64_t)a.size() == b.rows() && (int64_t)j < b.cols());
  std::vector<Fr> rets(a.size());
  auto parallel_f = [&rets, &a, &b, j](int64_t i) { rets[i] = a[i] * b(i, j); };
  parallel::For((int64_t)a.size(), parallel_f);
  return parallel::Accumulate(rets.begin(), rets.end(), FrZero());
}

//a, b的长度可能不等, 只用最小的长度作为内积输入
inline Fr InnerProduct(std::vector<Fr> const& a, std::vector<Fr> const& b) {
  // assert(a.size() == b.size());
  size_t n = std::min(a.size(), b.size());
  return InnerProduct(a.data(), b.data(), n);
}

inline Fr InnerProduct(FlatMatrix const& a, FlatMatrix const& b) {
  assert(a.rows() == b.rows() && a.cols() == b.cols());
  std::vector<Fr> c(a.rows());
  auto parallel_f = [&a, &b, &c](size_t i) {
    Fr const* row_a = a.row_ptr(i);
    Fr const* row_b = b.row_ptr(i);
    c[i] = InnerProduct(row_a, row_b, a.cols());
  };
  parallel::For((int64_t)c.size(), parallel_f);
  return parallel::Accumulate(c.begin(), c.end(), FrZero());
}

inline Fr InnerProduct(std::function<Fr(size_t)> const& get_a,
                       std::vector<Fr> const& b){
  std::vector<Fr> rets(b.size());
  auto parallel_f = [&rets, &get_a, &b](size_t i) {
    rets[i] = get_a(i) * b[i];
  };
  parallel::For(b.size(), parallel_f);
  return parallel::Accumulate(rets.begin(), rets.end(), FrZero());
}

inline Fr InnerProduct(std::function<Fr(size_t)> const& get_a,
                       std::function<Fr(size_t)> const& get_b, size_t n) {
  std::vector<Fr> rets(n);
  auto parallel_f = [&rets, &get_a, &get_b](size_t i) {
    rets[i] = get_a(i) * get_b(i);
  };
  parallel::For(n, parallel_f);
  return parallel::Accumulate(rets.begin(), rets.end(), FrZero());
}

// MatrixVectorMul for FlatMatrix: result[i] = sum_j mat(i,j) * vec[j]
// This computes mat * vec (standard matrix-vector multiply).
inline void MatrixVectorMul(FlatMatrix const& mat,
                            std::vector<Fr> const& vec,
                            std::vector<Fr>& result) {
  int64_t rows = mat.rows();
  int64_t cols = mat.cols();
  result.resize(rows);
  
  auto parallel_f = [&](int64_t i) {
    result[i] = InnerProduct(mat.row_ptr(i), vec.data(), cols);
  };
  parallel::For(rows, parallel_f);
}

// MatrixVectorMul for FlatMatrix with vec first: result[j] = sum_i mat(i,j) * vec[i]
// This computes mat^T * vec (left-multiply by row vector / transpose multiply).
inline void MatrixVectorMul(std::vector<Fr> const& vec,
                            FlatMatrix const& mat,
                            std::vector<Fr>& result) {
  int64_t cols = mat.cols();
  result.resize(cols);
  
  auto parallel_f = [&](int64_t j) {
    result[j] = InnerProduct(vec, mat, j);
  };
  parallel::For(cols, parallel_f);
}


inline void MatrixVectorMul(std::function<Fr(size_t)> const& get_a, FlatMatrix const& b, std::vector<Fr> & c){
  c.resize(b.cols());
  auto parallel_f = [&c, &get_a, &b](int64_t j) {
    auto get_b = [&b, j](size_t i) -> Fr { return b(i, j); };
    c[j] = InnerProduct(get_b, get_a, b.rows());
  };
  parallel::For(b.cols(), parallel_f);
}

inline std::vector<Fr> MatrixVectorMul(FlatMatrix const& a, std::vector<Fr> const& b){
  assert((int64_t)b.size() == a.cols());
  std::vector<Fr> c(a.rows());
  MatrixVectorMul(a, b, c);
  return c;
}

inline std::vector<Fr> MatrixVectorMul(std::vector<Fr> const& a, FlatMatrix const& b){
  assert((int64_t)a.size() == b.rows());
  std::vector<Fr> c(b.cols());
  MatrixVectorMul(a, b, c);
  return c;
}

inline void OuterProduct(std::vector<Fr> const& a, std::vector<Fr> const& b, FlatMatrix & c){
  c.resize(a.size(), b.size());
  auto parallel_f = [&a, &b, &c](size_t i){
    size_t row = i / b.size(), col = i % b.size();
    c(row, col) = a[row] * b[col];
  };
  parallel::For(a.size() * b.size(), parallel_f);
}

inline void OuterProduct(std::vector<Fr> const& a, std::vector<Fr> const& b, std::vector<Fr> & c){
  c.resize(a.size() * b.size());
  auto parallel_f = [&a, &b, &c](size_t i){
    size_t row = i / b.size(), col = i % b.size();
    c[i] = a[row] * b[col];
  };
  parallel::For(c.size(), parallel_f);
}

inline void MatrixSum(FlatMatrix & a, FlatMatrix const& b){
  assert(a.rows() == b.rows() && a.cols() == b.cols());
  auto parallel_f = [&a, &b](int64_t i) {
    a.data_[i] += b.data_[i];
  };
  parallel::For((int64_t)a.data_.size(), parallel_f);
}

inline FlatMatrix MatrixMul(FlatMatrix const& a, Fr const& b){
  FlatMatrix c(a.rows(), a.cols());
  auto parallel_f = [&c, &a, &b](int64_t idx) {
    c.data_[idx] = a.data_[idx] * b;
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
  return c;
}

inline void MatrixMul(FlatMatrix & c, FlatMatrix const& a, Fr const& b){
  c.resize(a.rows(), a.cols());
  auto parallel_f = [&c, &a, &b](int64_t idx) {
    c.data_[idx] = a.data_[idx] * b;
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
}

inline void MatrixMul(FlatMatrix const& a, FlatMatrix const& b, FlatMatrix & c){
  assert(a.cols() == b.rows());
  int64_t m = a.rows();
  int64_t n = a.cols();
  int64_t p = b.cols();
  c.resize(m, p);

  using EigenMatFr = Eigen::Matrix<Fr, Eigen::Dynamic, Eigen::Dynamic, Eigen::RowMajor>;
  using ConstMapFr = Eigen::Map<const EigenMatFr>;
  using MapFr      = Eigen::Map<EigenMatFr>;

  ConstMapFr ea(a.data_.data(), m, n);
  ConstMapFr eb(b.data_.data(), n, p);
  MapFr      ec(c.data_.data(), m, p);

  ec.noalias() = ea * eb;
}

inline FlatMatrix MatrixMul(FlatMatrix const& a, FlatMatrix const& b){
  FlatMatrix c;
  MatrixMul(a, b, c);
  return c;
}

inline void HadamardProduct(std::vector<Fr>& c, std::vector<Fr> const& a,
                            std::vector<Fr> const& b) {
  size_t mx = std::max(a.size(), b.size());
  size_t mn = std::min(a.size(), b.size());
  c.resize(mx, 0);
  auto parallel_f = [&c, &a, &b](size_t i) { c[i] = a[i] * b[i]; };
  parallel::For(mn, parallel_f);  // n < 16 * 1024);
}

inline std::vector<Fr> HadamardProduct(Fr const* a, Fr const* b, size_t n) {
  std::vector<Fr> c(n);
  auto parallel_f = [&c, a, b](int64_t i) { c[i] = a[i] * b[i]; };
  parallel::For(n, parallel_f);
  return c;
}

inline void HadamardProduct(FlatMatrix const& a,
                            FlatMatrix const& b,
                            FlatMatrix & c) {
  assert(a.rows() == b.rows() && a.cols() == b.cols());
  c.resize(a.rows(), a.cols());
  auto parallel_f = [&c, &a, &b](int64_t i) {
    c.data_[i] = a.data_[i] * b.data_[i];
  };
  parallel::For(a.rows() * a.cols(), parallel_f);
}

inline FlatMatrix HadamardProduct(FlatMatrix const& a,
                                  FlatMatrix const& b) {
  FlatMatrix c;
  HadamardProduct(a, b, c);
  return c;
}

//支持不同长度
inline std::vector<Fr> HadamardProduct(std::vector<Fr> const& a,
                                       std::vector<Fr> const& b) {
  std::vector<Fr> c;
  HadamardProduct(c, a, b);
  return c;
}

void ComputeWitness(FlatMatrix const& w,
                    FlatMatrix const& a,
                    FlatMatrix const& b,
                    FlatMatrix const& c,
                    FlatMatrix & wa,
                    FlatMatrix & wb,
                    FlatMatrix & wc,
                    std::vector<Fr> const& r_com_w,
                    std::vector<Fr> & r_com_wa,
                    std::vector<Fr> & r_com_wb,
                    std::vector<Fr> & r_com_wc){
  Tick tick(__FN__);

  assert(a.cols() == w.rows());

  wa.resize(a.rows(), w.cols());
  wb.resize(a.rows(), w.cols());
  wc.resize(a.rows(), w.cols());
  wa.fill(FrZero());
  wb.fill(FrZero());
  wc.fill(FrZero());
  r_com_wa.resize(a.rows(), FrZero());
  r_com_wb.resize(a.rows(), FrZero());
  r_com_wc.resize(a.rows(), FrZero());

  //这里不要用MatrixMul, 很慢
  std::array<parallel::VoidTask, 3> tasks;
  tasks[0] = [&w, &a, &wa, &r_com_w, &r_com_wa]() {
    auto parallel_f = [&w, &a, &wa, &r_com_w, &r_com_wa](size_t i){
        for(int64_t j=0; j<a.cols(); j++){
            Fr const& aij = a(i, j);
            if(aij == FrZero()) continue;
            Fr* wa_row = wa.row_ptr(i);
            Fr const* w_row = w.row_ptr(j);
            if(aij == FrOne()){
              for(int64_t k=0; k<w.cols(); k++) wa_row[k] += w_row[k];
              r_com_wa[i] += r_com_w[j];
            }else{
              for(int64_t k=0; k<w.cols(); k++) wa_row[k] += w_row[k] * aij;
              r_com_wa[i] += r_com_w[j] * aij;
            }
        }
    };
    parallel::For(a.rows(), parallel_f);
  };
  tasks[1] = [&w, &b, &wb, &r_com_w, &r_com_wb]() {
    auto parallel_f = [&w, &b, &wb, &r_com_w, &r_com_wb](size_t i){
        for(int64_t j=0; j<b.cols(); j++){
            Fr const& bij = b(i, j);
            if(bij == FrZero()) continue;
            Fr* wb_row = wb.row_ptr(i);
            Fr const* w_row = w.row_ptr(j);
            if(bij == FrOne()){
              for(int64_t k=0; k<w.cols(); k++) wb_row[k] += w_row[k];
              r_com_wb[i] += r_com_w[j];
            }else{
              for(int64_t k=0; k<w.cols(); k++) wb_row[k] += w_row[k] * bij;
              r_com_wb[i] += r_com_w[j] * bij;
            }
        }
    };
    parallel::For(b.rows(), parallel_f);
  };
  tasks[2] = [&w, &c, &wc, &r_com_w, &r_com_wc]() {
      auto parallel_f = [&w, &c, &wc, &r_com_w, &r_com_wc](size_t i){
          for(int64_t j=0; j<c.cols(); j++){
              Fr const& cij = c(i, j);
              if(cij == FrZero()) continue;
              Fr* wc_row = wc.row_ptr(i);
              Fr const* w_row = w.row_ptr(j);
              if(cij == FrOne()){
                for(int64_t k=0; k<w.cols(); k++) wc_row[k] += w_row[k];
                r_com_wc[i] += r_com_w[j];
              }else{
                for(int64_t k=0; k<w.cols(); k++) wc_row[k] += w_row[k] * cij;
                r_com_wc[i] += r_com_w[j] * cij;
              }
          }
      };
      parallel::For(c.rows(), parallel_f);
  };
  parallel::Invoke(tasks);

  assert(HadamardProduct(wa, wb) == wc);
}

void ComputeWitness(FlatMatrix const& w,
                    FlatMatrix const& a,
                    FlatMatrix const& b,
                    FlatMatrix const& c,
                    FlatMatrix & wa,
                    FlatMatrix & wb,
                    FlatMatrix & wc){
  Tick tick(__FN__);
  assert(a.cols() == w.rows());

  wa.resize(a.rows(), w.cols());
  wb.resize(a.rows(), w.cols());
  wc.resize(a.rows(), w.cols());
  wa.fill(FrZero());
  wb.fill(FrZero());
  wc.fill(FrZero());

  //这里不要用MatrixMul, 很慢
  std::array<parallel::VoidTask, 3> tasks;
  tasks[0] = [&a, &wa, &w]() {
      auto parallel_f = [&w, &a, &wa](size_t i){
          for(int64_t j=0; j<a.cols(); j++){
              Fr const& aij = a(i, j);
              if(aij == FrZero()) continue;
              Fr* wa_row = wa.row_ptr(i);
              Fr const* w_row = w.row_ptr(j);
              if(aij == FrOne()){
                for(int64_t k=0; k<w.cols(); k++) wa_row[k] += w_row[k];
              }else{
                for(int64_t k=0; k<w.cols(); k++) wa_row[k] += w_row[k] * aij;
              }
          }
      };
      parallel::For(a.rows(), parallel_f);
  };
  tasks[1] = [&w, &b, &wb]() {
      auto parallel_f = [&w, &b, &wb](size_t i){
          for(int64_t j=0; j<b.cols(); j++){
              Fr const& bij = b(i, j);
              if(bij == FrZero()) continue;
              Fr* wb_row = wb.row_ptr(i);
              Fr const* w_row = w.row_ptr(j);
              if(bij == FrOne()){
                for(int64_t k=0; k<w.cols(); k++) wb_row[k] += w_row[k];
              }else{
                for(int64_t k=0; k<w.cols(); k++) wb_row[k] += w_row[k] * bij;
              }
          }
      };
      parallel::For(b.rows(), parallel_f);
  };
  tasks[2] = [&w, &c, &wc]() {
      auto parallel_f = [&w, &c, &wc](size_t i){
          for(int64_t j=0; j<c.cols(); j++){
              Fr const& cij = c(i, j);
              if(cij == FrZero()) continue;
              Fr* wc_row = wc.row_ptr(i);
              Fr const* w_row = w.row_ptr(j);
              if(cij == FrOne()){
                for(int64_t k=0; k<w.cols(); k++) wc_row[k] += w_row[k];
              }else{
                for(int64_t k=0; k<w.cols(); k++) wc_row[k] += w_row[k] * cij;
              }
          }
      };
      parallel::For(c.rows(), parallel_f);
  };
  parallel::Invoke(tasks);

  assert(HadamardProduct(wa, wb) == wc);
}

inline Fr StrHashToFr(std::string const& s) {
  Fr f;
  f.setHashOf(s.data(), s.size());
  return f;
}

// the buffer of start must >= 32
inline bool BinToFr32(void const* start, Fr* fr) {
  return fr->deserialize(start, 32) == 32;
}

inline Fr BinToFr32(void const* start) {
  Fr r;
  CHECK(BinToFr32(start, &r), "");
  return r;
}

inline Fr H256ToFr(h256_t const& digest) {
  Fr r;
  bool success = false;
  r.setArray(&success, digest.data(), digest.size(), mcl::fp::Mod);
  assert(success);
  return r;
}

// buf must 32 bytes, if the fr comes from BinToFr31(), the buf[31] will be 0
inline void FrToBin(Fr const& fr, uint8_t* buf) {
  CHECK(fr.serialize(buf, 32) == 32, "");
}

inline h256_t FrToBin(Fr const& fr) {
  h256_t ret;
  FrToBin(fr, ret.data());
  return ret;
}

inline bool StrToFr(std::string const& s, Fr* fr) {
  try {
    fr->setStr(s);
    return true;
  } catch (std::exception&) {
    return false;
  }
}

// may throw exception
inline Fr StrToFr(std::string const& s) {
  Fr fr;
  fr.setStr(s);
  return fr;
}

inline std::string FrToStr(Fr const& fr) { return fr.getStr(); }

inline std::string UnPackStrFromFr(Fr const& fr) {
  uint8_t buf[32];
  FrToBin(fr, buf);
  assert(buf[31] == 0);
  buf[31] = 0;
  return std::string((char const*)buf);
}

// ex: if s = "ab", return 25185, BinToFr32 use little endian
// NOTE: we do not allow the '\0' in s.
inline Fr PackStrToFr(char const* s) {
  auto size = strlen(s);
  assert(size <= 31);
  size_t copy_len = std::min<size_t>(size, 31);
  uint8_t buf[32];
  memcpy(buf, s, copy_len);
  memset(buf + copy_len, 0, sizeof(buf) - copy_len);
  Fr ret = BinToFr32(buf);
#ifdef _DEBUG
  auto check_s = UnPackStrFromFr(ret);
  assert(check_s == s);
#endif
  return ret;
}

// the p[i] must belongs to [0, 1<<bits)
//bits为数独元素最少需要几个bit表示
std::vector<Fr> PackUintToFr(size_t bits, std::vector<Fr> const& units) {
  for (size_t i = 0; i < units.size(); ++i) {    
    assert(units[i].getMpz() < (mpz_class(1) << bits));
  }  

  size_t count = 253 / bits; //一个域元素可以装几个数独元素
  std::vector<Fr> ret((units.size() + count - 1) / count); //需要几个域元素装数独
  
  std::vector<Fr> pow_of_2(count);
  for (size_t i = 0; i < count; ++i) {
    pow_of_2[i].setMpz(mpz_class(1) << (i * bits));
  }

  for (size_t i = 0; i < ret.size(); ++i) {
    ret[i] = FrZero();    
    for (size_t j = 0; j < count; ++j) {
      if (i * count + j == units.size()) break;
      ret[i] += units[i * count + j] * pow_of_2[j];
    }
  }
  return ret;
}

inline Fr FrBitsToFr(Fr const* p, size_t size) {
  assert(size <= 253);
  boost::dynamic_bitset<uint8_t> bitset(256);
  for (size_t i = 0; i < size; ++i) {
    bitset[i] = p[i] == FrOne();
  }
  for (size_t i = size; i < 256; ++i) {
    bitset[i] = 0;
  }

  // Copy bytes to buffer
  std::vector<uint8_t> bytes;
  boost::to_block_range(bitset, std::back_inserter(bytes));
  assert(bytes.size() == 32);

  auto ret = BinToFr32(bytes.data());

#ifdef _DEBUG
  mpz_class mpz = misc::MpzFromLE(bytes.data(), bytes.size());
  Fr ret2;
  ret2.setMpz(mpz);
  assert(ret == ret2);
#endif

  return ret;
}

inline std::vector<Fr> FrBitsToFrs(Fr const* p, size_t size) {
  std::vector<Fr> ret((size + 252) / 253);
  for (size_t i = 0; i < ret.size(); ++i) {
    ret[i] = FrBitsToFr(p, std::min<size_t>(size, 253));
    p += 253;
    size -= 253;
  }
  return ret;
}

inline std::vector<Fr> FrBitsToFrs(std::vector<Fr> const& bits) {
  return FrBitsToFrs(bits.data(), bits.size());
}

inline std::vector<Fr> FrToFrBits(Fr const& f) {
  std::vector<Fr> ret(253);
  h256_t h = FrToBin(f);
  boost::dynamic_bitset<uint8_t> bitset(h.begin(), h.end());
  assert(bitset[253] == 0);
  assert(bitset[253] == 0);
  assert(bitset[254] == 0);
  for (auto i = 0; i < 253; ++i) {
    ret[i] = bitset[i] ? FrOne() : FrZero();
  }

#ifdef _DEBUG
  std::vector<Fr> pow2(253);
  for (auto i = 0; i < 253; ++i) {
    if (i == 0)
      pow2[i] = 1;
    else
      pow2[i] = pow2[i - 1] + pow2[i - 1];
  }

  auto ip = InnerProduct(ret, pow2);
  assert(f == ip);
#endif
  return ret;
}

inline std::vector<Fr> FrsToFrBits(std::vector<Fr> const& f) {
  std::vector<Fr> ret;
  ret.reserve(f.size() * 253);
  for (auto const& i : f) {
    auto a = FrToFrBits(i);
    ret.insert(ret.end(), a.begin(), a.end());
  }
  return ret;
}

inline boost::dynamic_bitset<uint8_t> FrsToBitset(Fr const* f, size_t size) {
  boost::dynamic_bitset<uint8_t> ret;
  ret.resize(size * 253);
  for (size_t i = 0; i < size; ++i) {
    h256_t h = FrToBin(f[i]);
    boost::dynamic_bitset<uint8_t> b(h.begin(), h.end());
    for (auto j = 0; j < 253; ++j) {
      ret[i * 253 + j] = b[j];
    }
  }
  return ret;
}

// would throw if mpz is invalid
inline Fr SignedMpzToFr(mpz_class const mpz) {
  Fr fr;
  if (mpz >= 0) {
    fr.setMpz(mpz);
  } else {
    fr.setMpz(-mpz);
    fr = -fr;
  }
  return fr;
}

inline mpz_class FrToSignedMpz(Fr const& fr) {
  return fr.isNegative() ? -((-fr).getMpz()) : fr.getMpz();
}

// buf must 32 bytes
inline bool BinToG1(uint8_t const* buf, G1* g) {
  return g->deserialize(buf, 32) == 32;
}

inline G1 BinToG1(uint8_t const* buf) {
  G1 r;
  CHECK(BinToG1(buf, &r), "");
  return r;
}

// buf must 32 bytes
inline void G1ToBin(G1 const& g, uint8_t* buf) {
  CHECK(g.serialize(buf, 32) == 32, "");
}

inline h256_t G1ToBin(G1 const& g) {
  h256_t r;
  G1ToBin(g, r.data());
  return r;
}

// capability of buffer >= kG1FlatBinSize
inline void G1ToFlatBin(G1 const& g, uint8_t* const buf) {
  if (g.isZero()) {
    memset(buf, 0, kG1FlatBinSize);
    return;
  }

  uint8_t* p = buf;
  G1 g_normalized;
  G1 const* pg;
  if (!g.isNormalized()) {
    g_normalized = g;
    g_normalized.normalize();
    pg = &g_normalized;
  } else {
    pg = &g;
  }

  assert(pg->z == 1);

  p[0] = 1;
  ++p;

  pg->x.serialize(p, kFpBinSize);
  p += kFpBinSize;
  pg->y.serialize(p, kFpBinSize);
}

inline bool FlatBinToG1(uint8_t const* const buf, G1* g) {
  if (buf[0] == 0) {
    g->clear();
    return true;
  }

  uint8_t const* p = buf;
  assert(p[0] == 1);
  g->z = 1;
  ++p;

  size_t n = g->x.deserialize(p, kFpBinSize);
  p += kFpBinSize;
  assert(n);
  if (n == 0) return false;

  n = g->y.deserialize(p, kFpBinSize);
  assert(n);
  return n > 0;
}

inline G1 FlatBinToG1(uint8_t const* const buf) {
  G1 r;
  CHECK(FlatBinToG1(buf, &r), "");
  return r;
}

inline bool StrToG1(std::string const& s, G1* g) {
  try {
    g->setStr(s);
    return true;
  } catch (std::exception&) {
    return false;
  }
}

// may throw
inline G1 StrToG1(std::string const& s) {
  G1 g;
  g.setStr(s);
  return g;
}

inline std::string G1ToStr(G1 const& g) { return g.getStr(); }

// buf must 64 bytes
inline bool BinToG2(uint8_t const* buf, G2* g) {
  return g->deserialize(buf, 64) == 64;
}

inline G2 BinToG2(uint8_t const* buf) {
  G2 r;
  CHECK(BinToG2(buf, &r), "");
  return r;
}

// buf must 64 bytes
inline void G2ToBin(G2 const& g, uint8_t* buf) {
  CHECK(g.serialize(buf, 64) == 64, "");
}

// >= kG2FlatBinSize
inline void G2ToFlatBin(uint8_t* const buf, const G2* g) {
  if (g->isZero()) {
    memset(buf, 0, kG2FlatBinSize);
    return;
  }

  uint8_t* p = buf;
  G2 g_normalized;
  if (!g->isNormalized()) {
    g_normalized = *g;
    g_normalized.normalize();
    g = &g_normalized;
  }

  assert(g->z == 1);

  p[0] = 1;
  ++p;

  g->x.serialize(p, kFp2BinSize);
  p += kFp2BinSize;
  g->y.serialize(p, kFp2BinSize);
}

// kG2FlatBinSize
inline bool FlatBinToG2(uint8_t const* const buf, G2* g) {
  if (buf[0] == 0) {
    g->clear();
    return true;
  }

  uint8_t const* p = buf;
  assert(p[0] == 1);
  g->z = 1;
  ++p;

  size_t n = g->x.deserialize(p, kFp2BinSize);
  p += kFp2BinSize;
  if (n == 0) return false;

  n = g->y.deserialize(p, kFp2BinSize);
  return n > 0;
}

inline G2 FlatBinToG2(uint8_t const* const buf) {
  G2 r;
  CHECK(FlatBinToG2(buf, &r), "");
  return r;
}

inline bool StrToG2(std::string const& s, G2* g) {
  try {
    g->setStr(s);
    return true;
  } catch (std::exception&) {
    return false;
  }
}

// may throw exception
inline G2 StrToG2(std::string const& s) {
  G2 g;
  g.setStr(s);
  return g;
}



inline std::string G2ToStr(G2 const& g) { return g.getStr(); }

inline uint64_t GetG1wmFlatLen(G1WM const& wm) {
  uint64_t size = sizeof(uint64_t) * 3;
  size += wm.tbl_.size() * kG1FlatBinSize;
  return size;
}

inline uint64_t GetG2wmFlatLen(G2WM const& wm) {
  uint64_t size = sizeof(uint64_t) * 3;
  size += wm.tbl_.size() * kG2FlatBinSize;
  return size;
}

inline bool FlatBinToG1wm(uint8_t const* buf, size_t len, G1WM& wm) {
  uint8_t const* p = buf;
  uint64_t left_len = len;

  if (len <= sizeof(uint64_t) * 3) return false;

  uint64_t bit_size;
  memcpy(&bit_size, p, sizeof(bit_size));
  p += sizeof(bit_size);
  bit_size = boost::endian::big_to_native(bit_size);
  wm.bitSize_ = bit_size;
  assert(wm.bitSize_);
  if (!wm.bitSize_) return false;

  uint64_t win_size;
  memcpy(&win_size, p, sizeof(win_size));
  p += sizeof(win_size);
  win_size = boost::endian::big_to_native(win_size);
  wm.winSize_ = win_size;
  assert(wm.winSize_);
  if (!wm.winSize_) return false;

  uint64_t tbl_size;
  memcpy(&tbl_size, p, sizeof(tbl_size));
  p += sizeof(tbl_size);
  tbl_size = boost::endian::big_to_native(tbl_size);
  assert(tbl_size);
  if (!tbl_size) return false;

  uint64_t check_tbl_size =
      (bit_size + win_size - 1) / win_size * ((uint64_t)1 << win_size);
  if (tbl_size != check_tbl_size) return false;

  left_len -= sizeof(uint64_t) * 3;
  if (left_len != kG1FlatBinSize * tbl_size) return false;

  wm.tbl_.resize(tbl_size);
  for (uint64_t i = 0; i < tbl_size; ++i) {
    if (!FlatBinToG1(p, &wm.tbl_[i])) return false;
    p += kG1FlatBinSize;
  }
  return true;
}

inline bool G1wmToFlatBin(G1WM const& wm, std::vector<uint8_t>& ret) {
  assert(wm.bitSize_ && wm.winSize_ && wm.tbl_.size());
  if (!wm.bitSize_ || !wm.winSize_ || !wm.tbl_.size()) return false;

  uint64_t bit_size = wm.bitSize_;
  auto bit_size_big = boost::endian::native_to_big(bit_size);

  uint64_t win_size = wm.winSize_;
  auto win_size_big = boost::endian::native_to_big(win_size);

  uint64_t tbl_size = wm.tbl_.size();
  auto tbl_size_big = boost::endian::native_to_big(tbl_size);

  uint64_t size = sizeof(uint64_t) * 3 + kG1FlatBinSize * tbl_size;
  ret.resize(size);

  uint8_t* p = ret.data();

  memcpy(p, &bit_size_big, sizeof(bit_size_big));
  p += sizeof(bit_size_big);

  memcpy(p, &win_size_big, sizeof(win_size_big));
  p += sizeof(win_size_big);

  memcpy(p, &tbl_size_big, sizeof(tbl_size_big));
  p += sizeof(tbl_size_big);

  for (uint64_t i = 0; i < tbl_size; ++i) {
    G1 const& g = wm.tbl_[i];
    G1ToFlatBin(g, p);
    p += kG1FlatBinSize;
  }

  assert(ret.size() == GetG1wmFlatLen(wm));

  return true;
}

inline bool G2wmToFlatBin(G2WM const& wm, std::vector<uint8_t>& ret) {
  assert(wm.bitSize_ && wm.winSize_ && wm.tbl_.size());
  if (!wm.bitSize_ || !wm.winSize_ || !wm.tbl_.size()) return false;

  uint64_t bit_size = wm.bitSize_;
  auto bit_size_big = boost::endian::native_to_big(bit_size);

  uint64_t win_size = wm.winSize_;
  auto win_size_big = boost::endian::native_to_big(win_size);

  uint64_t tbl_size = wm.tbl_.size();
  auto tbl_size_big = boost::endian::native_to_big(tbl_size);

  uint64_t size = sizeof(uint64_t) * 3 + kG2FlatBinSize * wm.tbl_.size();
  ret.resize(size);

  uint8_t* p = ret.data();

  memcpy(p, &bit_size_big, sizeof(bit_size_big));
  p += sizeof(bit_size_big);

  memcpy(p, &win_size_big, sizeof(win_size_big));
  p += sizeof(win_size_big);

  memcpy(p, &tbl_size_big, sizeof(tbl_size_big));
  p += sizeof(tbl_size_big);

  for (uint64_t i = 0; i < tbl_size; ++i) {
    G2 const& g = wm.tbl_[i];
    G2ToFlatBin(p, &g);
    p += kG2FlatBinSize;
  }

  assert(ret.size() == GetG2wmFlatLen(wm));

  return true;
}

inline bool FlatBinToG2wm(uint8_t const* buf, size_t len, G2WM& wm) {
  uint8_t const* p = buf;
  uint64_t left_len = len;

  if (len <= sizeof(uint64_t) * 3) return false;

  uint64_t bit_size;
  memcpy(&bit_size, p, sizeof(bit_size));
  p += sizeof(bit_size);
  bit_size = boost::endian::big_to_native(bit_size);
  wm.bitSize_ = bit_size;
  assert(wm.bitSize_);
  if (!wm.bitSize_) return false;

  uint64_t win_size;
  memcpy(&win_size, p, sizeof(win_size));
  p += sizeof(win_size);
  win_size = boost::endian::big_to_native(win_size);
  wm.winSize_ = win_size;
  assert(wm.winSize_);
  if (!wm.winSize_) return false;

  uint64_t tbl_size;
  memcpy(&tbl_size, p, sizeof(tbl_size));
  p += sizeof(tbl_size);
  tbl_size = boost::endian::big_to_native(tbl_size);
  assert(tbl_size);
  if (!tbl_size) return false;

  uint64_t check_tbl_size =
      (bit_size + win_size - 1) / win_size * ((uint64_t)1 << win_size);
  if (tbl_size != check_tbl_size) return false;

  left_len -= sizeof(uint64_t) * 3;
  if (left_len != kG2FlatBinSize * tbl_size) return false;

  wm.tbl_.resize(tbl_size);
  for (uint64_t i = 0; i < tbl_size; ++i) {
    if (!FlatBinToG2(p, &wm.tbl_[i])) return false;
    p += kG2FlatBinSize;
  }
  return true;
}

// very fast if fr is uint64/uint32
inline G1 MultiExpBosCoster(std::function<G1(size_t)> const& get_g,
                            std::function<Fr(size_t)> const& get_f, size_t n) {
  if (n == 0) return G1Zero();
  if (n == 1) return get_g(0) * get_f(0);

  class OrderedExponent {
   public:
    size_t idx() const { return idx_; }
    Fr const& fr() const { return fr_; }
    size_t num_bits() const { return num_bits_; }
    OrderedExponent(size_t idx, Fr const& fr) : idx_(idx), fr_(fr) {
      num_bits_ = NumOfBits();
    }
    bool operator<(OrderedExponent const& other) const {
      return fr_ < other.fr_;
    }
    void Minus(Fr const& b) {
      fr_ -= b;
      num_bits_ = NumOfBits();
    }
    void Clear() { fr_.clear(); }

   private:
    size_t NumOfBits() const {
      auto mpz = fr_.getMpz();
      return mpz_sizeinbase(mpz.get_mpz_t(), 2);
    }

   private:
    size_t idx_;
    Fr fr_;
    size_t num_bits_;
  };

  std::vector<OrderedExponent> opt_q;
  size_t const odd_n = (n % 2) ? n : (n + 1);
  opt_q.reserve(odd_n);
  std::vector<G1> g;
  g.reserve(odd_n);
  for (size_t i = 0; i < n; ++i) {
    g.emplace_back(get_g(i));
    opt_q.emplace_back(OrderedExponent(i, get_f(i)));
  }
  std::make_heap(opt_q.begin(), opt_q.end());
  if (n != odd_n) {
    g.emplace_back(G1Zero());
    opt_q.emplace_back(OrderedExponent(odd_n - 1, FrZero()));
  }

  G1 opt_result = G1Zero();

  for (;;) {
    OrderedExponent& a = opt_q[0];
    OrderedExponent& b = (opt_q[1] < opt_q[2] ? opt_q[2] : opt_q[1]);

    const size_t abits = a.num_bits();

    if (b.fr().isZero()) {
      opt_result = opt_result + (g[a.idx()] * a.fr());
      break;
    }

    const size_t bbits = b.num_bits();
    const size_t limit = (abits - bbits >= 20 ? 20 : abits - bbits);

    if (bbits < ((size_t)1) << limit) {
      /*
        In this case, exponentiating to the power of a is cheaper than
        subtracting b from a multiple times, so let's do it directly
      */
      opt_result = opt_result + (g[a.idx()] * a.fr());
      a.Clear();
    } else {
      // x A + y B => (x-y) A + y (B+A)
      // mpn_sub_n(a.r.data, a.r.data, b.r.data, 4);
      a.Minus(b.fr());
      g[b.idx()] = g[b.idx()] + g[a.idx()];
    }

    // regardless of whether a was cleared or subtracted from we push it down,
    // then take back up

    /* heapify A down */
    size_t a_pos = 0;
    while (2 * a_pos + 2 < odd_n) {
      // this is a max-heap so to maintain a heap property we swap with the
      // largest of the two
      if (opt_q[2 * a_pos + 1] < opt_q[2 * a_pos + 2]) {
        std::swap(opt_q[a_pos], opt_q[2 * a_pos + 2]);
        a_pos = 2 * a_pos + 2;
      } else {
        std::swap(opt_q[a_pos], opt_q[2 * a_pos + 1]);
        a_pos = 2 * a_pos + 1;
      }
    }

    /* now heapify A up appropriate amount of times */
    while (a_pos > 0 && opt_q[(a_pos - 1) / 2] < opt_q[a_pos]) {
      std::swap(opt_q[a_pos], opt_q[(a_pos - 1) / 2]);
      a_pos = (a_pos - 1) / 2;
    }
  }

  return opt_result;
}

inline G1 MultiExpBosCoster(G1 const* pg, Fr const* pf, size_t n) {
  auto get_g = [pg](size_t i) { return pg[i]; };
  auto get_f = [pf](size_t i) { return pf[i]; };
  return MultiExpBosCoster(get_g, get_f, n);
}

namespace details {
inline std::vector<Fp6> ComputeG2Coeff() {
  std::vector<Fp6> g2_1_coeff;
  mcl::bn256::precomputeG2(g2_1_coeff, G2One());
  return g2_1_coeff;
}
}  // namespace details

// e(a, G2One()) == e(c, d)
inline bool PairingMatch(G1 const& a, G1 const& c, G2 const& d) {
  static std::vector<Fp6> g2_1_coeff = details::ComputeG2Coeff();
  Fp12 e1;
  mcl::bn256::precomputedMillerLoop(e1, a, g2_1_coeff);
  mcl::bn256::finalExp(e1, e1);
  Fp12 e2;
  mcl::bn256::pairing(e2, c, d);
  assert(e1 == e2);
  return e1 == e2;
}

// e(a, b) == e(c, d)
inline bool PairingMatch(G1 const& a, G2 const& b, G1 const& c, G2 const& d) {
  Fp12 e1, e2;
  mcl::bn256::pairing(e1, a, b);
  mcl::bn256::pairing(e2, c, d);
  assert(e1 == e2);
  return (e1 == e2);
}

inline Fr FrPower(Fr const& base, mpz_class const& exp) {
  Fr z;
  Fr::pow(z, base, exp);
  return z;
}

inline bool operator==(G1WM const& a, G1WM const& b) {
  if (a.bitSize_ != b.bitSize_) return false;
  if (a.winSize_ != b.winSize_) return false;
  if (a.tbl_.size() != b.tbl_.size()) return false;
  for (size_t i = 0; i < a.tbl_.size(); ++i) {
    auto const& ga = a.tbl_[i];
    auto const& gb = b.tbl_[i];
    if (ga != gb) {
      return false;
    }
  }
  return true;
}

inline bool operator!=(G1WM const& a, G1WM const& b) { return !(a == b); }

inline bool operator==(G2WM const& a, G2WM const& b) {
  if (a.bitSize_ != b.bitSize_) return false;
  if (a.winSize_ != b.winSize_) return false;
  if (a.tbl_.size() != b.tbl_.size()) return false;
  for (size_t i = 0; i < a.tbl_.size(); ++i) {
    if (a.tbl_[i] != b.tbl_[i]) return false;
  }
  return true;
}

inline bool operator!=(G2WM const& a, G2WM const& b) { return !(a == b); }

inline std::vector<Fr> SplitFr(Fr const& fr, int64_t n) {
  std::vector<Fr> ret(n);
  if (n == 1) {
    ret[0] = fr;
  } else {
    FrRand(ret.data(), n - 1);
    auto sum_exclude_last =
        std::accumulate(ret.begin(), ret.begin() + n - 1, FrZero());
    ret.back() = fr - sum_exclude_last;

    assert(fr == std::accumulate(ret.begin(), ret.end(), FrZero()));
  }
  return ret;
}

#include <cybozu/benchmark.hpp>
#include <mcl/bn256.hpp>
inline bool TestMcl(int64_t n) {
  // using namespace mcl::bn;
  try {
    const int N = (int)n;
    std::cout << "mcl jit: " << mcl::fp::isEnableJIT() << "\n";
    G1 P = G1Rand();
    G1 Q = G1Rand();
    Tick tick(__FN__);
    CYBOZU_BENCH_C("add", N, G1::add, P, Q, P);
    CYBOZU_BENCH_C("dbl", N, G1::dbl, P, P);
  } catch (std::exception& e) {
    std::cout << "err " << e.what() << "\n";
    return false;
  }
  return true;
}

// ========================================================================
// SparseMatrix: CSR (Compressed Sparse Row) format
// ========================================================================
struct SparseMatrix {
  int64_t rows_ = 0;
  int64_t cols_ = 0;
  std::vector<int64_t> row_ptr_;
  std::vector<int64_t> col_idx_;
  std::vector<Fr> values_;

  SparseMatrix() = default;

  int64_t rows() const { return rows_; }
  int64_t cols() const { return cols_; }
  int64_t nnz() const { return (int64_t)values_.size(); }
  bool empty() const { return rows_ == 0 || cols_ == 0; }
};

// MatrixVectorMul for SparseMatrix: result[j] = sum_i vec[i] * mat(i,j)
// (left-multiply by row vector, i.e. vec^T * mat)
inline void MatrixVectorMul(std::vector<Fr> const& vec,
                            SparseMatrix const& mat,
                            std::vector<Fr>& result) {
  int64_t rows = mat.rows();
  int64_t cols = mat.cols();
  result.assign(cols, FrZero());

  // Compute per-row contributions in parallel
  std::vector<std::vector<std::pair<int64_t, Fr>>> row_contribs(rows);
  auto compute_row = [&](int64_t i) {
    std::vector<std::pair<int64_t, Fr>> contrib;
    Fr vi = vec[i];
    for (int64_t k = mat.row_ptr_[i]; k < mat.row_ptr_[i + 1]; ++k) {
      contrib.emplace_back(mat.col_idx_[k], vi * mat.values_[k]);
    }
    row_contribs[i] = std::move(contrib);
  };
  parallel::For(rows, compute_row);

  // Reduce into result
  for (int64_t i = 0; i < rows; ++i) {
    for (auto const& p : row_contribs[i]) {
      result[p.first] += p.second;
    }
  }
}

// SparseMatrix * FlatMatrix multiplication (parallel)
// sparse_a is m x n_vars (CSR), dense_b is n_vars x n (FlatMatrix)
// result is m x n: result(i,j) = sum_k sparse_a(i,k) * dense_b(k,j)
inline void SparseMatrixMulDense(
    SparseMatrix const& sparse_a,
    FlatMatrix const& dense_b,
    FlatMatrix& result) {
  int64_t m = sparse_a.rows();
  int64_t n = dense_b.cols();
  result.resize(m, n);

  auto compute_row = [&](int64_t i) {
    Fr* result_row = result.row_ptr(i);
    std::fill(result_row, result_row + n, FrZero());
    for (int64_t k = sparse_a.row_ptr_[i]; k < sparse_a.row_ptr_[i + 1]; ++k) {
      int64_t col = sparse_a.col_idx_[k];
      Fr const& val = sparse_a.values_[k];
      Fr const* b_row = dense_b.row_ptr(col);
      for (int64_t j = 0; j < n; ++j) {
        result_row[j] += val * b_row[j];
      }
    }
  };
  parallel::For(m, compute_row);
}

// Alias for backward compatibility
inline void SparseMatrixMulFlat(
    SparseMatrix const& sparse_a,
    FlatMatrix const& flat_b,
    FlatMatrix& result) {
  SparseMatrixMulDense(sparse_a, flat_b, result);
}

// Build a scaled sparse matrix: result(i,j) = scale[i] * mat(i,j)
// Returns a new SparseMatrix with the same sparsity pattern
inline SparseMatrix ScaleSparseRows(
    SparseMatrix const& mat,
    std::vector<Fr> const& scale) {
  SparseMatrix result;
  result.rows_ = mat.rows_;
  result.cols_ = mat.cols_;
  result.row_ptr_ = mat.row_ptr_;
  result.col_idx_ = mat.col_idx_;
  result.values_.resize(mat.values_.size());

  auto scale_row = [&](int64_t i) {
    for (int64_t k = mat.row_ptr_[i]; k < mat.row_ptr_[i + 1]; ++k) {
      result.values_[k] = scale[i] * mat.values_[k];
    }
  };
  parallel::For(mat.rows_, scale_row);
  return result;
}

// ========================================================================
// SparseZMatrix: CSR format for sparse witness matrix Z
// Used to optimize A12 protocol when Z has many zero elements
// ========================================================================
struct SparseZMatrix {
  int64_t rows_ = 0;  // n_vars (number of variables)
  int64_t cols_ = 0;  // n (number of instances)
  std::vector<int64_t> row_ptr_;   // row pointers (size: rows_ + 1)
  std::vector<int64_t> col_idx_;   // column indices of non-zero elements
  std::vector<Fr> values_;         // non-zero values

  SparseZMatrix() = default;

  int64_t rows() const { return rows_; }
  int64_t cols() const { return cols_; }
  int64_t nnz() const { return (int64_t)values_.size(); }
  bool empty() const { return rows_ == 0 || cols_ == 0; }
  
  double sparsity() const {
    if (rows_ * cols_ == 0) return 0.0;
    return 1.0 - static_cast<double>(nnz()) / (rows_ * cols_);
  }
  
  // Get the i-th row's non-zero count
  int64_t row_nnz(int64_t i) const {
    return row_ptr_[i + 1] - row_ptr_[i];
  }
};

// ========================================================================
// SparseZMatrixCSC: CSC (Compressed Sparse Column) format for sparse Z
// Enables O(nnz_col) column extraction instead of O(rows * avg_nnz_per_row)
// ========================================================================
struct SparseZMatrixCSC {
  int64_t rows_ = 0;  // n_vars
  int64_t cols_ = 0;  // n (instances)
  std::vector<int64_t> col_ptr_;   // column pointers (size: cols_ + 1)
  std::vector<int64_t> row_idx_;   // row indices of non-zero elements
  std::vector<Fr> values_;         // non-zero values

  SparseZMatrixCSC() = default;

  int64_t rows() const { return rows_; }
  int64_t cols() const { return cols_; }
  int64_t nnz() const { return (int64_t)values_.size(); }

  // Get non-zero count for column j
  int64_t col_nnz(int64_t j) const {
    return col_ptr_[j + 1] - col_ptr_[j];
  }
};

// Convert CSR SparseZMatrix to CSC SparseZMatrixCSC in O(nnz) time.
// This is a one-time cost that amortizes over all subsequent column accesses.
inline SparseZMatrixCSC SparseZToCSC(SparseZMatrix const& csr) {
  SparseZMatrixCSC csc;
  csc.rows_ = csr.rows();
  csc.cols_ = csr.cols();
  int64_t total_nnz = csr.nnz();

  csc.col_ptr_.assign(csc.cols_ + 1, 0);

  // Pass 1: count non-zeros per column
  for (int64_t k = 0; k < total_nnz; ++k) {
    csc.col_ptr_[csr.col_idx_[k] + 1]++;
  }

  // Cumulative sum to get column pointers
  for (int64_t j = 0; j < csc.cols_; ++j) {
    csc.col_ptr_[j + 1] += csc.col_ptr_[j];
  }

  // Pass 2: fill row indices and values
  csc.row_idx_.resize(total_nnz);
  csc.values_.resize(total_nnz);
  std::vector<int64_t> current_pos(csc.col_ptr_.begin(), csc.col_ptr_.end() - 1);

  for (int64_t i = 0; i < csr.rows(); ++i) {
    for (int64_t k = csr.row_ptr_[i]; k < csr.row_ptr_[i + 1]; ++k) {
      int64_t j = csr.col_idx_[k];
      int64_t pos = current_pos[j]++;
      csc.row_idx_[pos] = i;
      csc.values_[pos] = csr.values_[k];
    }
  }

  return csc;
}

// Convert FlatMatrix to SparseZMatrix (CSR format)
// Z is stored as rows = n_vars, cols = n_instances
inline SparseZMatrix FlatMatrixToSparseZ(FlatMatrix const& mat) {
  SparseZMatrix sparse;
  sparse.rows_ = mat.rows();
  sparse.cols_ = mat.cols();
  sparse.row_ptr_.resize(sparse.rows_ + 1, 0);
  
  // First pass: count non-zeros per row
  for (int64_t i = 0; i < sparse.rows_; ++i) {
    for (int64_t j = 0; j < sparse.cols_; ++j) {
      if (mat(i, j) != FrZero()) {
        sparse.row_ptr_[i + 1]++;
      }
    }
  }
  
  // Cumulative sum to get row pointers
  for (int64_t i = 0; i < sparse.rows_; ++i) {
    sparse.row_ptr_[i + 1] += sparse.row_ptr_[i];
  }
  
  // Allocate space
  int64_t total_nnz = sparse.row_ptr_[sparse.rows_];
  sparse.col_idx_.resize(total_nnz);
  sparse.values_.resize(total_nnz);
  
  // Second pass: fill values
  std::vector<int64_t> current_pos = sparse.row_ptr_;
  for (int64_t i = 0; i < sparse.rows_; ++i) {
    for (int64_t j = 0; j < sparse.cols_; ++j) {
      Fr const& val = mat(i, j);
      if (val != FrZero()) {
        int64_t pos = current_pos[i]++;
        sparse.col_idx_[pos] = j;
        sparse.values_[pos] = val;
      }
    }
  }
  
  return sparse;
}

// SparseZMatrix * vector: result[i] = sum_j sparse_z(i,j) * vec[j]
// This computes Z * vec (standard matrix-vector multiply)
// vec must have size == cols, result has size == rows
inline void SparseZMatrixVectorMulRight(
    SparseZMatrix const& sparse_z,
    std::vector<Fr> const& vec,
    std::vector<Fr>& result) {
  int64_t rows = sparse_z.rows();
  result.assign(rows, FrZero());
  
  auto compute_row = [&](int64_t i) {
    Fr sum = FrZero();
    for (int64_t k = sparse_z.row_ptr_[i]; k < sparse_z.row_ptr_[i + 1]; ++k) {
      sum += sparse_z.values_[k] * vec[sparse_z.col_idx_[k]];
    }
    result[i] = sum;
  };
  parallel::For(rows, compute_row);
}

// vector^T * SparseZMatrix: result[j] = sum_i vec[i] * sparse_z(i,j)
// This computes vec^T * Z (left-multiply by row vector)
// vec must have size == rows, result has size == cols
inline void SparseZMatrixVectorMulLeft(
    std::vector<Fr> const& vec,
    SparseZMatrix const& sparse_z,
    std::vector<Fr>& result) {
  int64_t cols = sparse_z.cols();
  result.assign(cols, FrZero());
  
  for (int64_t i = 0; i < sparse_z.rows(); ++i) {
    Fr const& vi = vec[i];
    for (int64_t k = sparse_z.row_ptr_[i]; k < sparse_z.row_ptr_[i + 1]; ++k) {
      result[sparse_z.col_idx_[k]] += vi * sparse_z.values_[k];
    }
  }
}

// SparseMatrix * SparseZMatrix multiplication
// sparse_a is m x n_vars (CSR), sparse_z is n_vars x n (CSR)
// result is m x n: result[i][j] = sum_k sparse_a(i,k) * sparse_z(k,j)
inline void SparseMatrixMulSparseZ(
    SparseMatrix const& sparse_a,
    SparseZMatrix const& sparse_z,
    std::vector<std::vector<Fr>>& result) {
  int64_t m = sparse_a.rows();
  int64_t n = sparse_z.cols();
  result.resize(m, std::vector<Fr>(n, FrZero()));
  
  // For each row i of sparse_a
  auto compute_row = [&](int64_t i) {
    std::fill(result[i].begin(), result[i].end(), FrZero());
    // For each non-zero element (i, k) in sparse_a
    for (int64_t k_a = sparse_a.row_ptr_[i]; k_a < sparse_a.row_ptr_[i + 1]; ++k_a) {
      int64_t k = sparse_a.col_idx_[k_a];
      Fr const& a_val = sparse_a.values_[k_a];
      // For each non-zero element (k, j) in sparse_z
      for (int64_t k_z = sparse_z.row_ptr_[k]; k_z < sparse_z.row_ptr_[k + 1]; ++k_z) {
        int64_t j = sparse_z.col_idx_[k_z];
        result[i][j] += a_val * sparse_z.values_[k_z];
      }
    }
  };
  parallel::For(m, compute_row);
}

// Extract column j from SparseZMatrix
inline std::vector<Fr> SparseZMatrixCol(SparseZMatrix const& sparse_z, int64_t j) {
  std::vector<Fr> col(sparse_z.rows(), FrZero());
  for (int64_t i = 0; i < sparse_z.rows(); ++i) {
    for (int64_t k = sparse_z.row_ptr_[i]; k < sparse_z.row_ptr_[i + 1]; ++k) {
      if (sparse_z.col_idx_[k] == j) {
        col[i] = sparse_z.values_[k];
        break;
      }
    }
  }
  return col;
}

// Extract non-zero elements and their row indices from column j of SparseZMatrix.
// Returns (row_indices, values) pair containing only non-zero entries.
// This avoids allocating a dense n_vars-sized vector and the subsequent
// zero-checking pass in MultiExpBdlo12Inner(check_01=true).
// Parallelized by processing rows in parallel and filtering results.
inline std::pair<std::vector<int64_t>, std::vector<Fr>>
SparseZMatrixColNonZero(SparseZMatrix const& sparse_z, int64_t j) {
  int64_t rows = sparse_z.rows();

  // First pass: find matches in parallel, store (row, value) pairs
  std::vector<std::pair<int64_t, Fr>> matches;
  std::mutex matches_mutex;

  auto find_in_row = [&](int64_t i) {
    for (int64_t k = sparse_z.row_ptr_[i]; k < sparse_z.row_ptr_[i + 1]; ++k) {
      if (sparse_z.col_idx_[k] == j) {
        std::lock_guard<std::mutex> lock(matches_mutex);
        matches.emplace_back(i, sparse_z.values_[k]);
        break;
      }
    }
  };
  parallel::For(rows, find_in_row);

  // Extract row_indices and values from matches
  std::vector<int64_t> row_indices;
  std::vector<Fr> values;
  row_indices.reserve(matches.size());
  values.reserve(matches.size());
  for (auto const& p : matches) {
    row_indices.push_back(p.first);
    values.push_back(p.second);
  }

  return {std::move(row_indices), std::move(values)};
}

// ========================================================================
// R1csStats: Statistics for R1CS constraint system
// ========================================================================
struct R1csStats {
  int64_t num_constraints = 0;
  int64_t num_variables = 0;
  int64_t nnz_a = 0;
  int64_t nnz_b = 0;
  int64_t nnz_c = 0;

  void Print() const {
    std::cout << "R1CS Stats: constraints=" << num_constraints
              << " variables=" << num_variables
              << " nnz_a=" << nnz_a
              << " nnz_b=" << nnz_b
              << " nnz_c=" << nnz_c << "\n";
  }
};
