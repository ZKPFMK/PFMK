#pragma once

#include <algorithm>

#include "./adapt.h"
#include "./details.h"
#include "./parallel_r1cs.h"
#include "circuit/sudoku_gadget.h"

namespace clink {
struct Sudoku {
  // using Policy = groth09::OrdinaryPolicy;
  using Policy = groth09::SuccinctPolicy;
  using R1cs = typename clink::ParallelR1cs<Policy>;
  using HyraxA = typename Policy::HyraxA;
  using Sec51 = typename Policy::Sec51;
  using Sec53 = typename Policy::Sec53;
  using Sec43 = typename Policy::Sec43;

  struct Proof {
    clink::ParallelR1cs<Policy>::Proof r1cs_proof;
    hyrax::A4::Proof adapt_proof;
    G1 com_x; // x is vector of the puzzle
    G1 com_y; // y is pack format of the x, for the later pod
    std::vector<G1> com_w;
    bool operator==(Proof const& b) const {
      return r1cs_proof == b.r1cs_proof && adapt_proof == b.adapt_proof &&
             com_x == b.com_x && com_y == b.com_y && com_w == b.com_w;
    }

    bool operator!=(Proof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("sudoku.p", ("rp", r1cs_proof), ("rp", adapt_proof),
                         ("cx", com_x), ("cy", com_y), ("cw", com_w));
    }
    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("sudoku.p", ("rp", r1cs_proof), ("rp", adapt_proof),
                         ("cx", com_x), ("cy", com_y), ("cw", com_w));
    }
  };

  // x: vector<Fr>, every element only use `bits` bits
  static void BuildPackPara(h256_t const& seed, size_t bits, size_t x_size,
                            std::vector<Fr>& a, std::vector<Fr>& b) {
    size_t count = 253 / bits; //一个域元素可以存储多少个数独元素
    size_t n = (x_size + count - 1) / count; //对于一个数独需要域元素的个数
    b.resize(n);
    ComputeFst(seed, "b", b);
    std::vector<Fr> c(count);
    for (size_t i = 0; i < count; ++i) {
      c[i].setMpz(mpz_class(1) << (bits * i));
    }
    a.reserve(count * n);
    for (size_t i = 0; i < n; ++i) {
      auto cb = -(c * b[i]);
      a.insert(a.end(), cb.begin(), cb.end());
    }
    assert(x_size <= a.size());
    a.resize(x_size);
  }

  // position of Mt
  static std::vector<std::vector<size_t>> BuildMtPos(size_t d) {
    size_t D = d * d;
    std::vector<std::vector<size_t>> mt_pos(D * 3);
    // every row,行对应的索引
    for (size_t i = 0; i < D; ++i) {
      auto& pos = mt_pos[i];
      pos.resize(D);
      for (size_t j = 0; j < D; ++j) {
        pos[j] = i * D + j;
      }
    }
    // every col,列对应的索引
    for (size_t i = 0; i < D; ++i) {
      auto& pos = mt_pos[i + D];
      pos.resize(D);
      for (size_t j = 0; j < D; ++j) {
        pos[j] = j * D + i;
      }
    }
    // every cell,宫对应的索引
    for (size_t i = 0; i < D; ++i) {
      auto& pos = mt_pos[i + D * 2];
      pos.resize(D);
      for (size_t j = 0; j < D; ++j) {
        size_t ii = (i / d) * d + j / d;
        size_t jj = (i % d) * d + j % d;
        pos[j] = ii * D + jj;
      }
    }
    return mt_pos;
  }

  static void AdaptUpdateSeed(h256_t& seed, G1 const& com_x,
                              std::vector<G1> const& com_w) {
    CryptoPP::Keccak_256 hash;
    HashUpdate(hash, seed);
    HashUpdate(hash, com_x);
    for (auto const& i : com_w) {
      HashUpdate(hash, i);
    }
    hash.Final(seed.data());
  }

  static void AdaptComputeFst(h256_t const& seed, std::string const& tag,
                              std::vector<Fr>& e) {
    std::string salt = "sudoku adapt " + std::to_string(e.size()) + tag;
    ComputeFst(seed, salt, e);
  }

  struct ProveInput {
    size_t d;
    size_t D;
    std::vector<Fr> const& x; //数独解
    G1 const& com_x; //承诺
    Fr const& com_x_r; //随机数
    std::vector<Fr> const& y; //数独打包的域元素
    G1 const& com_y; //承诺
    Fr const& com_y_r; //随机数
    std::vector<size_t> const& open_positions; //数独公开的位置
    GetRefG1 const& get_g; //获取承诺base的函数

    std::vector<Fr> open_values; //数独公开的值
    std::unique_ptr<R1csInfo> r1cs_info;
    int64_t s; //置换电路的变量数
    std::vector<std::vector<Fr>> mutable w; //置换变量数 * 3D
    std::vector<std::vector<size_t>> mt_pos; //前m行为行的解的索引, 中间m行为数独解列的索引, 后m行为宫的索引

    ProveInput(std::vector<Fr> const& x, G1 const& com_x, Fr const& com_x_r,
               std::vector<Fr> const& y, G1 const& com_y, Fr const& com_y_r,
               std::vector<size_t> const& open_positions, GetRefG1 const& get_g)
        : x(x),
          com_x(com_x),
          com_x_r(com_x_r),
          y(y),
          com_y(com_y),
          com_y_r(com_y_r),
          open_positions(open_positions),
          get_g(get_g) {
      D = (size_t)(std::sqrt(x.size()));
      if (D * D != x.size()) throw std::invalid_argument("invalid dimension");
      d = (size_t)std::sqrt(D);
      if (d * d != D) throw std::invalid_argument("invalid dimension");      

      libsnark::protoboard<Fr> pb; //电路板
      circuit::SudokuGadget gadget(pb, D); //置换电路

      int64_t const primary_input_size = D; //primary_input = statment
      pb.set_input_sizes(primary_input_size); //公开输入个数为置换的大小
      r1cs_info.reset(new R1csInfo(pb));
      s = r1cs_info->num_variables; //置换电路的变量数
      w.resize(s);
      for (auto& i : w) i.resize(D * 3);

      mt_pos = BuildMtPos(d); //D * 3D的矩阵, 

      for (size_t j = 0; j < D * 3; ++j) {
        std::vector<Fr> line(D);
        for (size_t i = 0; i < D; ++i) {
          line[i] = x[mt_pos[j][i]];
        }
        gadget.Assign(line);
        assert(pb.is_satisfied());
        auto v = pb.full_variable_assignment();
        for (int64_t i = 0; i < s; ++i) {
          w[i][j] = v[i];
        }
      }

      open_values.resize(open_positions.size());
      for (size_t i = 0; i < open_positions.size(); ++i) {
        open_values[i] = x[open_positions[i]];
      }
    }
  };

  static void Prove(Proof& proof, h256_t seed, ProveInput const& input) {
    Tick tick(__FN__);
    proof.com_x = input.com_x;
    proof.com_y = input.com_y;

    proof.com_w.resize(input.s);
    std::vector<Fr> com_w_r(input.s);

    // public input
    G1 sum_g = pc::ComputeSigmaG(0, input.D * 3);
    for (size_t i = 0; i < input.D; ++i) {
      assert(input.w[i].size() == input.D * 3);
      for (size_t j = 0; j < input.D * 3; ++j) {
        assert(input.w[i][j] == i + 1);
      }
      com_w_r[i] = FrZero();
      proof.com_w[i] = sum_g * (i + 1);
    }

    {
      auto parallel_f = [&com_w_r, &proof, &input](int64_t i) {
        com_w_r[i] = FrRand();
        proof.com_w[i] = pc::ComputeCom(input.get_g, input.w[i], com_w_r[i]);
      };
      parallel::For<int64_t>(input.D, input.s, parallel_f);
    }

    AdaptUpdateSeed(seed, input.com_x, proof.com_w);

    // prove adapt
    std::vector<AdaptProveItem> adapt_items;
    std::vector<Fr> e1, e2(input.D * input.D); // x * e2 = open_value * e2
        
    // adapt: com_x consistent with open values
    e1.resize(input.open_positions.size());
    AdaptComputeFst(seed, "open", e1);
    for (auto& i : e2) i = FrZero();
    for (size_t i = 0; i < input.open_positions.size(); ++i) {
      e2[input.open_positions[i]] = e1[i];
    }
    Fr z = InnerProduct(e1, input.open_values);
    AdaptProveItem adapt_open;
    adapt_open.Init(1, "open", z);
    adapt_open.x[0] = input.x;
    adapt_open.a[0] = e2;
    adapt_open.cx[0] = input.com_x;
    adapt_open.rx[0] = input.com_x_r;
    assert(adapt_open.CheckData());
    adapt_items.emplace_back(std::move(adapt_open));    

    // adapt: com_x consistent with com_w[N~2N)
    for (size_t i = 0; i < input.D; ++i) {
      e1.resize(input.D * 3);
      AdaptComputeFst(seed, "open", e1);
      std::vector<Fr> row(input.D * 3);
      for (size_t j = 0; j < input.D * 3; ++j) {
        row[j] = input.x[input.mt_pos[j][i]];        
      }
      for (auto& item : e2) item = FrZero();
      for (size_t j = 0; j < input.D * 3; ++j) {
        auto pos = input.mt_pos[j][i];
        e2[pos] += -e1[j];
      }
      AdaptProveItem adapt_cell;
      adapt_cell.Init(2, "cell" + std::to_string(i), FrZero());
      adapt_cell.x[0] = input.x;
      adapt_cell.a[0] = e2;
      adapt_cell.cx[0] = input.com_x;
      adapt_cell.rx[0] = input.com_x_r;
      adapt_cell.x[1] = std::move(row);
      adapt_cell.a[1] = e1;
      adapt_cell.cx[1] = proof.com_w[input.D + i];
      adapt_cell.rx[1] = com_w_r[input.D + i];
      assert(adapt_cell.CheckData());
      adapt_items.emplace_back(std::move(adapt_cell));      
    }

    // adapt: com_y consistent with com_x
    std::vector<Fr> xy_a, xy_b;
    BuildPackPara(seed, CeilLog2(input.D + 1), input.D*input.D, xy_a, xy_b);
    AdaptProveItem adapt_xy;
    adapt_xy.Init(2, "xy", FrZero());
    adapt_xy.x[0] = input.x;
    adapt_xy.a[0] = std::move(xy_a);
    adapt_xy.cx[0] = proof.com_x;
    adapt_xy.rx[0] = input.com_x_r;
    adapt_xy.x[1] = input.y;
    adapt_xy.a[1] = std::move(xy_b);
    adapt_xy.cx[1] = proof.com_y;
    adapt_xy.rx[1] = input.com_y_r;
    assert(adapt_xy.CheckData());
    adapt_items.emplace_back(std::move(adapt_xy));

    std::array<parallel::VoidTask, 2> tasks;

    tasks[0] = [&seed,&adapt_items, &proof]() {
      AdaptProve(seed, std::move(adapt_items), proof.adapt_proof);
    };

    tasks[1] = [&seed, &proof, &input, &com_w_r]() {
      // prove permutation
      typename R1cs::ProveInput r1cs_input(*input.r1cs_info, "sudoku",
                                           std::move(input.w), proof.com_w,
                                           com_w_r, input.get_g);
      R1cs::Prove(proof.r1cs_proof, seed, std::move(r1cs_input));
    };

    parallel::Invoke(tasks);
  }

  struct VerifyInput {
    size_t d;
    size_t D;
    std::vector<size_t> const& open_positions;
    std::vector<Fr> const& open_values;
    GetRefG1 const& get_g;

    std::unique_ptr<R1csInfo> r1cs_info;
    int64_t m;
    int64_t s;
    std::vector<std::vector<Fr>> public_w;
    std::vector<std::vector<size_t>> mt_pos;

    VerifyInput(size_t d, std::vector<size_t> const& open_positions,
                std::vector<Fr> const& open_values, GetRefG1 const& get_g)
        : d(d),
          D(d * d),
          open_positions(open_positions),
          open_values(open_values),
          get_g(get_g) {
      libsnark::protoboard<Fr> pb;
      circuit::SudokuGadget gadget(pb, D);
      int64_t const primary_input_size = D;
      pb.set_input_sizes(primary_input_size);
      r1cs_info.reset(new R1csInfo(pb));
      m = r1cs_info->num_constraints;
      s = r1cs_info->num_variables;

      // public input
      public_w.resize(D);
      for (size_t i = 0; i < D; ++i) {
        auto& row = public_w[i];
        row.resize(D * 3);
        for (size_t j = 0; j < D * 3; ++j) {
          row[j] = i + 1;
        }
      }

      mt_pos = BuildMtPos(d);
    }
  };

  static bool Verify(Proof const& proof, h256_t seed,
                     VerifyInput const& input) {
    Tick tick(__FN__);
    if ((int64_t)proof.com_w.size() != input.s) {
      assert(false);
      return false;
    }

    // public input
    G1 sum_g = pc::ComputeSigmaG(0, input.D * 3);
    for (size_t i = 0; i < input.D; ++i) {
      if (proof.com_w[i] != sum_g * (i + 1)) {
        assert(false);
        return false;
      }
    }

    AdaptUpdateSeed(seed, proof.com_x, proof.com_w);
    
    // verify adapt
    std::vector<AdaptVerifyItem> adapt_items;
    std::vector<Fr> e1, e2(input.D * input.D);

    // adapt: com_x consistent with open values
    e1.resize(input.open_positions.size());
    AdaptComputeFst(seed, "open", e1);
    for (auto& i : e2) i = FrZero();
    for (size_t i = 0; i < input.open_positions.size(); ++i) {
      e2[input.open_positions[i]] = e1[i];
    }
    Fr z = InnerProduct(e1, input.open_values);
    AdaptVerifyItem adapt_open;
    adapt_open.Init(1, "open", z);
    adapt_open.a[0] = e2;
    adapt_open.cx[0] = proof.com_x;
    adapt_items.emplace_back(std::move(adapt_open));

    // adapt: com_x consistent with com_w[N~2N)
    for (size_t i = 0; i < input.D; ++i) {
      e1.resize(input.D * 3);
      AdaptComputeFst(seed, "open", e1);
      for (auto& item : e2) item = FrZero();
      for (size_t j = 0; j < input.D * 3; ++j) {
        auto pos = input.mt_pos[j][i];
        e2[pos] += -e1[j];
      }
      AdaptVerifyItem adapt_cell;
      adapt_cell.Init(2, "cell" + std::to_string(i), FrZero());
      adapt_cell.a[0] = e2;
      adapt_cell.cx[0] = proof.com_x;
      adapt_cell.a[1] = e1;
      adapt_cell.cx[1] = proof.com_w[input.D + i];
      adapt_items.emplace_back(std::move(adapt_cell));    
    }

    // adapt: com_y consistent with com_x
    std::vector<Fr> xy_a, xy_b;
    BuildPackPara(seed, CeilLog2(input.D + 1), input.D * input.D, xy_a, xy_b);
    AdaptVerifyItem adapt_xy;
    adapt_xy.Init(2, "xy", FrZero());
    adapt_xy.a[0] = std::move(xy_a);
    adapt_xy.cx[0] = proof.com_x;
    adapt_xy.a[1] = std::move(xy_b);
    adapt_xy.cx[1] = proof.com_y;
    adapt_items.emplace_back(std::move(adapt_xy));

    // parallel prove
    std::array<std::atomic<bool>, 2> rets;
    std::array<parallel::VoidTask, 2> tasks;
    tasks[0] = [&input, &proof, &seed, &rets]() {
      typename ParallelR1cs<Policy>::VerifyInput pr_input(
          input.D * 3, *input.r1cs_info, "sudoku", proof.com_w, input.public_w,
          input.get_g);
      rets[0] = ParallelR1cs<Policy>::Verify(proof.r1cs_proof, seed, pr_input);
    };

    tasks[1] = [&adapt_items, &seed, &proof,&rets]() {
      rets[1] = AdaptVerify(seed, std::move(adapt_items), proof.adapt_proof);
    };

    parallel::Invoke(tasks);

    if (!rets[0] || !rets[1]) {
      assert(false);
      return false;
    }
    return true;
  }

  static std::vector<Fr> GeneratePuzzle(size_t d) {    
    size_t D = d * d;
    std::vector<std::vector<size_t>> matrix;
    matrix.reserve(D);

    std::vector<size_t> base(D); //1-9
    for (size_t i = 0; i < D; ++i) {
      base[i] = i + 1;
    }
    std::vector<size_t> rnd(d); //1-3
    for (size_t i = 0; i < d; ++i) {
      rnd[i] = i;
    }

    std::random_device rng;
    std::mt19937 urng(rng());
    auto buf = base;
    std::shuffle(buf.begin(), buf.end(), urng);

    for (size_t i = 0; i < d; ++i) {
      std::rotate(buf.begin(), buf.begin() + 1, buf.end());
      matrix.push_back(buf);
      for (size_t j = 1; j < d; ++j) {
        std::rotate(buf.begin(), buf.begin() + d, buf.end());
        matrix.push_back(buf);
      }
    }

    // shuffle
    for (size_t k = 0; k < d; ++k) {
      auto begin = matrix.begin() + k * d;
      auto end = begin + d;
      std::shuffle(begin, end, urng);
    }

    // rotate 90
    std::vector<std::vector<size_t>> dup(D);
    for (size_t i = 0; i < D; ++i) {
      dup[i].resize(D);
      for (size_t j = 0; j < D; ++j) {
        dup[i][j] = matrix[j][i];
      }
    }
    matrix = std::move(dup);

    // shuffle
    for (size_t k = 0; k < d; ++k) {
      auto begin = matrix.begin() + k * d;
      auto end = begin + d;
      std::shuffle(begin, end, urng);
    }

    // matrix to vector
    std::vector<size_t> ret(D * D);
    for (size_t i = 0; i < D; ++i) {
      for (size_t j = 0; j < D; ++j) {
        ret[i * D + j] = matrix[i][j];
      }
    }

    // check row
    for (size_t i = 0; i < D; ++i) {
      buf.resize(0);
      for (size_t j = 0; j < D; ++j) {
        buf.push_back(ret[i * D + j]);
      }
      std::sort(buf.begin(), buf.end());
      assert(buf == base);
    }

    // check col
    for (size_t j = 0; j < D; ++j) {
      buf.resize(0);
      for (size_t i = 0; i < D; ++i) {
        buf.push_back(ret[i * D + j]);
      }
      std::sort(buf.begin(), buf.end());
      assert(buf == base);
    }

    // check cell
    for (size_t i = 0; i < D; ++i) {
      buf.resize(0);
      for (size_t j = 0; j < D; ++j) {
        size_t ii = (i / d) * d + j / d;
        size_t jj = (i % d) * d + j % d;
        buf.push_back(ret[ii * D + jj]);
      }
      std::sort(buf.begin(), buf.end());
      assert(buf == base);
    }

    // for (size_t i = 0; i < D; ++i) {
    //   for (size_t j = 0; j < D; ++j) {
    //     std::cout << std::right << std::setw(4) << std::setfill(' ')
    //               << ret[i * D + j];
    //   }
    //   std::cout << "\n";
    // }
    // std::cout << "\n";

    std::vector<Fr> fr_ret(ret.size());
    for (size_t i = 0; i < ret.size(); ++i) {
      fr_ret[i] = ret[i];
    }
    return fr_ret;
  }

//   static bool Test(size_t d) {
//     size_t D = d * d;
//     auto x = GeneratePuzzle(d); //数独向量
//     assert(x.size() == D * D);

//     Fr com_x_r = FrRand();
//     G1 com_x = pc::ComputeCom(x, com_x_r); //计算承诺

//     auto y = PackUintToFr(CeilLog2(D + 1), x); //将数组元素放入到域元素中(0补齐), ceil向上取整, 当D=2^k时,+1用于补上最高位, 当D != 2^k时, ceil刚好向上+1
//     Fr com_y_r = FrRand();
//     G1 com_y = pc::ComputeCom(y, com_y_r);

//     std::vector<size_t> open_positions(D * D / 3); //数独公开数
//     for (auto& i : open_positions) i = rand() % (D * D);
//     std::sort(open_positions.begin(), open_positions.end());
//     open_positions.erase(
//         std::unique(open_positions.begin(), open_positions.end()),
//         open_positions.end());

//     std::vector<Fr> open_values(open_positions.size());
//     for (size_t i = 0; i < open_positions.size(); ++i) {
//       open_values[i] = x[open_positions[i]];
//     }

//     ProveInput prove_input(x, com_x, com_x_r, y, com_y, com_y_r, open_positions,
//                            pc::kGetRefG1); //证明是一个合法的数独解

//     h256_t seed = misc::RandH256();
//     Proof proof;
//     Prove(proof, seed, prove_input);

// #ifndef DISABLE_SERIALIZE_CHECK
//     // serialize to buffer
//     yas::mem_ostream os;
//     yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
//     oa.serialize(proof);
//     std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
//     // serialize from buffer
//     yas::mem_istream is(os.get_intrusive_buffer());
//     yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
//     Proof proof2;
//     ia.serialize(proof2);
//     if (proof != proof2) {
//       assert(false);
//       std::cout << "oops, serialize check failed\n";
//       return false;
//     }
// #endif

//     VerifyInput verify_input(d, open_positions, open_values, pc::kGetRefG1);
//     bool success = Verify(proof, seed, verify_input);
//     std::cout << "\nSudoku: " << D << "*" << D
//               << ", packed data to " << y.size() << "(fr) \n";
//     std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";
//     return success;
//   }


static bool Test(size_t d) {
    size_t D = d * d;
    auto x = GeneratePuzzle(d); //数独向量
    for(int i=0; i<D; i++){
      for(int j=0; j<D; j++){
          std::cout << x[i] << "\t";
      }
      std::cout << "\n" << std::endl;
    }
    return true;
    assert(x.size() == D * D);

    Fr com_x_r = FrRand();
    G1 com_x = pc::ComputeCom(x, com_x_r); //计算承诺

    auto y = PackUintToFr(CeilLog2(D + 1), x); //将数组元素放入到域元素中(0补齐), ceil向上取整, 当D=2^k时,+1用于补上最高位, 当D != 2^k时, ceil刚好向上+1
    Fr com_y_r = FrRand();
    G1 com_y = pc::ComputeCom(y, com_y_r);

    std::vector<size_t> open_positions(D * D / 3); //数独公开数
    for (auto& i : open_positions) i = rand() % (D * D);
    std::sort(open_positions.begin(), open_positions.end());
    open_positions.erase(
        std::unique(open_positions.begin(), open_positions.end()),
        open_positions.end());

    std::vector<Fr> open_values(open_positions.size());
    for (size_t i = 0; i < open_positions.size(); ++i) {
      open_values[i] = x[open_positions[i]];
    }

    ProveInput prove_input(x, com_x, com_x_r, y, com_y, com_y_r, open_positions,
                           pc::kGetRefG1); //证明是一个合法的数独解

    h256_t seed = misc::RandH256();
    Proof proof;
    Prove(proof, seed, prove_input);

#ifndef DISABLE_SERIALIZE_CHECK
    // serialize to buffer
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa.serialize(proof);
    std::cout << "proof size: " << os.get_shared_buffer().size << "\n";
    // serialize from buffer
    yas::mem_istream is(os.get_intrusive_buffer());
    yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
    Proof proof2;
    ia.serialize(proof2);
    if (proof != proof2) {
      assert(false);
      std::cout << "oops, serialize check failed\n";
      return false;
    }
#endif

    VerifyInput verify_input(d, open_positions, open_values, pc::kGetRefG1);
    bool success = Verify(proof, seed, verify_input);
    std::cout << "\nSudoku: " << D << "*" << D
              << ", packed data to " << y.size() << "(fr) \n";
    std::cout << __FILE__ << " " << __FN__ << ": " << success << "\n\n\n\n\n\n";

    return clink::Pod<clink::VrsMimc5Scheme, groth09::SuccinctPolicy>::TestPod(std::vector<G1>(1, com_y), y, std::vector<Fr>(1, com_y_r), 1, y.size(), ".");
  }
};
}  // namespace clink