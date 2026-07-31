#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"

namespace circuit::flappybird {

/**
 * RangeFlagGadget - 范围判断 Gadget
 *
 * 对于一组预计算的常量值 vals[i], 判断每个值是否满足:
 *   base <= vals[i] < base + width
 *
 * 其中 base 是一个变量 (pb_variable), vals[i] 是编译时常量。
 *
 * 该条件等价于两个差值都 >= 0:
 *   - 下界差值: vals[i] - base >= 0
 *   - 上界差值: base + width - 1 - vals[i] >= 0
 *
 * 使用 abs_batch_gadget 批量判断差值符号, 组合得到标志:
 *   flag[i] = (1 - lower_sign[i]) * (1 - upper_sign[i])
 *
 * 输入:
 *   - base: 范围起始值 (变量)
 *   - width: 范围宽度 (常量)
 *   - vals: 预计算的常量值数组
 *
 * 输出:
 *   - flag[i]: 标志数组, flag[i] = 1 表示 vals[i] 在 [base, base + width) 内
 *
 * 设计参考: pong/render/paddle_col_flag_gadget.h
 */
class RangeFlagGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr size_t RANGE_BITS = 10;  // 值范围所需比特位 (0-404 需要 10 位)

  /**
   * 构造函数
   *
   * @param pb protoboard
   * @param base 范围起始值 (变量)
   * @param width 范围宽度 (常量)
   * @param vals 预计算的常量值数组
   * @param annotation_prefix 注释前缀
   */
  RangeFlagGadget(libsnark::protoboard<Fr>& pb,
                  libsnark::pb_variable<Fr> const& base,
                  int width,
                  std::vector<int> const& vals,
                  const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        base_(base),
        width_(width),
        vals_(vals),
        num_items_(vals.size()) {
    // 分配标志变量
    flag_.allocate(this->pb, num_items_, FMT(this->annotation_prefix, " flag"));

    // 构建下界和上界的 linear_combination 数组
    libsnark::linear_combination_array<Fr> lower_lcs;
    libsnark::linear_combination_array<Fr> upper_lcs;
    for (int i = 0; i < num_items_; ++i) {
      // 下界差值: vals[i] - base (>= 0 表示 vals[i] >= base)
      lower_lcs.emplace_back(-base_ + Fr(vals_[i]));
      // 上界差值: base + width - 1 - vals[i] (>= 0 表示 vals[i] < base + width)
      upper_lcs.emplace_back(base_ + Fr(width_ - 1 - vals_[i]));
    }

    // 使用 abs_batch_gadget 批量判断差值符号
    lower_abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, lower_lcs, RANGE_BITS,
        FMT(this->annotation_prefix, " lo_batch")));
    upper_abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, upper_lcs, RANGE_BITS,
        FMT(this->annotation_prefix, " hi_batch")));

    // flag[i] = (1 - lower_sign[i]) * (1 - upper_sign[i])
    for (int i = 0; i < num_items_; ++i) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(
              -lower_abs_batch_->ret_sign(i) + Fr(1),
              -upper_abs_batch_->ret_sign(i) + Fr(1),
              flag_[i]),
          FMT(this->annotation_prefix, " flag_%d", i));
    }
  }

  /**
   * 获取标志数组
   * flag[i] = 1 表示 vals[i] 在 [base, base + width) 内
   */
  libsnark::pb_variable_array<Fr> const& flag() const { return flag_; }

  /**
   * 生成 witness
   *
   * @param base_val 范围起始值的具体值
   */
  void generate_r1cs_witness(int64_t base_val) {
    // 预计算下界和上界差值
    std::vector<int64_t> lower_vals(num_items_);
    std::vector<int64_t> upper_vals(num_items_);
    for (int i = 0; i < num_items_; ++i) {
      lower_vals[i] = vals_[i] - base_val;                    // vals[i] - base
      upper_vals[i] = base_val + width_ - 1 - vals_[i];       // base + width - 1 - vals[i]
    }

    lower_abs_batch_->generate_r1cs_witness_precomputed(lower_vals);
    upper_abs_batch_->generate_r1cs_witness_precomputed(upper_vals);

    // 设置标志
    for (int i = 0; i < num_items_; ++i) {
      bool in_range = (vals_[i] >= base_val) && (vals_[i] < base_val + width_);
      this->pb.val(flag_[i]) = Fr(in_range ? 1 : 0);
    }
  }

 private:
  libsnark::pb_variable<Fr> const& base_;
  int width_;
  std::vector<int> vals_;
  int num_items_;

  libsnark::pb_variable_array<Fr> flag_;

  std::unique_ptr<circuit::abs_batch_gadget> lower_abs_batch_;
  std::unique_ptr<circuit::abs_batch_gadget> upper_abs_batch_;
};

/**
 * LessThanFlagGadget - 小于判断 Gadget
 *
 * 对于一组预计算的常量值 vals[i], 判断每个值是否满足:
 *   vals[i] < threshold
 *
 * 其中 threshold 是一个变量 (pb_variable), vals[i] 是编译时常量。
 *
 * 该条件等价于: threshold - 1 - vals[i] >= 0
 *
 * 使用 abs_batch_gadget 批量判断差值符号:
 *   flag[i] = 1 - sign[i]
 *
 * 输入:
 *   - threshold: 阈值 (变量)
 *   - vals: 预计算的常量值数组
 *
 * 输出:
 *   - flag[i]: 标志数组, flag[i] = 1 表示 vals[i] < threshold
 */
class LessThanFlagGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr size_t RANGE_BITS = 10;

  /**
   * 构造函数
   *
   * @param pb protoboard
   * @param threshold 阈值 (变量)
   * @param vals 预计算的常量值数组
   * @param annotation_prefix 注释前缀
   */
  LessThanFlagGadget(libsnark::protoboard<Fr>& pb,
                     libsnark::pb_variable<Fr> const& threshold,
                     std::vector<int> const& vals,
                     const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        threshold_(threshold),
        vals_(vals),
        num_items_(vals.size()) {
    // 分配标志变量
    flag_.allocate(this->pb, num_items_, FMT(this->annotation_prefix, " flag"));

    // 构建差值: threshold - 1 - vals[i] (>= 0 表示 vals[i] < threshold)
    libsnark::linear_combination_array<Fr> diff_lcs;
    for (int i = 0; i < num_items_; ++i) {
      diff_lcs.emplace_back(threshold_ + Fr(-1 - vals_[i]));
    }

    abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, diff_lcs, RANGE_BITS,
        FMT(this->annotation_prefix, " abs_batch")));

    // flag[i] = 1 - sign[i]
    for (int i = 0; i < num_items_; ++i) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(
              1, -abs_batch_->ret_sign(i) + Fr(1), flag_[i]),
          FMT(this->annotation_prefix, " flag_%d", i));
    }
  }

  libsnark::pb_variable_array<Fr> const& flag() const { return flag_; }

  /**
   * 生成 witness
   *
   * @param threshold_val 阈值的具体值
   */
  void generate_r1cs_witness(int64_t threshold_val) {
    std::vector<int64_t> diff_vals(num_items_);
    for (int i = 0; i < num_items_; ++i) {
      diff_vals[i] = threshold_val - 1 - vals_[i];
    }
    abs_batch_->generate_r1cs_witness_precomputed(diff_vals);

    for (int i = 0; i < num_items_; ++i) {
      bool lt = vals_[i] < threshold_val;
      this->pb.val(flag_[i]) = Fr(lt ? 1 : 0);
    }
  }

 private:
  libsnark::pb_variable<Fr> const& threshold_;
  std::vector<int> vals_;
  int num_items_;

  libsnark::pb_variable_array<Fr> flag_;
  std::unique_ptr<circuit::abs_batch_gadget> abs_batch_;
};

/**
 * GreaterEqFlagGadget - 大于等于判断 Gadget
 *
 * 对于一组预计算的常量值 vals[i], 判断每个值是否满足:
 *   vals[i] >= threshold
 *
 * 其中 threshold 是一个变量 (linear_combination), vals[i] 是编译时常量。
 *
 * 该条件等价于: vals[i] - threshold >= 0
 *
 * 使用 abs_batch_gadget 批量判断差值符号:
 *   flag[i] = 1 - sign[i]
 *
 * 输入:
 *   - threshold: 阈值 (linear_combination, 可以是 pipe_gap_y + PIPE_GAP_SIZE)
 *   - vals: 预计算的常量值数组
 *
 * 输出:
 *   - flag[i]: 标志数组, flag[i] = 1 表示 vals[i] >= threshold
 */
class GreaterEqFlagGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr size_t RANGE_BITS = 10;

  /**
   * 构造函数
   *
   * @param pb protoboard
   * @param threshold 阈值 (linear_combination)
   * @param vals 预计算的常量值数组
   * @param annotation_prefix 注释前缀
   */
  GreaterEqFlagGadget(libsnark::protoboard<Fr>& pb,
                      libsnark::linear_combination<Fr> const& threshold,
                      std::vector<int> const& vals,
                      const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        threshold_(threshold),
        vals_(vals),
        num_items_(vals.size()) {
    // 分配标志变量
    flag_.allocate(this->pb, num_items_, FMT(this->annotation_prefix, " flag"));

    // 构建差值: vals[i] - threshold (>= 0 表示 vals[i] >= threshold)
    libsnark::linear_combination_array<Fr> diff_lcs;
    for (int i = 0; i < num_items_; ++i) {
      diff_lcs.emplace_back(-threshold_ + Fr(vals_[i]));
    }

    abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, diff_lcs, RANGE_BITS,
        FMT(this->annotation_prefix, " abs_batch")));

    // flag[i] = 1 - sign[i]
    for (int i = 0; i < num_items_; ++i) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(
              1, -abs_batch_->ret_sign(i) + Fr(1), flag_[i]),
          FMT(this->annotation_prefix, " flag_%d", i));
    }
  }

  libsnark::pb_variable_array<Fr> const& flag() const { return flag_; }

  /**
   * 生成 witness
   *
   * @param threshold_val 阈值的具体值
   */
  void generate_r1cs_witness(int64_t threshold_val) {
    std::vector<int64_t> diff_vals(num_items_);
    for (int i = 0; i < num_items_; ++i) {
      diff_vals[i] = vals_[i] - threshold_val;
    }
    abs_batch_->generate_r1cs_witness_precomputed(diff_vals);

    for (int i = 0; i < num_items_; ++i) {
      bool ge = vals_[i] >= threshold_val;
      this->pb.val(flag_[i]) = Fr(ge ? 1 : 0);
    }
  }

 private:
  libsnark::linear_combination<Fr> threshold_;
  std::vector<int> vals_;
  int num_items_;

  libsnark::pb_variable_array<Fr> flag_;
  std::unique_ptr<circuit::abs_batch_gadget> abs_batch_;
};

}  // namespace circuit::flappybird
