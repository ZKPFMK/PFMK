#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"

namespace circuit::pong {

/**
 * PaddleColFlagGadget - 球拍列范围判断 Gadget
 *
 * 对于每个列 col, 判断是否满足: paddle_x <= col < paddle_x + width
 * 该条件等价于两个差值都 >= 0:
 *   - 下界差值: col - paddle_x >= 0
 *   - 上界差值: paddle_x + width - 1 - col >= 0
 *
 * 使用 abs_batch_gadget 批量判断差值符号 (利用并行化加速), 组合得到列标志:
 *   col_flag[col] = (1 - lower_sign) * (1 - upper_sign)
 *
 * 输入:
 *   - paddle_x: 球拍左边界 X 坐标
 *   - width: 球拍宽度
 *
 * 输出:
 *   - col_flag[col]: 列标志数组, col_flag[col] = 1 表示该列在球拍范围内
 */
class PaddleColFlagGadget : public libsnark::gadget<Fr> {
 public:
  // ========== 常量 ==========
  static constexpr size_t COL_BITS = 7;  // 列坐标范围判断所需比特位 (0-83 需要 7 位)

  /**
   * 构造函数
   *
   * @param pb protoboard
   * @param paddle_x 球拍左边界 X 坐标
   * @param width 球拍宽度
   * @param num_cols 列数 (默认 84)
   * @param annotation_prefix 注释前缀
   */
  PaddleColFlagGadget(libsnark::protoboard<Fr>& pb,
                      libsnark::pb_variable<Fr> const& paddle_x,
                      int width,
                      int num_cols,
                      const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        paddle_x_(paddle_x),
        width_(width),
        num_cols_(num_cols) {
    // 分配列标志变量
    col_flag_.allocate(this->pb, num_cols_, FMT(this->annotation_prefix, " cf"));

    // 构建下界和上界的 linear_combination 数组
    libsnark::linear_combination_array<Fr> lower_lcs;
    libsnark::linear_combination_array<Fr> upper_lcs;
    for (int col = 0; col < num_cols_; ++col) {
      // 下界差值: col - paddle_x (>= 0 表示 col >= paddle_x)
      lower_lcs.emplace_back(-paddle_x_ + Fr(col));
      // 上界差值: paddle_x + width - 1 - col (>= 0 表示 col < paddle_x + width)
      upper_lcs.emplace_back(paddle_x_ + Fr(width_ - 1 - col));
    }

    // 使用 abs_batch_gadget 批量判断差值符号 (内部使用 parallel::For 加速)
    lower_abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, lower_lcs, COL_BITS,
        FMT(this->annotation_prefix, " lo_batch")));
    upper_abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, upper_lcs, COL_BITS,
        FMT(this->annotation_prefix, " hi_batch")));

    // col_flag[col] = (1 - lower_sign[col]) * (1 - upper_sign[col])
    for (int col = 0; col < num_cols_; ++col) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(
              -lower_abs_batch_->ret_sign(col) + Fr(1),
              -upper_abs_batch_->ret_sign(col) + Fr(1),
              col_flag_[col]),
          FMT(this->annotation_prefix, " cf_%d", col));
    }
  }

  /**
   * 获取列标志数组
   * col_flag[col] = 1 表示该列在球拍范围 [paddle_x, paddle_x + width) 内
   */
  libsnark::pb_variable_array<Fr> const& col_flag() const { return col_flag_; }

  /**
   * 生成 witness
   *
   * @param paddle_x_val 球拍左边界的具体值
   */
  void generate_r1cs_witness(int64_t paddle_x_val) {
    // 预计算下界和上界差值, 跳过昂贵的 evaluate 调用
    std::vector<int64_t> lower_vals(num_cols_);
    std::vector<int64_t> upper_vals(num_cols_);
    for (int col = 0; col < num_cols_; ++col) {
      lower_vals[col] = col - paddle_x_val;                   // col - paddle_x
      upper_vals[col] = paddle_x_val + width_ - 1 - col;     // paddle_x + width - 1 - col
    }

    lower_abs_batch_->generate_r1cs_witness_precomputed(lower_vals);
    upper_abs_batch_->generate_r1cs_witness_precomputed(upper_vals);

    // 设置列标志
    for (int col = 0; col < num_cols_; ++col) {
      bool in_range = (col >= paddle_x_val) && (col < paddle_x_val + width_);
      this->pb.val(col_flag_[col]) = Fr(in_range ? 1 : 0);
    }
  }

 private:
  // ========== 输入参数 ==========
  libsnark::pb_variable<Fr> const& paddle_x_;  // 球拍左边界 X 坐标
  int width_;                                   // 球拍宽度
  int num_cols_;                                // 列数

  // ========== 输出变量 ==========
  libsnark::pb_variable_array<Fr> col_flag_;  // 列标志数组

  // ========== 内部 gadget (批量化) ==========
  std::unique_ptr<circuit::abs_batch_gadget> lower_abs_batch_;  // 下界批量判断
  std::unique_ptr<circuit::abs_batch_gadget> upper_abs_batch_;  // 上界批量判断
};

}  // namespace circuit::pong
