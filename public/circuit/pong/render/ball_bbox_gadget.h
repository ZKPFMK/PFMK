#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"

namespace circuit::pong {

/**
 * BallBboxGadget - 球包围盒 (Bounding Box) 行列判断 Gadget
 *
 * 计算球的 bbox 范围: [ball_y - R, ball_y + R] x [ball_x - R, ball_x + R]
 * 先用 bbox 做快速筛选，再在 bbox 内做精确的圆形判断。
 *
 * 功能:
 *   1. 计算每个行是否在球的 bbox 行范围内
 *   2. 计算每个列是否在球的 bbox 列范围内
 *   3. 计算每个列到球心的 X 方向距离平方 (dx_sq)
 *   4. 计算每个行到球心的 Y 方向距离平方 (dy_sq)
 *
 * 使用 abs_batch_gadget 批量处理行/列范围判断 (利用并行化加速)。
 *
 * 输入:
 *   - ball_x: 球心 X 坐标
 *   - ball_y: 球心 Y 坐标
 *   - ball_radius: 球的半径
 *   - image_width: 图像宽度
 *   - image_height: 图像高度
 *
 * 输出:
 *   - ball_row_flag[row]: 行标志数组, = 1 表示该行在球的 bbox 范围内
 *   - ball_col_flag[col]: 列标志数组, = 1 表示该列在球的 bbox 范围内
 *   - dx_sq[col]: 每个列到球心的 X 方向距离平方
 *   - dy_sq[row]: 每个行到球心的 Y 方向距离平方
 */
class BallBboxGadget : public libsnark::gadget<Fr> {
 public:
  // ========== 常量 ==========
  static constexpr size_t COL_BITS = 7;  // 列坐标范围判断所需比特位 (0-83 需要 7 位)

  /**
   * 构造函数
   *
   * @param pb protoboard
   * @param ball_x 球心 X 坐标
   * @param ball_y 球心 Y 坐标
   * @param ball_radius 球的半径
   * @param image_width 图像宽度
   * @param image_height 图像高度
   * @param annotation_prefix 注释前缀
   */
  BallBboxGadget(libsnark::protoboard<Fr>& pb,
                 libsnark::pb_variable<Fr> const& ball_x,
                 libsnark::pb_variable<Fr> const& ball_y,
                 int ball_radius,
                 int image_width,
                 int image_height,
                 const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        ball_x_(ball_x),
        ball_y_(ball_y),
        ball_radius_(ball_radius),
        image_width_(image_width),
        image_height_(image_height) {
    // ========================================================================
    // 第一步: 分配球 bbox 行列标志变量
    // ========================================================================
    ball_row_flag_.allocate(this->pb, image_height_,
                            FMT(this->annotation_prefix, " brf"));
    ball_col_flag_.allocate(this->pb, image_width_,
                            FMT(this->annotation_prefix, " bcf"));

    // ========================================================================
    // 第二步: 批量判断每一行是否在球的 bbox 行范围内
    // 条件: ball_y - R <= row <= ball_y + R
    // 等价于: (row - ball_y + R) >= 0 AND (ball_y + R - row) >= 0
    // ========================================================================
    {
      libsnark::linear_combination_array<Fr> row_lower_lcs;
      libsnark::linear_combination_array<Fr> row_upper_lcs;
      for (int row = 0; row < image_height_; ++row) {
        row_lower_lcs.emplace_back(-ball_y_ + Fr(row + ball_radius_));
        row_upper_lcs.emplace_back(ball_y_ + Fr(ball_radius_ - row));
      }

      ball_row_lower_abs_batch_.reset(new circuit::abs_batch_gadget(
          this->pb, row_lower_lcs, COL_BITS,
          FMT(this->annotation_prefix, " brlo_batch")));
      ball_row_upper_abs_batch_.reset(new circuit::abs_batch_gadget(
          this->pb, row_upper_lcs, COL_BITS,
          FMT(this->annotation_prefix, " brhi_batch")));

      for (int row = 0; row < image_height_; ++row) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                -ball_row_lower_abs_batch_->ret_sign(row) + Fr(1),
                -ball_row_upper_abs_batch_->ret_sign(row) + Fr(1),
                ball_row_flag_[row]),
            FMT(this->annotation_prefix, " brf_%d", row));
      }
    }

    // ========================================================================
    // 第三步: 批量判断每一列是否在球的 bbox 列范围内
    // 条件: ball_x - R <= col <= ball_x + R
    // 等价于: (col - ball_x + R) >= 0 AND (ball_x + R - col) >= 0
    // ========================================================================
    {
      libsnark::linear_combination_array<Fr> col_lower_lcs;
      libsnark::linear_combination_array<Fr> col_upper_lcs;
      for (int col = 0; col < image_width_; ++col) {
        col_lower_lcs.emplace_back(-ball_x_ + Fr(col + ball_radius_));
        col_upper_lcs.emplace_back(ball_x_ + Fr(ball_radius_ - col));
      }

      ball_col_lower_abs_batch_.reset(new circuit::abs_batch_gadget(
          this->pb, col_lower_lcs, COL_BITS,
          FMT(this->annotation_prefix, " bclo_batch")));
      ball_col_upper_abs_batch_.reset(new circuit::abs_batch_gadget(
          this->pb, col_upper_lcs, COL_BITS,
          FMT(this->annotation_prefix, " bchi_batch")));

      for (int col = 0; col < image_width_; ++col) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                -ball_col_lower_abs_batch_->ret_sign(col) + Fr(1),
                -ball_col_upper_abs_batch_->ret_sign(col) + Fr(1),
                ball_col_flag_[col]),
            FMT(this->annotation_prefix, " bcf_%d", col));
      }
    }

    // ========================================================================
    // 第四步: 计算距离平方 dx_sq 和 dy_sq (用于圆形判断)
    // ========================================================================
    dx_sq_.allocate(this->pb, image_width_,
                    FMT(this->annotation_prefix, " dxs"));
    dy_sq_.allocate(this->pb, image_height_,
                    FMT(this->annotation_prefix, " dys"));

    for (int col = 0; col < image_width_; ++col) {
      libsnark::linear_combination<Fr> dx = -ball_x_ + Fr(col);
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(dx, dx, dx_sq_[col]),
          FMT(this->annotation_prefix, " dxs_%d", col));
    }

    for (int row = 0; row < image_height_; ++row) {
      libsnark::linear_combination<Fr> dy = -ball_y_ + Fr(row);
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(dy, dy, dy_sq_[row]),
          FMT(this->annotation_prefix, " dys_%d", row));
    }
  }

  // ========== 访问器 ==========

  libsnark::pb_variable_array<Fr> const& ball_row_flag() const { return ball_row_flag_; }
  libsnark::pb_variable_array<Fr> const& ball_col_flag() const { return ball_col_flag_; }
  libsnark::pb_variable_array<Fr> const& dx_sq() const { return dx_sq_; }
  libsnark::pb_variable_array<Fr> const& dy_sq() const { return dy_sq_; }

  /**
   * 生成 witness
   *
   * @param ball_x_val 球心 X 坐标的具体值
   * @param ball_y_val 球心 Y 坐标的具体值
   */
  void generate_r1cs_witness(int64_t ball_x_val, int64_t ball_y_val) {
    // 预计算行范围差值, 跳过昂贵的 evaluate 调用
    std::vector<int64_t> row_lower_vals(image_height_);
    std::vector<int64_t> row_upper_vals(image_height_);
    for (int row = 0; row < image_height_; ++row) {
      row_lower_vals[row] = row - ball_y_val + ball_radius_;   // row - ball_y + R
      row_upper_vals[row] = ball_y_val + ball_radius_ - row;   // ball_y + R - row
    }
    ball_row_lower_abs_batch_->generate_r1cs_witness_precomputed(row_lower_vals);
    ball_row_upper_abs_batch_->generate_r1cs_witness_precomputed(row_upper_vals);
    for (int row = 0; row < image_height_; ++row) {
      bool in_row = (row >= ball_y_val - ball_radius_) && (row <= ball_y_val + ball_radius_);
      this->pb.val(ball_row_flag_[row]) = Fr(in_row ? 1 : 0);
    }

    // 预计算列范围差值
    std::vector<int64_t> col_lower_vals(image_width_);
    std::vector<int64_t> col_upper_vals(image_width_);
    for (int col = 0; col < image_width_; ++col) {
      col_lower_vals[col] = col - ball_x_val + ball_radius_;   // col - ball_x + R
      col_upper_vals[col] = ball_x_val + ball_radius_ - col;   // ball_x + R - col
    }
    ball_col_lower_abs_batch_->generate_r1cs_witness_precomputed(col_lower_vals);
    ball_col_upper_abs_batch_->generate_r1cs_witness_precomputed(col_upper_vals);
    for (int col = 0; col < image_width_; ++col) {
      bool in_col = (col >= ball_x_val - ball_radius_) && (col <= ball_x_val + ball_radius_);
      this->pb.val(ball_col_flag_[col]) = Fr(in_col ? 1 : 0);
    }

    // 计算距离平方的 witness
    for (int col = 0; col < image_width_; ++col) {
      int64_t dx = col - ball_x_val;
      this->pb.val(dx_sq_[col]) = Fr(dx * dx);
    }
    for (int row = 0; row < image_height_; ++row) {
      int64_t dy = row - ball_y_val;
      this->pb.val(dy_sq_[row]) = Fr(dy * dy);
    }
  }

 private:
  // ========== 输入参数 ==========
  libsnark::pb_variable<Fr> const& ball_x_;
  libsnark::pb_variable<Fr> const& ball_y_;
  int ball_radius_;
  int image_width_;
  int image_height_;

  // ========== 输出变量 ==========
  libsnark::pb_variable_array<Fr> ball_row_flag_;
  libsnark::pb_variable_array<Fr> ball_col_flag_;
  libsnark::pb_variable_array<Fr> dx_sq_;
  libsnark::pb_variable_array<Fr> dy_sq_;

  // ========== 内部 gadget (批量化) ==========
  std::unique_ptr<circuit::abs_batch_gadget> ball_row_lower_abs_batch_;
  std::unique_ptr<circuit::abs_batch_gadget> ball_row_upper_abs_batch_;
  std::unique_ptr<circuit::abs_batch_gadget> ball_col_lower_abs_batch_;
  std::unique_ptr<circuit::abs_batch_gadget> ball_col_upper_abs_batch_;
};

}  // namespace circuit::pong
