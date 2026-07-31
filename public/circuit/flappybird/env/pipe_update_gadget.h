#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"

/**
 * Pipe Update Gadget - 管道位置更新电路
 *
 * 对应 Python transition_logic_r1cs 中的 Step 5 + Step 6:
 *
 *   Step 5: 更新管道位置
 *     pipe1_x_new = pipe1_x + PIPE_VELOCITY_X
 *     pipe2_x_new = pipe2_x + PIPE_VELOCITY_X
 *
 *   Step 6: 管道管理 (回收)
 *     check_pipe1_offscreen = (pipe1_x_new < -PIPE_WIDTH) ? 1 : 0
 *     if offscreen:
 *       pipe1_x = pipe2_x_new
 *       pipe1_gap_y = pipe2_gap_y
 *       pipe2_x = SCREEN_WIDTH + 10
 *       pipe2_gap_y = next_gap_y
 *     else:
 *       保持不变
 *
 * 输入：
 *   - pipe1_x: 第一个管道的X位置 (整数)
 *   - pipe1_gap_y: 第一个管道的间隙Y位置 (整数)
 *   - pipe2_x: 第二个管道的X位置 (整数)
 *   - pipe2_gap_y: 第二个管道的间隙Y位置 (整数)
 *   - next_gap_y: 下一个管道的间隙Y (外部输入，确定性)
 *
 * 输出：
 *   - new_pipe1_x, new_pipe1_gap_y
 *   - new_pipe2_x, new_pipe2_gap_y
 *
 * 常量：
 *   PIPE_VELOCITY_X = -4
 *   PIPE_WIDTH = 52
 *   SCREEN_WIDTH = 288
 *
 * 约束逻辑：
 *   1. pipe1_x_moved = pipe1_x + PIPE_VELOCITY_X (线性组合)
 *   2. pipe2_x_moved = pipe2_x + PIPE_VELOCITY_X (线性组合)
 *   3. check_offscreen = (pipe1_x_moved < -PIPE_WIDTH) ? 1 : 0
 *      即 (pipe1_x_moved + PIPE_WIDTH < 0) ? 1 : 0
 *      使用 abs_gadget 判断 pipe1_x_moved + PIPE_WIDTH 的符号
 *   4. 使用 select_gadget 选择输出:
 *      new_pipe1_x = offscreen ? pipe2_x_moved : pipe1_x_moved
 *      new_pipe1_gap_y = offscreen ? pipe2_gap_y : pipe1_gap_y
 *      new_pipe2_x = offscreen ? (SCREEN_WIDTH + 10) : pipe2_x_moved
 *      new_pipe2_gap_y = offscreen ? next_gap_y : pipe2_gap_y
 *
 * 注意: 所有值都是整数。
 *       pipe_x 范围约 [-56, 298], 需要 POS_BITS >= 10
 */
namespace circuit::flappybird {

class PipeUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int PIPE_VELOCITY_X = -4;
  static constexpr int PIPE_WIDTH = 52;
  static constexpr int SCREEN_WIDTH = 288;
  static constexpr int NEW_PIPE_X = SCREEN_WIDTH + 10;  // 298
  static constexpr size_t POS_BITS = 10;  // 位置范围需要 10 位

  /**
   * 构造函数
   * @param pb protoboard
   * @param pipe1_x 第一个管道X位置
   * @param pipe1_gap_y 第一个管道间隙Y
   * @param pipe2_x 第二个管道X位置
   * @param pipe2_gap_y 第二个管道间隙Y
   * @param next_gap_y 下一个管道间隙Y (外部输入)
   * @param annotation_prefix 注释前缀
   */
  PipeUpdateGadget(libsnark::protoboard<Fr>& pb,
                   libsnark::pb_variable<Fr> const& pipe1_x,
                   libsnark::pb_variable<Fr> const& pipe1_gap_y,
                   libsnark::pb_variable<Fr> const& pipe2_x,
                   libsnark::pb_variable<Fr> const& pipe2_gap_y,
                   libsnark::pb_variable<Fr> const& next_gap_y,
                   const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        pipe1_x_(pipe1_x),
        pipe1_gap_y_(pipe1_gap_y),
        pipe2_x_(pipe2_x),
        pipe2_gap_y_(pipe2_gap_y),
        next_gap_y_(next_gap_y) {
    GenerateConstraints();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness(int64_t pipe1_x_val, int64_t pipe1_gap_y_val,
                              int64_t pipe2_x_val, int64_t pipe2_gap_y_val,
                              int64_t next_gap_y_val) {
    // 判断是否离开屏幕
    offscreen_abs_->generate_r1cs_witness();

    // 选择输出
    pipe1_x_select_->generate_r1cs_witness();
    pipe1_gap_y_select_->generate_r1cs_witness();
    pipe2_x_select_->generate_r1cs_witness();
    pipe2_gap_y_select_->generate_r1cs_witness();
  }

  /**
   * 获取输出
   */
  libsnark::pb_variable<Fr> ret_pipe1_x() const { return pipe1_x_select_->ret(); }
  libsnark::pb_variable<Fr> ret_pipe1_gap_y() const { return pipe1_gap_y_select_->ret(); }
  libsnark::pb_variable<Fr> ret_pipe2_x() const { return pipe2_x_select_->ret(); }
  libsnark::pb_variable<Fr> ret_pipe2_gap_y() const { return pipe2_gap_y_select_->ret(); }

 private:
  // 输入
  libsnark::pb_variable<Fr> const& pipe1_x_;
  libsnark::pb_variable<Fr> const& pipe1_gap_y_;
  libsnark::pb_variable<Fr> const& pipe2_x_;
  libsnark::pb_variable<Fr> const& pipe2_gap_y_;
  libsnark::pb_variable<Fr> const& next_gap_y_;

  // 子 gadget
  std::unique_ptr<circuit::abs_gadget> offscreen_abs_;
  std::unique_ptr<circuit::select_gadget> pipe1_x_select_;
  std::unique_ptr<circuit::select_gadget> pipe1_gap_y_select_;
  std::unique_ptr<circuit::select_gadget> pipe2_x_select_;
  std::unique_ptr<circuit::select_gadget> pipe2_gap_y_select_;

  void GenerateConstraints() {
    // 使用线性组合表示移动后的位置，无需额外变量和约束
    // pipe1_x_moved_lc = pipe1_x + PIPE_VELOCITY_X
    libsnark::linear_combination<Fr> pipe1_x_moved_lc =
        pipe1_x_ + Fr(PIPE_VELOCITY_X);

    // pipe2_x_moved_lc = pipe2_x + PIPE_VELOCITY_X
    libsnark::linear_combination<Fr> pipe2_x_moved_lc =
        pipe2_x_ + Fr(PIPE_VELOCITY_X);

    // check_offscreen = (pipe1_x_moved + PIPE_WIDTH < 0) ? 1 : 0
    // 即 (pipe1_x_moved + PIPE_WIDTH) 的符号
    // 当 pipe1_x_moved < -PIPE_WIDTH 时, pipe1_x_moved + PIPE_WIDTH < 0, sign=1
    libsnark::linear_combination<Fr> offscreen_check =
        pipe1_x_moved_lc + Fr(PIPE_WIDTH);
    offscreen_abs_.reset(new circuit::abs_gadget(
        this->pb, offscreen_check, POS_BITS,
        FMT(this->annotation_prefix, " offscreen_check")));

    // offscreen = offscreen_abs_->ret_sign()
    libsnark::linear_combination<Fr> offscreen = offscreen_abs_->ret_sign();

    // new_pipe1_x = offscreen ? pipe2_x_moved : pipe1_x_moved
    pipe1_x_select_.reset(new circuit::select_gadget(
        this->pb, offscreen, pipe2_x_moved_lc, pipe1_x_moved_lc,
        FMT(this->annotation_prefix, " pipe1_x_select")));

    // new_pipe1_gap_y = offscreen ? pipe2_gap_y : pipe1_gap_y
    pipe1_gap_y_select_.reset(new circuit::select_gadget(
        this->pb, offscreen, pipe2_gap_y_, pipe1_gap_y_,
        FMT(this->annotation_prefix, " pipe1_gap_y_select")));

    // new_pipe2_x = offscreen ? NEW_PIPE_X : pipe2_x_moved
    pipe2_x_select_.reset(new circuit::select_gadget(
        this->pb, offscreen, Fr(NEW_PIPE_X), pipe2_x_moved_lc,
        FMT(this->annotation_prefix, " pipe2_x_select")));

    // new_pipe2_gap_y = offscreen ? next_gap_y : pipe2_gap_y
    pipe2_gap_y_select_.reset(new circuit::select_gadget(
        this->pb, offscreen, next_gap_y_, pipe2_gap_y_,
        FMT(this->annotation_prefix, " pipe2_gap_y_select")));
  }
};

}  // namespace circuit::flappybird
