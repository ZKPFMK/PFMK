#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"
#include "circuit/basic/max_gadget.h"

/**
 * Bird Update Gadget - 鸟的位置更新电路
 *
 * 对应 Python transition_logic_r1cs 中的 Step 4 (位置部分):
 *
 *   bird_y_new = bird_y + bird_vy
 *   need_clamp = (bird_y_new < 0) ? 1 : 0
 *   bird_y = need_clamp * 0 + (1 - need_clamp) * bird_y_new
 *   bird_vy_final = need_clamp * 0 + (1 - need_clamp) * bird_vy
 *
 * 输入：
 *   - bird_y: 当前鸟的Y位置 (整数)
 *   - bird_vy: 更新后的速度 (来自 VelocityUpdateGadget)
 *
 * 输出：
 *   - new_bird_y: 更新后的Y位置 (整数, >= 0)
 *   - new_bird_vy: 最终速度 (如果触顶则为0)
 *
 * 约束逻辑：
 *   1. bird_y_raw = bird_y + bird_vy (线性)
 *   2. new_bird_y = max(bird_y_raw, 0)
 *      使用 max_gadget
 *   3. need_clamp = (bird_y_raw < 0) ? 1 : 0
 *      从 max_gadget 内部的 abs_gadget 获取 sign
 *   4. new_bird_vy = need_clamp ? 0 : bird_vy
 *      使用 select_gadget
 *
 * 注意: 所有值都是整数，不使用定点数。
 *       bird_y 范围 [0, 404], 需要 POS_BITS >= 10
 */
namespace circuit::flappybird {

class BirdUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int BASE_Y = 404;
  static constexpr size_t POS_BITS = 10;  // bird_y 范围 [0, 404], 需要 10 位

  /**
   * 构造函数
   * @param pb protoboard
   * @param bird_y 当前鸟的Y位置
   * @param bird_vy 更新后的速度 (来自 VelocityUpdateGadget)
   * @param annotation_prefix 注释前缀
   */
  BirdUpdateGadget(libsnark::protoboard<Fr>& pb,
                   libsnark::pb_variable<Fr> const& bird_y,
                   libsnark::pb_variable<Fr> const& bird_vy,
                   const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        bird_y_(bird_y),
        bird_vy_(bird_vy) {
    GenerateConstraints();
  }

  /**
   * 生成 witness
   * @param bird_y_val 当前Y位置值
   * @param bird_vy_val 更新后的速度值
   */
  void generate_r1cs_witness(int64_t bird_y_val, int64_t bird_vy_val) {
    // max_gadget 内部会处理 witness
    bird_y_max_gadget_->generate_r1cs_witness();
    // select_gadget 处理 vy 的 clamp
    vy_clamp_select_->generate_r1cs_witness();
  }

  /**
   * 获取更新后的Y位置 (>= 0)
   */
  libsnark::pb_variable<Fr> ret_bird_y() const {
    return bird_y_max_gadget_->ret();
  }

  /**
   * 获取最终速度 (触顶时为0)
   */
  libsnark::pb_variable<Fr> ret_bird_vy() const {
    return vy_clamp_select_->ret();
  }

 private:
  libsnark::pb_variable<Fr> const& bird_y_;
  libsnark::pb_variable<Fr> const& bird_vy_;

  // 子 gadget
  std::unique_ptr<circuit::max_gadget> bird_y_max_gadget_;
  std::unique_ptr<circuit::select_gadget> vy_clamp_select_;

  void GenerateConstraints() {
    // bird_y_raw = bird_y + bird_vy (线性组合)
    libsnark::linear_combination<Fr> bird_y_raw = bird_y_ + bird_vy_;

    // new_bird_y = max(bird_y_raw, 0)
    bird_y_max_gadget_.reset(new circuit::max_gadget(
        this->pb, bird_y_raw, Fr(0), POS_BITS,
        FMT(this->annotation_prefix, " bird_y_max")));

    // need_clamp = sign of (bird_y_raw - 0) when bird_y_raw < 0
    // max_gadget 内部: abs(bird_y_raw - 0), sign=1 when bird_y_raw < 0
    // need_clamp = abs_gadget->ret_sign()
    libsnark::linear_combination<Fr> need_clamp =
        bird_y_max_gadget_->get_abs()->ret_sign();

    // new_bird_vy = need_clamp ? 0 : bird_vy
    vy_clamp_select_.reset(new circuit::select_gadget(
        this->pb, need_clamp, Fr(0), bird_vy_,
        FMT(this->annotation_prefix, " vy_clamp")));
  }
};

}  // namespace circuit::flappybird
