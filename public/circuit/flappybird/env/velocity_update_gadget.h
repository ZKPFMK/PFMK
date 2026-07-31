#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"

/**
 * Velocity Update Gadget - 鸟的速度更新电路
 *
 * 对应 Python transition_logic_r1cs 中的 Step 1 + Step 4:
 *
 *   Step 1: 处理动作
 *     bird_vy_after_action = action * UPWARD_SPEED + (1 - action) * bird_vy
 *
 *   Step 4: 更新速度 (重力)
 *     need_gravity = (bird_vy_after_action < MAX_VELOCITY_Y) ? 1 : 0
 *     bird_vy = bird_vy_after_action + need_gravity * DOWNWARD_SPEED
 *
 * 输入：
 *   - bird_vy: 当前鸟的垂直速度 (整数)
 *   - action: 动作 (0=不跳, 1=跳)，必须是 {0, 1}
 *
 * 输出：
 *   - new_bird_vy: 更新后的速度 (整数)
 *
 * 常量：
 *   UPWARD_SPEED = -9
 *   MAX_VELOCITY_Y = 10
 *   DOWNWARD_SPEED = 1
 *
 * 约束逻辑：
 *   1. vy_after_action = action * UPWARD_SPEED + (1 - action) * bird_vy
 *      使用 select_gadget: action==1 选 UPWARD_SPEED, action==0 选 bird_vy
 *   2. need_gravity = (vy_after_action < MAX_VELOCITY_Y) ? 1 : 0
 *      使用 abs_gadget 判断 vy_after_action - MAX_VELOCITY_Y 的符号
 *      当 vy_after_action - MAX_VELOCITY_Y < 0 时 sign=1, need_gravity=sign
 *      注意: 当 vy_after_action == MAX_VELOCITY_Y 时 sign=0, need_gravity=0 (正确)
 *   3. new_bird_vy = vy_after_action + need_gravity * DOWNWARD_SPEED
 *      使用线性约束
 *
 * 注意: 所有值都是整数，不使用定点数。
 */
namespace circuit::flappybird {

class VelocityUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int UPWARD_SPEED = -9;
  static constexpr int MAX_VELOCITY_Y = 10;
  static constexpr int DOWNWARD_SPEED = 1;
  static constexpr size_t VEL_BITS = 5;  // 速度范围 [-9, 10], |val| <= 16 < 2^5

  /**
   * 构造函数
   * @param pb protoboard
   * @param bird_vy 当前鸟的垂直速度
   * @param action 动作 (0 或 1)，可以是 linear_combination
   * @param annotation_prefix 注释前缀
   */
  VelocityUpdateGadget(libsnark::protoboard<Fr>& pb,
                       libsnark::pb_variable<Fr> const& bird_vy,
                       libsnark::linear_combination<Fr> const& action,
                       const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        bird_vy_(bird_vy),
        action_(action) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 生成 witness
   * @param bird_vy_val 当前速度值
   * @param action_val 动作值 (0 或 1)
   */
  void generate_r1cs_witness(int64_t bird_vy_val, int action_val) {
    // Step 1: 动作处理
    vy_after_action_select_->generate_r1cs_witness();

    // Step 2: 重力判断
    vy_minus_max_abs_->generate_r1cs_witness();

    // Step 3: 最终速度 (直接使用子 gadget 计算好的值)
    int64_t vy_after_action = this->pb.val(vy_after_action_select_->ret()).getInt64();
    int64_t need_gravity = this->pb.val(vy_minus_max_abs_->ret_sign()).getInt64();
    this->pb.val(new_bird_vy_) = Fr(vy_after_action + need_gravity * DOWNWARD_SPEED);
  }

  /**
   * 获取更新后的速度
   */
  libsnark::pb_variable<Fr> ret() const { return new_bird_vy_; }

  /**
   * 获取动作处理后的速度 (未加重力)
   */
  libsnark::pb_variable<Fr> ret_vy_after_action() const {
    return vy_after_action_select_->ret();
  }

 private:
  libsnark::pb_variable<Fr> const& bird_vy_;
  libsnark::linear_combination<Fr> action_;

  // 输出
  libsnark::pb_variable<Fr> new_bird_vy_;

  // 子 gadget
  std::unique_ptr<circuit::select_gadget> vy_after_action_select_;
  std::unique_ptr<circuit::abs_gadget> vy_minus_max_abs_;

  void AllocateVariables() {
    new_bird_vy_.allocate(this->pb,
                          FMT(this->annotation_prefix, " new_bird_vy"));
  }

  void GenerateConstraints() {
    // Step 1: vy_after_action = action ? UPWARD_SPEED : bird_vy
    vy_after_action_select_.reset(new circuit::select_gadget(
        this->pb, action_, Fr(UPWARD_SPEED), bird_vy_,
        FMT(this->annotation_prefix, " vy_after_action")));

    // Step 2: need_gravity = (vy_after_action < MAX_VELOCITY_Y) ? 1 : 0
    // diff = vy_after_action - MAX_VELOCITY_Y
    // 当 diff < 0 时 sign=1 (need_gravity=1)
    // 当 diff >= 0 时 sign=0 (need_gravity=0)
    libsnark::linear_combination<Fr> vy_minus_max =
        vy_after_action_select_->ret() - Fr(MAX_VELOCITY_Y);
    vy_minus_max_abs_.reset(new circuit::abs_gadget(
        this->pb, vy_minus_max, VEL_BITS,
        FMT(this->annotation_prefix, " vy_minus_max")));

    // Step 3: new_bird_vy = vy_after_action + need_gravity * DOWNWARD_SPEED
    // need_gravity = vy_minus_max_abs_->ret_sign()
    libsnark::linear_combination<Fr> new_vy_lc =
        vy_after_action_select_->ret() +
        libsnark::linear_combination<Fr>(vy_minus_max_abs_->ret_sign()) * Fr(DOWNWARD_SPEED);
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, new_vy_lc, new_bird_vy_),
        FMT(this->annotation_prefix, " new_vy_calc"));
  }
};

}  // namespace circuit::flappybird
