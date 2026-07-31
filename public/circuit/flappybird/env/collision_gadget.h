#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/or_gadget.h"
#include "circuit/flappybird/env/pipe_collision_gadget.h"

/**
 * Collision Gadget - 碰撞检测电路
 *
 * 对应 Python transition_logic_r1cs 中的 Step 7:
 *
 *   地面碰撞:
 *     ground_collision = (bird_y + BIRD_HEIGHT >= BASE_Y) ? 1 : 0
 *
 *   管道碰撞 (对每个管道调用 PipeCollisionGadget):
 *     pipe_collision_1 = PipeCollisionGadget(bird_y, pipe1_x, pipe1_gap_y)
 *     pipe_collision_2 = PipeCollisionGadget(bird_y, pipe2_x, pipe2_gap_y)
 *
 *   总碰撞:
 *     any_collision = ground_collision OR pipe_collision_1 OR pipe_collision_2
 *
 * 输入：
 *   - bird_y: 鸟的Y位置 (整数)
 *   - pipe1_x, pipe1_gap_y: 管道1的位置
 *   - pipe2_x, pipe2_gap_y: 管道2的位置
 *
 * 输出：
 *   - any_collision: 是否发生碰撞 (0 或 1)
 *
 * 常量：
 *   BIRD_HEIGHT = 24, BASE_Y = 404
 *
 * 注意: 所有值都是整数。
 */
namespace circuit::flappybird {

class CollisionGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int BIRD_HEIGHT = 24;
  static constexpr int BASE_Y = 404;
  static constexpr size_t POS_BITS = 10;

  /**
   * 构造函数
   */
  CollisionGadget(libsnark::protoboard<Fr>& pb,
                  libsnark::pb_variable<Fr> const& bird_y,
                  libsnark::pb_variable<Fr> const& pipe1_x,
                  libsnark::pb_variable<Fr> const& pipe1_gap_y,
                  libsnark::pb_variable<Fr> const& pipe2_x,
                  libsnark::pb_variable<Fr> const& pipe2_gap_y,
                  const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        bird_y_(bird_y),
        pipe1_x_(pipe1_x),
        pipe1_gap_y_(pipe1_gap_y),
        pipe2_x_(pipe2_x),
        pipe2_gap_y_(pipe2_gap_y) {
    GenerateConstraints();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness() {
    // 地面碰撞
    ground_collision_abs_->generate_r1cs_witness();

    // 管道碰撞
    pipe1_collision_->generate_r1cs_witness();
    pipe2_collision_->generate_r1cs_witness();

    // 总碰撞
    pipe_collision_or_->generate_r1cs_witness();
    any_collision_or_->generate_r1cs_witness();
  }

  /**
   * 获取碰撞结果
   */
  libsnark::pb_variable<Fr> ret() const { return any_collision_or_->ret(); }

 private:
  // 输入
  libsnark::pb_variable<Fr> const& bird_y_;
  libsnark::pb_variable<Fr> const& pipe1_x_;
  libsnark::pb_variable<Fr> const& pipe1_gap_y_;
  libsnark::pb_variable<Fr> const& pipe2_x_;
  libsnark::pb_variable<Fr> const& pipe2_gap_y_;

  // 子 gadget
  std::unique_ptr<circuit::abs_gadget> ground_collision_abs_;
  std::unique_ptr<PipeCollisionGadget> pipe1_collision_;
  std::unique_ptr<PipeCollisionGadget> pipe2_collision_;
  std::unique_ptr<circuit::or_gadget1> pipe_collision_or_;
  std::unique_ptr<circuit::or_gadget1> any_collision_or_;

  void GenerateConstraints() {
    // ========== 地面碰撞 ==========
    // ground_collision = (bird_y + BIRD_HEIGHT >= BASE_Y) ? 1 : 0
    // diff = bird_y + BIRD_HEIGHT - BASE_Y
    // 当 diff >= 0 时碰撞, sign=0 => ground_collision = 1 - sign
    libsnark::linear_combination<Fr> ground_diff =
        libsnark::linear_combination<Fr>(bird_y_) + Fr(BIRD_HEIGHT - BASE_Y);
    ground_collision_abs_.reset(new circuit::abs_gadget(
        this->pb, ground_diff, POS_BITS,
        FMT(this->annotation_prefix, " ground_collision")));
    // ground_collision = 1 - ground_collision_abs_->ret_sign()
    libsnark::linear_combination<Fr> ground_collision =
        libsnark::linear_combination<Fr>(ground_collision_abs_->ret_sign()) * Fr(-1) + Fr(1);

    // ========== 管道碰撞 (使用 PipeCollisionGadget) ==========
    pipe1_collision_.reset(new PipeCollisionGadget(
        this->pb, bird_y_, pipe1_x_, pipe1_gap_y_,
        FMT(this->annotation_prefix, " pipe1_collision")));

    pipe2_collision_.reset(new PipeCollisionGadget(
        this->pb, bird_y_, pipe2_x_, pipe2_gap_y_,
        FMT(this->annotation_prefix, " pipe2_collision")));

    // ========== 总碰撞 ==========
    // pipe_collision = pipe1_collision OR pipe2_collision
    pipe_collision_or_.reset(new circuit::or_gadget1(
        this->pb,
        pipe1_collision_->ret(),
        pipe2_collision_->ret(),
        FMT(this->annotation_prefix, " pipe_collision_or")));

    // any_collision = ground_collision OR pipe_collision
    any_collision_or_.reset(new circuit::or_gadget1(
        this->pb,
        ground_collision,
        pipe_collision_or_->ret(),
        FMT(this->annotation_prefix, " any_collision_or")));
  }
};

}  // namespace circuit::flappybird
