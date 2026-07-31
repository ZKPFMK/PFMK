#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/and_gadget.h"
#include "circuit/basic/or_gadget.h"

/**
 * Pipe Collision Gadget - 单个管道碰撞检测电路
 *
 * 检测鸟是否与单个管道发生碰撞。
 *
 * 碰撞条件:
 *   1. X方向重叠: pipe_x < bird_right AND pipe_x + PIPE_WIDTH > bird_left
 *   2. Y方向碰撞: bird_y < gap_y (撞上管) OR bird_y + BIRD_HEIGHT > gap_y + PIPE_GAP_SIZE (撞下管)
 *   3. 总碰撞: x_overlap AND y_collision
 *
 * 输入：
 *   - bird_y: 鸟的Y位置 (整数)
 *   - pipe_x: 管道的X位置 (整数)
 *   - pipe_gap_y: 管道间隙的Y位置 (整数，间隙顶部)
 *
 * 输出：
 *   - collision: 是否碰撞 (0 或 1)
 *
 * 常量 (来自游戏设定):
 *   BIRD_X = 57, BIRD_WIDTH = 34, BIRD_HEIGHT = 24
 *   PIPE_WIDTH = 52, PIPE_GAP_SIZE = 100
 *   BIRD_LEFT = 57, BIRD_RIGHT = 91
 */
namespace circuit::flappybird {

class PipeCollisionGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int BIRD_X = 57;
  static constexpr int BIRD_WIDTH = 34;
  static constexpr int BIRD_HEIGHT = 24;
  static constexpr int PIPE_WIDTH = 52;
  static constexpr int PIPE_GAP_SIZE = 100;
  static constexpr int BIRD_LEFT = BIRD_X;              // 57
  static constexpr int BIRD_RIGHT = BIRD_X + BIRD_WIDTH; // 91
  static constexpr size_t POS_BITS = 10;

  /**
   * 构造函数
   * @param pb protoboard
   * @param bird_y 鸟的Y位置
   * @param pipe_x 管道X位置
   * @param pipe_gap_y 管道间隙Y位置
   * @param annotation_prefix 注释前缀
   */
  PipeCollisionGadget(libsnark::protoboard<Fr>& pb,
                      libsnark::pb_variable<Fr> const& bird_y,
                      libsnark::pb_variable<Fr> const& pipe_x,
                      libsnark::pb_variable<Fr> const& pipe_gap_y,
                      const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        bird_y_(bird_y),
        pipe_x_(pipe_x),
        pipe_gap_y_(pipe_gap_y) {
    GenerateConstraints();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness() {
    x_overlap_left_->generate_r1cs_witness();
    x_overlap_right_->generate_r1cs_witness();
    x_overlap_and_->generate_r1cs_witness();
    hit_upper_->generate_r1cs_witness();
    hit_lower_->generate_r1cs_witness();
    hit_or_->generate_r1cs_witness();
    collision_and_->generate_r1cs_witness();
  }

  /**
   * 获取碰撞结果
   */
  libsnark::pb_variable<Fr> ret() const { return collision_and_->ret(); }

 private:
  // 输入
  libsnark::pb_variable<Fr> const& bird_y_;
  libsnark::pb_variable<Fr> const& pipe_x_;
  libsnark::pb_variable<Fr> const& pipe_gap_y_;

  // 子 gadget
  std::unique_ptr<circuit::abs_gadget> x_overlap_left_;
  std::unique_ptr<circuit::abs_gadget> x_overlap_right_;
  std::unique_ptr<circuit::and_gadget> x_overlap_and_;
  std::unique_ptr<circuit::abs_gadget> hit_upper_;
  std::unique_ptr<circuit::abs_gadget> hit_lower_;
  std::unique_ptr<circuit::or_gadget1> hit_or_;
  std::unique_ptr<circuit::and_gadget> collision_and_;

  void GenerateConstraints() {
    // ========== X方向重叠检测 ==========
    // 条件1: pipe_x < BIRD_RIGHT  =>  BIRD_RIGHT - 1 - pipe_x >= 0
    // 使用 abs_gadget: sign=1 when value < 0
    // in_range_left = 1 - sign
    libsnark::linear_combination<Fr> x_left_diff =
        libsnark::linear_combination<Fr>(pipe_x_) * Fr(-1) + Fr(BIRD_RIGHT - 1);
    x_overlap_left_.reset(new circuit::abs_gadget(
        this->pb, x_left_diff, POS_BITS,
        FMT(this->annotation_prefix, " x_overlap_left")));

    // 条件2: pipe_x + PIPE_WIDTH > BIRD_LEFT  =>  pipe_x + PIPE_WIDTH - 1 - BIRD_LEFT >= 0
    libsnark::linear_combination<Fr> x_right_diff =
        libsnark::linear_combination<Fr>(pipe_x_) + Fr(PIPE_WIDTH - 1 - BIRD_LEFT);
    x_overlap_right_.reset(new circuit::abs_gadget(
        this->pb, x_right_diff, POS_BITS,
        FMT(this->annotation_prefix, " x_overlap_right")));

    // x_overlap = (1 - sign_left) AND (1 - sign_right)
    libsnark::linear_combination<Fr> in_range_left =
        libsnark::linear_combination<Fr>(x_overlap_left_->ret_sign()) * Fr(-1) + Fr(1);
    libsnark::linear_combination<Fr> in_range_right =
        libsnark::linear_combination<Fr>(x_overlap_right_->ret_sign()) * Fr(-1) + Fr(1);
    x_overlap_and_.reset(new circuit::and_gadget(
        this->pb, in_range_left, in_range_right,
        FMT(this->annotation_prefix, " x_overlap")));

    // ========== Y方向碰撞检测 ==========
    // hit_upper = (bird_y < gap_y) ? 1 : 0
    //   gap_y - bird_y - 1 >= 0  =>  sign=0 => hit_upper = 1 - sign
    libsnark::linear_combination<Fr> upper_diff =
        libsnark::linear_combination<Fr>(pipe_gap_y_) - libsnark::linear_combination<Fr>(bird_y_) - Fr(1);
    hit_upper_.reset(new circuit::abs_gadget(
        this->pb, upper_diff, POS_BITS,
        FMT(this->annotation_prefix, " hit_upper")));
    libsnark::linear_combination<Fr> hit_upper_flag =
        libsnark::linear_combination<Fr>(hit_upper_->ret_sign()) * Fr(-1) + Fr(1);

    // hit_lower = (bird_y + BIRD_HEIGHT > gap_y + PIPE_GAP_SIZE) ? 1 : 0
    //   bird_y + BIRD_HEIGHT - gap_y - PIPE_GAP_SIZE - 1 >= 0
    libsnark::linear_combination<Fr> lower_diff =
        libsnark::linear_combination<Fr>(bird_y_) + Fr(BIRD_HEIGHT - PIPE_GAP_SIZE - 1) - libsnark::linear_combination<Fr>(pipe_gap_y_);
    hit_lower_.reset(new circuit::abs_gadget(
        this->pb, lower_diff, POS_BITS,
        FMT(this->annotation_prefix, " hit_lower")));
    libsnark::linear_combination<Fr> hit_lower_flag =
        libsnark::linear_combination<Fr>(hit_lower_->ret_sign()) * Fr(-1) + Fr(1);

    // hit_y = hit_upper OR hit_lower
    hit_or_.reset(new circuit::or_gadget1(
        this->pb, hit_upper_flag, hit_lower_flag,
        FMT(this->annotation_prefix, " hit_or")));

    // ========== 总碰撞 ==========
    // collision = x_overlap AND hit_y
    collision_and_.reset(new circuit::and_gadget(
        this->pb,
        x_overlap_and_->ret(),
        hit_or_->ret(),
        FMT(this->annotation_prefix, " collision")));
  }
};

}  // namespace circuit::flappybird
