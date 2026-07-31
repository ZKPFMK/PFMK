#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"

/**
 * Paddle Hit Gadget - 球拍碰撞检测电路
 *
 * 功能：
 *   检测球是否与单个球拍发生碰撞
 *   统一处理上下球拍的碰撞检测逻辑
 *
 * 设计思路：
 *   - 传入球的中心位置和球拍的位置信息，检测是否发生碰撞
 *   - X方向：检测球心是否在拍子X范围内
 *     ball_center_x >= paddle_x && ball_center_x <= paddle_x + PADDLE_WIDTH
 *   - Y方向：检测球和拍子是否重叠
 *     ball_top <= paddle_bottom && ball_bottom >= paddle_top
 *     即 (ball_center_y - BALL_RADIUS) <= (paddle_y + PADDLE_HEIGHT)
 *        && (ball_center_y + BALL_RADIUS) >= paddle_y
 *   - 上下球拍使用相同的碰撞检测逻辑，只需传入不同的 paddle_x 和 paddle_y
 *
 * 输入：
 *   - ball_center_x: 球的中心X位置
 *   - ball_center_y: 球的中心Y位置
 *   - paddle_x: 球拍X位置 (左边界)
 *   - paddle_y: 球拍Y位置 (上边界，常量)
 *
 * 输出：
 *   - hit: 是否发生碰撞 (0或1)
 *   - hit_pos: 碰撞位置 (球相对于球拍左边缘的位置)
 *
 * 碰撞条件：
 *   X方向: ball_center_x >= paddle_x && ball_center_x <= paddle_x + PADDLE_WIDTH
 *   Y方向: (ball_center_y - BALL_RADIUS) <= (paddle_y + PADDLE_HEIGHT)
 *          && (ball_center_y + BALL_RADIUS) >= paddle_y
 *
 * 注意：上下球拍的Y轴检测条件在数学上是等价的，区别仅在碰撞响应
 *       (由 BallStateUpdateGadget 处理)。本 gadget 只负责检测是否碰撞。
 */
namespace circuit::pong {

class PaddleHitGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int BALL_RADIUS = 3;
  static constexpr int PADDLE_WIDTH = 20;
  static constexpr int PADDLE_HEIGHT = 3;
  static constexpr size_t POS_BITS = 7;

  /**
   * 构造函数
   * @param pb protoboard
   * @param ball_center_x 球的中心X位置
   * @param ball_center_y 球的中心Y位置
   * @param paddle_x 球拍X位置 (左边界)
   * @param paddle_y 球拍Y位置 (上边界，整数常量)
   * @param annotation_prefix 注释前缀
   */
  PaddleHitGadget(libsnark::protoboard<Fr>& pb,
                  libsnark::pb_variable<Fr> const& ball_center_x,
                  libsnark::pb_variable<Fr> const& ball_center_y,
                  libsnark::pb_variable<Fr> const& paddle_x,
                  int paddle_y,
                  const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        ball_center_x_(ball_center_x),
        ball_center_y_(ball_center_y),
        paddle_x_(paddle_x),
        paddle_y_(paddle_y) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 生成witness
   */
  void generate_r1cs_witness(int64_t ball_center_x_val, int64_t ball_center_y_val,
                              int64_t paddle_x_val) {
    // 生成所有 abs_gadget 的 witness
    ball_center_x_minus_paddle_left_->generate_r1cs_witness();
    paddle_right_minus_ball_center_x_->generate_r1cs_witness();
    paddle_bottom_minus_ball_top_->generate_r1cs_witness();
    ball_bottom_minus_paddle_top_->generate_r1cs_witness();
    
    // 计算球拍边界
    int64_t paddle_left_val = paddle_x_val;
    int64_t paddle_right_val = paddle_x_val + PADDLE_WIDTH;
    int64_t paddle_top_val = paddle_y_;
    int64_t paddle_bottom_val = paddle_y_ + PADDLE_HEIGHT;
    
    // 计算球的上下边界
    int64_t ball_top_val = ball_center_y_val - BALL_RADIUS;
    int64_t ball_bottom_val = ball_center_y_val + BALL_RADIUS;
    
    // X方向检测：球心在拍子X范围内
    bool in_paddle_x = (ball_center_x_val >= paddle_left_val) && 
                       (ball_center_x_val <= paddle_right_val);
    
    // Y方向检测：球和拍子重叠
    // ball_top <= paddle_bottom && ball_bottom >= paddle_top
    bool in_paddle_y = (ball_top_val <= paddle_bottom_val) && 
                       (ball_bottom_val >= paddle_top_val);
    
    // 碰撞条件：X和Y方向都满足
    bool hit = in_paddle_x && in_paddle_y;
    
    // 计算碰撞位置（球心相对于球拍左边缘的位置）
    int64_t hit_pos = ball_center_x_val - paddle_left_val;
    
    // 设置输出变量
    this->pb.val(hit_) = Fr(hit ? 1 : 0);
    this->pb.val(hit_pos_) = Fr(hit_pos);
    this->pb.val(in_paddle_x_) = Fr(in_paddle_x ? 1 : 0);
    this->pb.val(in_paddle_y_) = Fr(in_paddle_y ? 1 : 0);
  }

  /**
   * 获取碰撞结果
   */
  libsnark::pb_variable<Fr> ret_hit() const { return hit_; }
  
  /**
   * 获取碰撞位置
   */
  libsnark::pb_variable<Fr> ret_hit_pos() const { return hit_pos_; }
  
  /**
   * 获取X方向是否在范围内
   */
  libsnark::pb_variable<Fr> ret_in_paddle_x() const { return in_paddle_x_; }
  
  /**
   * 获取Y方向是否在范围内
   */
  libsnark::pb_variable<Fr> ret_in_paddle_y() const { return in_paddle_y_; }

 private:
  // 输入变量 - 球
  libsnark::pb_variable<Fr> const& ball_center_x_;
  libsnark::pb_variable<Fr> const& ball_center_y_;
  
  // 输入变量 - 球拍
  libsnark::pb_variable<Fr> const& paddle_x_;  // 球拍X位置 (变量)
  int paddle_y_;                                 // 球拍Y位置 (常量)
  
  // 输出变量
  libsnark::pb_variable<Fr> hit_;
  libsnark::pb_variable<Fr> hit_pos_;
  libsnark::pb_variable<Fr> in_paddle_x_;
  libsnark::pb_variable<Fr> in_paddle_y_;
  
  // 子gadget
  std::unique_ptr<circuit::abs_gadget> ball_center_x_minus_paddle_left_;
  std::unique_ptr<circuit::abs_gadget> paddle_right_minus_ball_center_x_;
  std::unique_ptr<circuit::abs_gadget> paddle_bottom_minus_ball_top_;
  std::unique_ptr<circuit::abs_gadget> ball_bottom_minus_paddle_top_;
  
  void AllocateVariables() {
    hit_.allocate(this->pb, FMT(this->annotation_prefix, " hit"));
    hit_pos_.allocate(this->pb, FMT(this->annotation_prefix, " hit_pos"));
    in_paddle_x_.allocate(this->pb, FMT(this->annotation_prefix, " in_paddle_x"));
    in_paddle_y_.allocate(this->pb, FMT(this->annotation_prefix, " in_paddle_y"));
  }
  
  void GenerateConstraints() {
    // ========== 球的上下边界（使用线性组合）==========
    // ball_top = ball_center_y - BALL_RADIUS
    // ball_bottom = ball_center_y + BALL_RADIUS
    libsnark::linear_combination<Fr> ball_top_lc = ball_center_y_ - Fr(BALL_RADIUS);
    libsnark::linear_combination<Fr> ball_bottom_lc = ball_center_y_ + Fr(BALL_RADIUS);
    
    // ========== 球拍边界（使用线性组合）==========
    // paddle_left = paddle_x_
    // paddle_right = paddle_x_ + PADDLE_WIDTH
    // paddle_top = paddle_y_ (常量)
    // paddle_bottom = paddle_y_ + PADDLE_HEIGHT (常量)
    libsnark::linear_combination<Fr> paddle_left_lc = paddle_x_;
    libsnark::linear_combination<Fr> paddle_right_lc = paddle_x_ + Fr(PADDLE_WIDTH);
    int paddle_top = paddle_y_;
    int paddle_bottom = paddle_y_ + PADDLE_HEIGHT;
    
    // ========== X方向检测：球心在拍子X范围内 ==========
    // 条件1: ball_center_x >= paddle_left (即 paddle_x)
    // 使用 abs_gadget: sign = 1 when ball_center_x - paddle_x < 0
    // 所以 ball_center_x_ge_paddle_left = 1 - sign
    libsnark::linear_combination<Fr> ball_center_x_minus_left = ball_center_x_ - paddle_left_lc;
    ball_center_x_minus_paddle_left_.reset(new circuit::abs_gadget(
        this->pb, ball_center_x_minus_left, POS_BITS, 
        FMT(this->annotation_prefix, " ball_center_x_minus_paddle_left")));
    
    // 条件2: ball_center_x <= paddle_right (即 paddle_x + PADDLE_WIDTH)
    // 使用 abs_gadget: sign = 1 when paddle_right - ball_center_x < 0
    // 所以 ball_center_x_le_paddle_right = 1 - sign
    libsnark::linear_combination<Fr> paddle_right_minus_ball_center_x = paddle_right_lc - ball_center_x_;
    paddle_right_minus_ball_center_x_.reset(new circuit::abs_gadget(
        this->pb, paddle_right_minus_ball_center_x, POS_BITS, 
        FMT(this->annotation_prefix, " paddle_right_minus_ball_center_x")));
    
    // in_paddle_x = (1 - sign1) * (1 - sign2)
    libsnark::linear_combination<Fr> in_paddle_x_lc = Fr(1);
    in_paddle_x_lc = in_paddle_x_lc - ball_center_x_minus_paddle_left_->ret_sign();
    libsnark::linear_combination<Fr> in_paddle_x_lc2 = Fr(1);
    in_paddle_x_lc2 = in_paddle_x_lc2 - paddle_right_minus_ball_center_x_->ret_sign();
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(in_paddle_x_lc, in_paddle_x_lc2, in_paddle_x_),
        FMT(this->annotation_prefix, " in_paddle_x_calc"));
    
    // ========== Y方向检测：球和拍子重叠 ==========
    // 条件1: ball_top <= paddle_bottom
    //   即 paddle_bottom - ball_top >= 0
    //   即 (paddle_y + PADDLE_HEIGHT) - (ball_center_y - BALL_RADIUS) >= 0
    //   展开: paddle_bottom + BALL_RADIUS - ball_center_y >= 0
    // 使用 abs_gadget: sign = 1 when value < 0
    // 所以 ball_top_le_paddle_bottom = 1 - sign
    libsnark::linear_combination<Fr> paddle_bottom_minus_ball_top =
        libsnark::linear_combination<Fr>(Fr(paddle_bottom + BALL_RADIUS)) - ball_center_y_;
    paddle_bottom_minus_ball_top_.reset(new circuit::abs_gadget(
        this->pb, paddle_bottom_minus_ball_top, POS_BITS, 
        FMT(this->annotation_prefix, " paddle_bottom_minus_ball_top")));
    
    // 条件2: ball_bottom >= paddle_top
    //   即 ball_bottom - paddle_top >= 0
    //   即 (ball_center_y + BALL_RADIUS) - paddle_y >= 0
    // 使用 abs_gadget: sign = 1 when value < 0
    // 所以 ball_bottom_ge_paddle_top = 1 - sign
    libsnark::linear_combination<Fr> ball_bottom_minus_paddle_top =
        ball_center_y_ + Fr(BALL_RADIUS - paddle_top);
    ball_bottom_minus_paddle_top_.reset(new circuit::abs_gadget(
        this->pb, ball_bottom_minus_paddle_top, POS_BITS, 
        FMT(this->annotation_prefix, " ball_bottom_minus_paddle_top")));
    
    // in_paddle_y = (1 - sign1) * (1 - sign2)
    libsnark::linear_combination<Fr> in_paddle_y_lc = Fr(1);
    in_paddle_y_lc = in_paddle_y_lc - paddle_bottom_minus_ball_top_->ret_sign();
    libsnark::linear_combination<Fr> in_paddle_y_lc2 = Fr(1);
    in_paddle_y_lc2 = in_paddle_y_lc2 - ball_bottom_minus_paddle_top_->ret_sign();
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(in_paddle_y_lc, in_paddle_y_lc2, in_paddle_y_),
        FMT(this->annotation_prefix, " in_paddle_y_calc"));
    
    // ========== 碰撞结果 ==========
    // hit = in_paddle_x * in_paddle_y
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(in_paddle_x_, in_paddle_y_, hit_),
        FMT(this->annotation_prefix, " hit_calc"));
    
    // ========== 碰撞位置 ==========
    // hit_pos = ball_center_x - paddle_x
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_center_x_ - paddle_x_, hit_pos_),
        FMT(this->annotation_prefix, " hit_pos_calc"));
  }
};

}  // namespace circuit::pong
