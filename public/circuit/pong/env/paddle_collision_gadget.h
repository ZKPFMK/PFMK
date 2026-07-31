#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"
#include "circuit/pong/env/paddle_hit_gadget.h"

/**
 * Paddle Collision Gadget - 球拍碰撞处理电路
 *
 * 功能：
 *   1. 调用 PaddleHitGadget 检测球是否与上下球拍发生碰撞
 *   2. 根据碰撞结果计算碰撞后球的位置和速度
 *
 * 设计思路：
 *   - 碰撞检测：调用两次 PaddleHitGadget，分别传入上下球拍信息
 *   - 碰撞响应：
 *     - 上方球拍碰撞: ball_y = PADDLE1_Y + PADDLE_HEIGHT + BALL_RADIUS,
 *                      ball_vy = abs(ball_vy)
 *     - 下方球拍碰撞: ball_y = PADDLE2_Y - BALL_RADIUS - 1,
 *                      ball_vy = -abs(ball_vy)
 *     - 碰撞位置决定 ball_vx: 左半边向左(-BALL_SPEED), 右半边向右(BALL_SPEED)
 *
 * 输入：
 *   - ball_x: 球的X位置
 *   - ball_y: 球的Y位置 (预期位置，已加上速度)
 *   - ball_vx: 球的X速度
 *   - ball_vy: 球的Y速度
 *   - paddle1_x: 玩家1球拍X位置 (上方)
 *   - paddle2_x: 玩家2球拍X位置 (下方)
 *
 * 输出：
 *   - ball_y_after: 碰撞后的球Y位置
 *   - ball_vx_after: 碰撞后的球X速度
 *   - ball_vy_after: 碰撞后的球Y速度
 *   - hit_paddle1: 是否碰到球拍1
 *   - hit_paddle2: 是否碰到球拍2
 */
namespace circuit::pong {

class PaddleCollisionGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int SCREEN_WIDTH = 84;
  static constexpr int BALL_RADIUS = 3;
  static constexpr int BALL_SPEED = 2;
  static constexpr int PADDLE_WIDTH = 20;
  static constexpr int PADDLE_HEIGHT = 3;
  static constexpr int PADDLE1_Y = 5;
  static constexpr int PADDLE2_Y = 76;
  static constexpr size_t POS_BITS = 7;
  static constexpr size_t VEL_BITS = 3;

  /**
   * 构造函数
   */
  PaddleCollisionGadget(libsnark::protoboard<Fr>& pb,
                         libsnark::pb_variable<Fr> const& ball_x,
                         libsnark::pb_variable<Fr> const& ball_y,
                         libsnark::pb_variable<Fr> const& ball_vx,
                         libsnark::pb_variable<Fr> const& ball_vy,
                         libsnark::pb_variable<Fr> const& paddle1_x,
                         libsnark::pb_variable<Fr> const& paddle2_x,
                         const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        ball_x_(ball_x),
        ball_y_(ball_y),
        ball_vx_(ball_vx),
        ball_vy_(ball_vy),
        paddle1_x_(paddle1_x),
        paddle2_x_(paddle2_x) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 生成witness
   */
  void generate_r1cs_witness(int64_t ball_x_val, int64_t ball_y_val,
                              int64_t ball_vx_val, int64_t ball_vy_val,
                              int64_t paddle1_x_val, int64_t paddle2_x_val) {
    // 生成碰撞检测 witness
    paddle1_hit_gadget_->generate_r1cs_witness(ball_x_val, ball_y_val, paddle1_x_val);
    paddle2_hit_gadget_->generate_r1cs_witness(ball_x_val, ball_y_val, paddle2_x_val);
    
    // 生成 abs_vy_gadget witness
    abs_vy_gadget_->generate_r1cs_witness();
    
    // 生成 hit_pos_minus_half gadgets witness
    hit_pos1_minus_half_->generate_r1cs_witness();
    hit_pos2_minus_half_->generate_r1cs_witness();
    
    // 生成 select_gadget witness（链式依赖，顺序执行）
    ball_y_after_paddle1_select_->generate_r1cs_witness();
    ball_y_after_paddle2_select_->generate_r1cs_witness();
    ball_vy_after_paddle1_select_->generate_r1cs_witness();
    ball_vy_after_paddle2_select_->generate_r1cs_witness();
    ball_vx_after_paddle1_select_->generate_r1cs_witness();
    ball_vx_after_paddle2_select_->generate_r1cs_witness();
  }

  /**
   * 获取输出变量
   */
  libsnark::pb_variable<Fr> ret_ball_y() const { return ball_y_after_paddle2_select_->ret(); }
  libsnark::pb_variable<Fr> ret_ball_vx() const { return ball_vx_after_paddle2_select_->ret(); }
  libsnark::pb_variable<Fr> ret_ball_vy() const { return ball_vy_after_paddle2_select_->ret(); }
  libsnark::pb_variable<Fr> ret_hit_paddle1() const { return paddle1_hit_gadget_->ret_hit(); }
  libsnark::pb_variable<Fr> ret_hit_paddle2() const { return paddle2_hit_gadget_->ret_hit(); }

 private:
  // 输入变量
  libsnark::pb_variable<Fr> const& ball_x_;
  libsnark::pb_variable<Fr> const& ball_y_;
  libsnark::pb_variable<Fr> const& ball_vx_;
  libsnark::pb_variable<Fr> const& ball_vy_;
  libsnark::pb_variable<Fr> const& paddle1_x_;
  libsnark::pb_variable<Fr> const& paddle2_x_;
  
  // 注：输出变量直接使用 select_gadget 的 ret()，无需额外变量
  // 注：is_left / new_vx 使用线性组合表示，无需额外变量
  
  // 子gadget - 碰撞检测
  std::unique_ptr<PaddleHitGadget> paddle1_hit_gadget_;
  std::unique_ptr<PaddleHitGadget> paddle2_hit_gadget_;
  
  // 子gadget - 碰撞响应
  std::unique_ptr<circuit::abs_gadget> abs_vy_gadget_;
  std::unique_ptr<circuit::abs_gadget> hit_pos1_minus_half_;
  std::unique_ptr<circuit::abs_gadget> hit_pos2_minus_half_;
  std::unique_ptr<circuit::select_gadget> ball_y_after_paddle1_select_;
  std::unique_ptr<circuit::select_gadget> ball_y_after_paddle2_select_;
  std::unique_ptr<circuit::select_gadget> ball_vy_after_paddle1_select_;
  std::unique_ptr<circuit::select_gadget> ball_vy_after_paddle2_select_;
  std::unique_ptr<circuit::select_gadget> ball_vx_after_paddle1_select_;
  std::unique_ptr<circuit::select_gadget> ball_vx_after_paddle2_select_;
  
  void AllocateVariables() {
    // 所有变量都由子 gadget 内部分配，无需额外分配
  }
  
  void GenerateConstraints() {
    // ========== 碰撞检测：调用 PaddleHitGadget ==========
    // 上方球拍 (paddle1)
    paddle1_hit_gadget_.reset(new PaddleHitGadget(
        this->pb, ball_x_, ball_y_,
        paddle1_x_, PADDLE1_Y,
        FMT(this->annotation_prefix, " paddle1_hit")));
    
    // 下方球拍 (paddle2)
    paddle2_hit_gadget_.reset(new PaddleHitGadget(
        this->pb, ball_x_, ball_y_,
        paddle2_x_, PADDLE2_Y,
        FMT(this->annotation_prefix, " paddle2_hit")));
    
    // ========== 碰撞响应：计算碰撞后的状态 ==========
    
    // abs(ball_vy) 用于碰撞后的速度计算
    abs_vy_gadget_.reset(new circuit::abs_gadget(
        this->pb, ball_vy_, VEL_BITS, FMT(this->annotation_prefix, " abs_vy")));
    
    // ---- 计算碰撞后的 ball_vx ----
    // is_left = sign(hit_pos - PADDLE_WIDTH/2)，直接用 abs_gadget 的 ret_sign()
    // new_vx = BALL_SPEED - 2 * BALL_SPEED * is_left，用线性组合表示
    libsnark::linear_combination<Fr> hit_pos1_minus_half_lc =
        paddle1_hit_gadget_->ret_hit_pos() - Fr(PADDLE_WIDTH / 2);
    hit_pos1_minus_half_.reset(new circuit::abs_gadget(
        this->pb, hit_pos1_minus_half_lc, POS_BITS,
        FMT(this->annotation_prefix, " hit_pos1_minus_half")));
    
    // new_vx1 = BALL_SPEED - 2 * BALL_SPEED * sign1 (线性组合，无需额外约束)
    libsnark::linear_combination<Fr> new_vx1_lc;
    new_vx1_lc = new_vx1_lc + Fr(BALL_SPEED);
    new_vx1_lc = new_vx1_lc - (2 * BALL_SPEED) * libsnark::linear_combination<Fr>(hit_pos1_minus_half_->ret_sign());
    
    libsnark::linear_combination<Fr> hit_pos2_minus_half_lc =
        paddle2_hit_gadget_->ret_hit_pos() - Fr(PADDLE_WIDTH / 2);
    hit_pos2_minus_half_.reset(new circuit::abs_gadget(
        this->pb, hit_pos2_minus_half_lc, POS_BITS,
        FMT(this->annotation_prefix, " hit_pos2_minus_half")));
    
    // new_vx2 = BALL_SPEED - 2 * BALL_SPEED * sign2 (线性组合，无需额外约束)
    libsnark::linear_combination<Fr> new_vx2_lc;
    new_vx2_lc = new_vx2_lc + Fr(BALL_SPEED);
    new_vx2_lc = new_vx2_lc - (2 * BALL_SPEED) * libsnark::linear_combination<Fr>(hit_pos2_minus_half_->ret_sign());
    
    // ---- ball_y 碰撞响应 ----
    // paddle1 碰撞: ball_y = PADDLE1_Y + PADDLE_HEIGHT + BALL_RADIUS
    // paddle2 碰撞: ball_y = PADDLE2_Y - BALL_RADIUS - 1
    // 先处理 paddle1，再处理 paddle2（链式 select）
    ball_y_after_paddle1_select_.reset(new circuit::select_gadget(
        this->pb, paddle1_hit_gadget_->ret_hit(),
        Fr(PADDLE1_Y + PADDLE_HEIGHT + BALL_RADIUS),
        ball_y_,
        FMT(this->annotation_prefix, " ball_y_after_paddle1")));
    
    ball_y_after_paddle2_select_.reset(new circuit::select_gadget(
        this->pb, paddle2_hit_gadget_->ret_hit(),
        Fr(PADDLE2_Y - BALL_RADIUS - 1),
        ball_y_after_paddle1_select_->ret(),
        FMT(this->annotation_prefix, " ball_y_after_paddle2")));
    
    // ---- ball_vy 碰撞响应 ----
    // paddle1 碰撞: ball_vy = abs(ball_vy) (向下)
    // paddle2 碰撞: ball_vy = -abs(ball_vy) (向上)
    ball_vy_after_paddle1_select_.reset(new circuit::select_gadget(
        this->pb, paddle1_hit_gadget_->ret_hit(),
        abs_vy_gadget_->ret_abs(),
        ball_vy_,
        FMT(this->annotation_prefix, " ball_vy_after_paddle1")));
    
    ball_vy_after_paddle2_select_.reset(new circuit::select_gadget(
        this->pb, paddle2_hit_gadget_->ret_hit(),
        -abs_vy_gadget_->ret_abs(),
        ball_vy_after_paddle1_select_->ret(),
        FMT(this->annotation_prefix, " ball_vy_after_paddle2")));
    
    // ---- ball_vx 碰撞响应 ----
    // paddle1 碰撞: ball_vx = new_vx1
    // paddle2 碰撞: ball_vx = new_vx2
    ball_vx_after_paddle1_select_.reset(new circuit::select_gadget(
        this->pb, paddle1_hit_gadget_->ret_hit(),
        new_vx1_lc,
        ball_vx_,
        FMT(this->annotation_prefix, " ball_vx_after_paddle1")));
    
    ball_vx_after_paddle2_select_.reset(new circuit::select_gadget(
        this->pb, paddle2_hit_gadget_->ret_hit(),
        new_vx2_lc,
        ball_vx_after_paddle1_select_->ret(),
        FMT(this->annotation_prefix, " ball_vx_after_paddle2")));
  }
};

}  // namespace circuit::pong
