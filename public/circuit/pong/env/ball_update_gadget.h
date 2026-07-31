#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/max_gadget.h"
#include "circuit/basic/min_gadget.h"

/**
 * Ball Update Gadget - 球位置更新与边界反弹电路
 *
 * 功能：
 *   1. 更新球的X位置 (位置 += 速度)
 *   2. 左右边界反弹检测
 *   3. 计算反弹后的X速度
 *   4. 更新球的Y位置 (位置 += 速度)
 *
 * 输入：
 *   - ball_x: 当前球的X位置
 *   - ball_vx: 当前球的X速度
 *   - ball_y: 当前球的Y位置
 *   - ball_vy: 当前球的Y速度
 *
 * 输出：
 *   - new_ball_x: 更新后的球X位置
 *   - new_ball_vx: 更新后的球X速度 (考虑边界反弹)
 *   - new_ball_y: 更新后的球Y位置
 */
namespace circuit::pong {

class BallUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int SCREEN_WIDTH = 84;
  static constexpr int BALL_RADIUS = 3;
  static constexpr size_t POS_BITS = 7;
  static constexpr size_t VEL_BITS = 3;

  /**
   * 构造函数
   * @param pb protoboard
   * @param ball_x 当前球的X位置
   * @param ball_vx 当前球的X速度
   * @param ball_y 当前球的Y位置
   * @param ball_vy 当前球的Y速度
   * @param annotation_prefix 注释前缀
   */
  BallUpdateGadget(libsnark::protoboard<Fr>& pb,
                   libsnark::pb_variable<Fr> const& ball_x,
                   libsnark::pb_variable<Fr> const& ball_vx,
                   libsnark::pb_variable<Fr> const& ball_y,
                   libsnark::pb_variable<Fr> const& ball_vy,
                   const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        ball_x_(ball_x),
        ball_vx_(ball_vx),
        ball_y_(ball_y),
        ball_vy_(ball_vy) {
    // 分配变量
    no_hit_vx_.allocate(pb, FMT(this->annotation_prefix, " no_hit_vx"));
    hit_vx_.allocate(pb, FMT(this->annotation_prefix, " hit_vx"));
    ball_vx_after_.allocate(pb, FMT(this->annotation_prefix, " ball_vx_after"));
    ball_y_after_.allocate(pb, FMT(this->annotation_prefix, " ball_y_after"));
    
    // 创建 abs_gadget 用于计算 |ball_vx|
    abs_vx_gadget_.reset(new circuit::abs_gadget(
        pb, ball_vx, VEL_BITS, FMT(this->annotation_prefix, " abs_vx")));
    
    // 创建 max_gadget 和 min_gadget 用于边界限制
    // ball_x_expected = ball_x + ball_vx (线性组合)
    libsnark::linear_combination<Fr> ball_x_expected = ball_x + ball_vx;
    
    ball_x_max_gadget_.reset(new circuit::max_gadget(
        pb, ball_x_expected, Fr(BALL_RADIUS), POS_BITS,
        FMT(this->annotation_prefix, " ball_x_max")));
    
    int64_t max_ball_x = SCREEN_WIDTH - BALL_RADIUS - 1;
    ball_x_min_gadget_.reset(new circuit::min_gadget(
        pb, ball_x_max_gadget_->ret(), Fr(max_ball_x), POS_BITS,
        FMT(this->annotation_prefix, " ball_x_min")));
    
    // 在构造函数中生成约束
    // left_hit = (ball_x_expected <= BALL_RADIUS) = ball_x_max_gadget_->get_abs()->ret_sign()
    libsnark::linear_combination<Fr> left_hit = ball_x_max_gadget_->get_abs()->ret_sign();
    
    // right_hit = (ball_x_expected >= MAX) = 1 - ball_x_min_gadget_->get_abs()->ret_sign()
    libsnark::linear_combination<Fr> right_hit = -ball_x_min_gadget_->get_abs()->ret_sign() + 1;
    
    // no_hit = 1 - left_hit - right_hit
    libsnark::linear_combination<Fr> no_hit = -left_hit - right_hit + 1;
    
    // hit_vx = (left_hit - right_hit) * abs_ball_vx
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(left_hit - right_hit, abs_vx_gadget_->ret_abs(), hit_vx_),
        FMT(this->annotation_prefix, " hit_vx_calc"));
    
    // ball_vx_after = hit_vx + no_hit * ball_vx
    // 合并了 no_hit_vx 和 ball_vx_after 的约束
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(no_hit, ball_vx_, ball_vx_after_ - hit_vx_),
        FMT(this->annotation_prefix, " ball_vx_after_calc"));
    
    // ball_y_after = ball_y + ball_vy
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_y_ + ball_vy_, ball_y_after_),
        FMT(this->annotation_prefix, " ball_y_after_calc"));
  }

  /**
   * 生成witness
   * @param ball_x_val 当前球的X位置值
   * @param ball_vx_val 当前球的X速度值
   * @param ball_y_val 当前球的Y位置值
   * @param ball_vy_val 当前球的Y速度值
   */
  void generate_r1cs_witness(int64_t ball_x_val, int64_t ball_vx_val,
                              int64_t ball_y_val, int64_t ball_vy_val) {
    // 生成 abs_vx_gadget witness
    abs_vx_gadget_->generate_r1cs_witness();
    
    // 生成 ball_x_max_gadget 和 ball_x_min_gadget witness
    ball_x_max_gadget_->generate_r1cs_witness();
    ball_x_min_gadget_->generate_r1cs_witness();
    
    // 计算 hit_vx 和 no_hit_vx
    // 从 abs_gadget 的 sign 直接读取碰撞状态，确保与约束一致
    int64_t left_hit_val = this->pb.val(ball_x_max_gadget_->get_abs()->ret_sign()).getInt64();
    int64_t min_sign_val = this->pb.val(ball_x_min_gadget_->get_abs()->ret_sign()).getInt64();
    int64_t right_hit_val = 1 - min_sign_val;
    bool left_hit = (left_hit_val != 0);
    bool right_hit = (right_hit_val != 0);
    int64_t abs_vx = this->pb.val(abs_vx_gadget_->ret_abs()).getInt64();
    
    int64_t hit_vx_val = (left_hit ? abs_vx : 0) - (right_hit ? abs_vx : 0);
    int64_t no_hit_vx_val = (!left_hit && !right_hit) ? ball_vx_val : 0;
    int64_t ball_vx_after_val = hit_vx_val + no_hit_vx_val;
    
    this->pb.val(hit_vx_) = Fr(hit_vx_val);
    this->pb.val(no_hit_vx_) = Fr(no_hit_vx_val);
    this->pb.val(ball_vx_after_) = Fr(ball_vx_after_val);
    
    // 计算 ball_y_after
    int64_t ball_y_after_val = ball_y_val + ball_vy_val;
    this->pb.val(ball_y_after_) = Fr(ball_y_after_val);
  }

  /**
   * 获取更新后的球X位置
   */
  libsnark::pb_variable<Fr> ret_ball_x() const {
    return ball_x_min_gadget_->ret();
  }

  /**
   * 获取更新后的球X速度 (边界反弹后)
   */
  libsnark::pb_variable<Fr> ret_ball_vx() const {
    return ball_vx_after_;
  }

  /**
   * 获取更新后的球Y位置
   */
  libsnark::pb_variable<Fr> ret_ball_y() const {
    return ball_y_after_;
  }

  /**
   * 获取 hit_vx 变量
   */
  libsnark::pb_variable<Fr> ret_hit_vx() const {
    return hit_vx_;
  }

  /**
   * 获取 no_hit_vx 变量
   */
  libsnark::pb_variable<Fr> ret_no_hit_vx() const {
    return no_hit_vx_;
  }

  /**
   * 获取 abs_vx_gadget (用于后续电路)
   */
  circuit::abs_gadget* get_abs_vx_gadget() const {
    return abs_vx_gadget_.get();
  }

  /**
   * 获取 ball_x_max_gadget (用于后续电路)
   */
  circuit::max_gadget* get_ball_x_max_gadget() const {
    return ball_x_max_gadget_.get();
  }

  /**
   * 获取 ball_x_min_gadget (用于后续电路)
   */
  circuit::min_gadget* get_ball_x_min_gadget() const {
    return ball_x_min_gadget_.get();
  }

 private:
  libsnark::pb_variable<Fr> const& ball_x_;
  libsnark::pb_variable<Fr> const& ball_vx_;
  libsnark::pb_variable<Fr> const& ball_y_;
  libsnark::pb_variable<Fr> const& ball_vy_;
  
  libsnark::pb_variable<Fr> no_hit_vx_;
  libsnark::pb_variable<Fr> hit_vx_;
  libsnark::pb_variable<Fr> ball_vx_after_;
  libsnark::pb_variable<Fr> ball_y_after_;
  
  std::unique_ptr<circuit::abs_gadget> abs_vx_gadget_;
  std::unique_ptr<circuit::max_gadget> ball_x_max_gadget_;
  std::unique_ptr<circuit::min_gadget> ball_x_min_gadget_;
};

}  // namespace circuit::pong
