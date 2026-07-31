#pragma once

#include "circuit/func.h"
#include "circuit/basic/max_gadget.h"
#include "circuit/basic/min_gadget.h"
#include "circuit/basic/onehot_gadget.h"

/**
 * Paddle Update Gadget - 球拍位置更新电路
 *
 * 功能：
 *   1. 根据动作更新球拍位置
 *   2. 确保球拍位置在有效范围内
 *
 * 输入：
 *   - paddle_x: 当前球拍X位置
 *   - action: 动作 (0=不动, 1=左, 2=右)
 *
 * 输出：
 *   - new_paddle_x: 更新后的球拍X位置
 */
namespace circuit::pong {

class PaddleUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int SCREEN_WIDTH = 84;
  static constexpr int PADDLE_WIDTH = 20;
  static constexpr int PADDLE_SPEED = 3;
  static constexpr size_t POS_BITS = 7;

  /**
   * 构造函数
   * @param pb protoboard
   * @param paddle_x 当前球拍位置
   * @param action 动作 (0=不动, 1=左, 2=右)，可以是 pb_variable 或 linear_combination
   * @param annotation_prefix 注释前缀
   */
  PaddleUpdateGadget(libsnark::protoboard<Fr>& pb,
                     libsnark::pb_variable<Fr> const& paddle_x,
                     libsnark::linear_combination<Fr> const& action,
                     const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        paddle_x_(paddle_x),
        action_(action) {
    // 创建 onehot_gadget 用于动作编码
    action_onehot_.reset(new circuit::onehot_gadget(
        pb, action, 3, FMT(this->annotation_prefix, " action_onehot")));
    
    // paddle_expected 作为线性组合: paddle_x + PADDLE_SPEED * (right - left)
    // 使用 linear_combination 的方式来避免歧义
    // paddle_expected_lc_ = paddle_x + PADDLE_SPEED * right - PADDLE_SPEED * left
    libsnark::linear_combination<Fr> right_minus_left = action_onehot_->bits[2] - action_onehot_->bits[1];
    paddle_expected_lc_ = paddle_x_ + PADDLE_SPEED * right_minus_left;
    
    // 创建 max_gadget 和 min_gadget 用于边界限制
    paddle_max_gadget_.reset(new circuit::max_gadget(
        pb, paddle_expected_lc_, Fr(0), POS_BITS,
        FMT(this->annotation_prefix, " paddle_max")));
    
    int64_t max_paddle_x = SCREEN_WIDTH - PADDLE_WIDTH;
    paddle_min_gadget_.reset(new circuit::min_gadget(
        pb, paddle_max_gadget_->ret(), Fr(max_paddle_x), POS_BITS,
        FMT(this->annotation_prefix, " paddle_min")));
  }

  /**
   * 生成witness
   * @param paddle_x_val 当前球拍位置值
   * @param action_val 动作值
   */
  void generate_r1cs_witness(int64_t paddle_x_val, int action_val) {
    // 生成 onehot witness
    action_onehot_->generate_r1cs_witness();
    
    // 生成 max 和 min witness
    paddle_max_gadget_->generate_r1cs_witness();
    paddle_min_gadget_->generate_r1cs_witness();
  }

  /**
   * 获取更新后的球拍位置
   */
  libsnark::pb_variable<Fr> ret() const {
    return paddle_min_gadget_->ret();
  }

 private:
  libsnark::pb_variable<Fr> const& paddle_x_;
  libsnark::linear_combination<Fr> const& action_;
  
  // paddle_expected 作为线性组合
  libsnark::linear_combination<Fr> paddle_expected_lc_;
  
  std::unique_ptr<circuit::onehot_gadget> action_onehot_;
  std::unique_ptr<circuit::max_gadget> paddle_max_gadget_;
  std::unique_ptr<circuit::min_gadget> paddle_min_gadget_;
};

}  // namespace circuit::pong
