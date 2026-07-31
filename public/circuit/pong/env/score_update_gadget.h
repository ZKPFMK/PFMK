#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/select_gadget.h"
#include "circuit/basic/zero_gadget.h"

/**
 * Score Update Gadget - 得分更新电路
 *
 * 功能：
 *   1. 检测球是否出界（得分）
 *   2. 更新分数
 *   3. 重置球的位置和速度（如果得分）
 *   4. 检测游戏是否结束
 *
 * 输入：
 *   - ball_x: 球的X位置 (碰撞后)
 *   - ball_y: 球的Y位置 (碰撞后)
 *   - ball_vx: 球的X速度 (碰撞后)
 *   - ball_vy: 球的Y速度 (碰撞后)
 *   - score1: 玩家1分数
 *   - score2: 玩家2分数
 *   - random_vx: 重置时的随机X速度方向 (-1 或 1)
 *
 * 输出：
 *   - ball_x_out: 更新后的球X位置
 *   - ball_y_out: 更新后的球Y位置
 *   - ball_vx_out: 更新后的球X速度
 *   - ball_vy_out: 更新后的球Y速度
 *   - score1_out: 更新后的玩家1分数
 *   - score2_out: 更新后的玩家2分数
 *   - terminal: 游戏是否结束
 *
 * 注意: random_vx 是方向指示 (-1 或 1)，实际速度为 random_vx * BALL_SPEED
 *       与 Python transition_logic_r1cs 中 random_vx * 2 一致
 */
namespace circuit::pong {

class ScoreUpdateGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int SCREEN_WIDTH = 84;
  static constexpr int SCREEN_HEIGHT = 84;
  static constexpr int BALL_SPEED = 2;
  static constexpr int WINNING_SCORE = 3;
  static constexpr size_t POS_BITS = 7;

  /**
   * 构造函数
   */
  ScoreUpdateGadget(libsnark::protoboard<Fr>& pb,
                     libsnark::pb_variable<Fr> const& ball_x,
                     libsnark::pb_variable<Fr> const& ball_y,
                     libsnark::pb_variable<Fr> const& ball_vx,
                     libsnark::pb_variable<Fr> const& ball_vy,
                     libsnark::pb_variable<Fr> const& score1,
                     libsnark::pb_variable<Fr> const& score2,
                     libsnark::pb_variable<Fr> const& random_vx,
                     const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        ball_x_(ball_x),
        ball_y_(ball_y),
        ball_vx_(ball_vx),
        ball_vy_(ball_vy),
        score1_(score1),
        score2_(score2),
        random_vx_(random_vx) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 生成witness
   */
  void generate_r1cs_witness(int64_t ball_x_val, int64_t ball_y_val,
                              int64_t ball_vx_val, int64_t ball_vy_val,
                              int64_t score1_val, int64_t score2_val, int64_t random_vx_val) {
    // 得分检测
    bool is_score_player2 = (ball_y_val < 0);
    bool is_score_player1 = (ball_y_val >= SCREEN_HEIGHT);
    bool is_score = is_score_player1 || is_score_player2;
    
    // 生成 abs_ball_y_ 和 ball_y_minus_height_ witness
    abs_ball_y_->generate_r1cs_witness();
    ball_y_minus_height_->generate_r1cs_witness();
    
    // 计算最终输出
    int64_t ball_x_final = is_score ? (SCREEN_WIDTH / 2) : ball_x_val;
    int64_t ball_y_final = is_score ? (SCREEN_HEIGHT / 2) : ball_y_val;
    int64_t ball_vx_final = is_score ? (random_vx_val * BALL_SPEED) : ball_vx_val;
    int64_t ball_vy_final = is_score ? (is_score_player2 ? BALL_SPEED : -BALL_SPEED) : ball_vy_val;
    int64_t score1_final = score1_val + (is_score_player1 ? 1 : 0);
    int64_t score2_final = score2_val + (is_score_player2 ? 1 : 0);
    bool terminal = (score1_final >= WINNING_SCORE) || (score2_final >= WINNING_SCORE);
    
    // 生成 select_gadget witness
    ball_x_out_select_->generate_r1cs_witness();
    ball_y_out_select_->generate_r1cs_witness();
    ball_vx_out_select_->generate_r1cs_witness();
    ball_vy_out_player2_->generate_r1cs_witness();
    ball_vy_out_player1_->generate_r1cs_witness();
    
    // 设置输出变量
    this->pb.val(ball_x_out_) = Fr(ball_x_final);
    this->pb.val(ball_y_out_) = Fr(ball_y_final);
    this->pb.val(ball_vx_out_) = Fr(ball_vx_final);
    this->pb.val(ball_vy_out_) = Fr(ball_vy_final);
    this->pb.val(score1_out_) = Fr(score1_final);
    this->pb.val(score2_out_) = Fr(score2_final);
    this->pb.val(terminal_out_) = Fr(terminal ? 1 : 0);
    
    // 生成 zero_gadget witness (terminal 检测)
    is_score1_winning_->generate_r1cs_witness();
    is_score2_winning_->generate_r1cs_witness();
  }

  /**
   * 获取输出变量
   */
  libsnark::pb_variable<Fr> ret_ball_x() const { return ball_x_out_; }
  libsnark::pb_variable<Fr> ret_ball_y() const { return ball_y_out_; }
  libsnark::pb_variable<Fr> ret_ball_vx() const { return ball_vx_out_; }
  libsnark::pb_variable<Fr> ret_ball_vy() const { return ball_vy_out_; }
  libsnark::pb_variable<Fr> ret_score1() const { return score1_out_; }
  libsnark::pb_variable<Fr> ret_score2() const { return score2_out_; }
  libsnark::pb_variable<Fr> ret_terminal() const { return terminal_out_; }

 private:
  // 输入变量
  libsnark::pb_variable<Fr> const& ball_x_;
  libsnark::pb_variable<Fr> const& ball_y_;
  libsnark::pb_variable<Fr> const& ball_vx_;
  libsnark::pb_variable<Fr> const& ball_vy_;
  libsnark::pb_variable<Fr> const& score1_;
  libsnark::pb_variable<Fr> const& score2_;
  libsnark::pb_variable<Fr> const& random_vx_;
  
  // 输出变量
  libsnark::pb_variable<Fr> ball_x_out_;
  libsnark::pb_variable<Fr> ball_y_out_;
  libsnark::pb_variable<Fr> ball_vx_out_;
  libsnark::pb_variable<Fr> ball_vy_out_;
  libsnark::pb_variable<Fr> score1_out_;
  libsnark::pb_variable<Fr> score2_out_;
  libsnark::pb_variable<Fr> terminal_out_;
  
  // 子gadget
  std::unique_ptr<circuit::abs_gadget> abs_ball_y_;
  std::unique_ptr<circuit::abs_gadget> ball_y_minus_height_;
  std::unique_ptr<circuit::select_gadget> ball_x_out_select_;
  std::unique_ptr<circuit::select_gadget> ball_y_out_select_;
  std::unique_ptr<circuit::select_gadget> ball_vx_out_select_;
  std::unique_ptr<circuit::select_gadget> ball_vy_out_player2_;
  std::unique_ptr<circuit::select_gadget> ball_vy_out_player1_;
  std::unique_ptr<circuit::zero_gadget> is_score1_winning_;
  std::unique_ptr<circuit::zero_gadget> is_score2_winning_;
  
  void AllocateVariables() {
    ball_x_out_.allocate(this->pb, FMT(this->annotation_prefix, " ball_x_out"));
    ball_y_out_.allocate(this->pb, FMT(this->annotation_prefix, " ball_y_out"));
    ball_vx_out_.allocate(this->pb, FMT(this->annotation_prefix, " ball_vx_out"));
    ball_vy_out_.allocate(this->pb, FMT(this->annotation_prefix, " ball_vy_out"));
    score1_out_.allocate(this->pb, FMT(this->annotation_prefix, " score1_out"));
    score2_out_.allocate(this->pb, FMT(this->annotation_prefix, " score2_out"));
    terminal_out_.allocate(this->pb, FMT(this->annotation_prefix, " terminal_out"));
  }
  
  void GenerateConstraints() {
    // 创建 abs_ball_y_ (用于得分检测)
    abs_ball_y_.reset(new circuit::abs_gadget(
        this->pb, ball_y_, POS_BITS, FMT(this->annotation_prefix, " abs_ball_y")));
    
    // 创建 ball_y_minus_height_ (用于得分检测)
    libsnark::linear_combination<Fr> ball_y_minus_height_lc = ball_y_ - Fr(SCREEN_HEIGHT);
    ball_y_minus_height_.reset(new circuit::abs_gadget(
        this->pb, ball_y_minus_height_lc, POS_BITS, 
        FMT(this->annotation_prefix, " ball_y_minus_height")));
    
    // 得分检测
    // is_score_player2 = (ball_y_ < 0) = abs_ball_y_->ret_sign()
    // is_score_player1 = (ball_y_ >= SCREEN_HEIGHT) = 1 - ball_y_minus_height_->ret_sign()
    libsnark::linear_combination<Fr> is_score_player2 = abs_ball_y_->ret_sign();
    libsnark::linear_combination<Fr> is_score_player1 = Fr(1);
    is_score_player1 = is_score_player1 - ball_y_minus_height_->ret_sign();
    libsnark::linear_combination<Fr> is_score = is_score_player1 + is_score_player2;
    
    // score1_out = score1 + is_score_player1
    libsnark::linear_combination<Fr> score1_out_lc = score1_ + is_score_player1;
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, score1_out_lc, score1_out_),
        FMT(this->annotation_prefix, " score1_out_calc"));
    
    // score2_out = score2 + is_score_player2
    libsnark::linear_combination<Fr> score2_out_lc = score2_ + is_score_player2;
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, score2_out_lc, score2_out_),
        FMT(this->annotation_prefix, " score2_out_calc"));
    
    // ball_x_out: 如果 is_score，ball_x = SCREEN_WIDTH / 2，否则 ball_x = ball_x_
    ball_x_out_select_.reset(new circuit::select_gadget(
        this->pb, is_score, Fr(SCREEN_WIDTH / 2), ball_x_,
        FMT(this->annotation_prefix, " ball_x_out_select")));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_x_out_select_->ret(), ball_x_out_),
        FMT(this->annotation_prefix, " ball_x_out_final"));
    
    // ball_y_out: 如果 is_score，ball_y = SCREEN_HEIGHT / 2，否则 ball_y = ball_y_
    ball_y_out_select_.reset(new circuit::select_gadget(
        this->pb, is_score, Fr(SCREEN_HEIGHT / 2), ball_y_,
        FMT(this->annotation_prefix, " ball_y_out_select")));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_y_out_select_->ret(), ball_y_out_),
        FMT(this->annotation_prefix, " ball_y_out_final"));
    
    // ball_vx_out: 如果 is_score，ball_vx = random_vx * BALL_SPEED，否则 ball_vx = ball_vx_
    // 与 Python 的 random_vx * 2 一致 (BALL_SPEED = 2)
    libsnark::linear_combination<Fr> random_vx_scaled = BALL_SPEED * libsnark::linear_combination<Fr>(random_vx_);
    ball_vx_out_select_.reset(new circuit::select_gadget(
        this->pb, is_score, random_vx_scaled, ball_vx_,
        FMT(this->annotation_prefix, " ball_vx_out_select")));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_vx_out_select_->ret(), ball_vx_out_),
        FMT(this->annotation_prefix, " ball_vx_out_final"));
    
    // ball_vy_out: 如果 is_score_player2，ball_vy = BALL_SPEED，如果 is_score_player1，ball_vy = -BALL_SPEED
    // 否则 ball_vy = ball_vy_
    ball_vy_out_player2_.reset(new circuit::select_gadget(
        this->pb, is_score_player2, Fr(BALL_SPEED), ball_vy_,
        FMT(this->annotation_prefix, " ball_vy_out_player2")));
    ball_vy_out_player1_.reset(new circuit::select_gadget(
        this->pb, is_score_player1, Fr(-BALL_SPEED), ball_vy_out_player2_->ret(),
        FMT(this->annotation_prefix, " ball_vy_out_player1")));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, ball_vy_out_player1_->ret(), ball_vy_out_),
        FMT(this->annotation_prefix, " ball_vy_out_final"));
    
    // terminal = (score1_out_ >= WINNING_SCORE) || (score2_out_ >= WINNING_SCORE)
    // 使用 zero_gadget 判断 score - WINNING_SCORE == 0
    // 由于分数只能递增1，score == WINNING_SCORE 等价于 score >= WINNING_SCORE
    is_score1_winning_.reset(new circuit::zero_gadget(
        this->pb, score1_out_ - Fr(WINNING_SCORE), 
        FMT(this->annotation_prefix, " is_score1_winning")));
    
    is_score2_winning_.reset(new circuit::zero_gadget(
        this->pb, score2_out_ - Fr(WINNING_SCORE), 
        FMT(this->annotation_prefix, " is_score2_winning")));
    
    // terminal = is_score1_winning || is_score2_winning
    // 使用 a OR b = a + b - a*b
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(is_score1_winning_->ret(), is_score2_winning_->ret(), 
                                      is_score1_winning_->ret() + is_score2_winning_->ret() - terminal_out_),
        FMT(this->annotation_prefix, " terminal_or"));
  }
};

}  // namespace circuit::pong
