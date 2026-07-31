#pragma once

#include "circuit/func.h"
#include "circuit/pong/env/paddle_update_gadget.h"
#include "circuit/pong/env/ball_update_gadget.h"
#include "circuit/pong/env/paddle_collision_gadget.h"
#include "circuit/pong/env/score_update_gadget.h"
#include "circuit/basic/select_gadget.h"

/**
 * Pong Environment Gadget - R1CS友好的状态转移
 *
 * 实现与Python pong.py中transition_logic_r1cs一致的状态转移逻辑:
 *   1. 检查 terminal 状态：如果已经是 terminal，状态保持不变
 *   2. 更新球拍位置 (根据动作左右移动)
 *   3. 更新球的位置 (位置 += 速度)
 *   4. 左右边界反弹
 *   5. 球拍碰撞检测与响应 (PaddleCollisionGadget 统一处理上下球拍)
 *   6. 得分检测
 *   7. 游戏结束检测
 *
 * 状态向量 (9维) - 所有值都是整数:
 *   [0] ball_x      - 球的X位置 (0-83)
 *   [1] ball_y      - 球的Y位置 (0-83)
 *   [2] ball_vx     - 球的X速度 (-2到2)
 *   [3] ball_vy     - 球的Y速度 (-2到2)
 *   [4] paddle1_x   - 玩家1球拍X位置 (上方, 0-64)
 *   [5] paddle2_x   - 玩家2球拍X位置 (下方, 0-64)
 *   [6] score1      - 玩家1分数 (0-3)
 *   [7] score2      - 玩家2分数 (0-3)
 *   [8] terminal    - 游戏是否结束 (0或1)
 *
 * 动作编码:
 *   action1: 玩家1动作 (DQN输出, 0=不动, 1=左, 2=右) - 不需要check
 *   action2: 玩家2动作 (AI输出, 0=不动, 1=左, 2=右) - 需要check
 *
 * 注意: 所有状态值直接使用整数，不需要定点数表示。
 *       使用 basic 目录下的 gadget (整数版本)。
 */
namespace circuit::pong {

class EnvGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr int STATE_DIM = 9;

  // 游戏常量 (与Python pong.py一致)
  static constexpr int SCREEN_WIDTH = 84;
  static constexpr int SCREEN_HEIGHT = 84;
  static constexpr int BALL_RADIUS = 3;
  static constexpr int BALL_SPEED = 2;
  static constexpr int PADDLE_WIDTH = 20;
  static constexpr int PADDLE_HEIGHT = 3;
  static constexpr int PADDLE_SPEED = 3;
  static constexpr int PADDLE1_Y = 5;    // 上方球拍Y位置
  static constexpr int PADDLE2_Y = 76;   // 下方球拍Y位置 (84 - 3 - 5)
  static constexpr int WINNING_SCORE = 3;  // 获胜分数

  // 二进制位数，用于 range check
  static constexpr size_t POS_BITS = 7;   // 位置值位数
  static constexpr size_t VEL_BITS = 3;   // 速度值位数

  /**
   * 构造函数
   */
  EnvGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_variable_array<Fr> const& in_state,
            libsnark::linear_combination<Fr> const& action1,
            libsnark::pb_variable<Fr> const& action2,
            libsnark::pb_variable<Fr> const& random_vx,
            libsnark::pb_variable<Fr> const& random_dir,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_ptr_(&in_state),
        action1_lc_ptr_(&action1),
        action2_ptr_(&action2),
        random_vx_ptr_(&random_vx),
        random_dir_ptr_(&random_dir) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 赋值
   */
  void AssignFromExternal() {
    GenerateWitness();
  }

  /**
   * 获取输出状态变量数组
   */
  libsnark::pb_variable_array<Fr> out_state_vars() const {
    libsnark::pb_variable_array<Fr> result;
    result.emplace_back(select_ball_x_->ret());       // out_state[0]: ball_x
    result.emplace_back(select_ball_y_->ret());       // out_state[1]: ball_y
    result.emplace_back(select_ball_vx_->ret());      // out_state[2]: ball_vx
    result.emplace_back(select_ball_vy_->ret());      // out_state[3]: ball_vy
    result.emplace_back(select_paddle1_x_->ret());    // out_state[4]: paddle1_x
    result.emplace_back(select_paddle2_x_->ret());    // out_state[5]: paddle2_x
    result.emplace_back(select_score1_->ret());       // out_state[6]: score1
    result.emplace_back(select_score2_->ret());       // out_state[7]: score2
    result.emplace_back(out_terminal_);               // out_state[8]: terminal
    return result;
  }
  
 private:
  // 外部变量指针
  libsnark::pb_variable_array<Fr> const* in_state_ptr_;
  libsnark::linear_combination<Fr> const* action1_lc_ptr_;
  libsnark::pb_variable<Fr> const* action2_ptr_;
  libsnark::pb_variable<Fr> const* random_vx_ptr_;
  libsnark::pb_variable<Fr> const* random_dir_ptr_;

  // 输出变量 (直接使用 select_gadget 的返回值)
  // 不需要额外的输出变量，避免不必要的约束
  libsnark::pb_variable<Fr> out_terminal_;
  
  // 中间变量
  libsnark::pb_variable<Fr> new_terminal_var_;  // 用于存储 score_update 的 terminal 输出

  // 子电路
  std::unique_ptr<PaddleUpdateGadget> paddle1_update_gadget_;
  std::unique_ptr<PaddleUpdateGadget> paddle2_update_gadget_;
  std::unique_ptr<BallUpdateGadget> ball_update_gadget_;
  std::unique_ptr<PaddleCollisionGadget> paddle_collision_gadget_;
  std::unique_ptr<ScoreUpdateGadget> score_update_gadget_;
  
  // terminal 状态选择 gadget
  std::unique_ptr<circuit::select_gadget> select_ball_x_;
  std::unique_ptr<circuit::select_gadget> select_ball_y_;
  std::unique_ptr<circuit::select_gadget> select_ball_vx_;
  std::unique_ptr<circuit::select_gadget> select_ball_vy_;
  std::unique_ptr<circuit::select_gadget> select_paddle1_x_;
  std::unique_ptr<circuit::select_gadget> select_paddle2_x_;
  std::unique_ptr<circuit::select_gadget> select_score1_;
  std::unique_ptr<circuit::select_gadget> select_score2_;

  libsnark::pb_variable_array<Fr> const& get_in_state() const {
    return *in_state_ptr_;
  }

  libsnark::linear_combination<Fr> const& get_action1() const {
    return *action1_lc_ptr_;
  }

  libsnark::pb_variable<Fr> const& get_action2() const {
    return *action2_ptr_;
  }

  libsnark::pb_variable<Fr> const& get_random_vx() const {
    return *random_vx_ptr_;
  }

  libsnark::pb_variable<Fr> const& get_random_dir() const {
    return *random_dir_ptr_;
  }

  void AllocateVariables() {
    out_terminal_.allocate(this->pb, FMT(this->annotation_prefix, " out_terminal"));
    new_terminal_var_.allocate(this->pb, FMT(this->annotation_prefix, " new_terminal_var"));
  }

  void GenerateConstraints() {
    auto const& in_state = get_in_state();
    auto const& action1 = get_action1();
    auto const& action2 = get_action2();
    auto const& random_vx = get_random_vx();

    // ========== 1. 更新球拍位置 ==========
    paddle1_update_gadget_.reset(new PaddleUpdateGadget(
        this->pb, in_state[4], action1, 
        FMT(this->annotation_prefix, " paddle1_update")));
    
    paddle2_update_gadget_.reset(new PaddleUpdateGadget(
        this->pb, in_state[5], action2, 
        FMT(this->annotation_prefix, " paddle2_update")));
    
    // ========== 2. 更新球位置 + 左右边界反弹 ==========
    ball_update_gadget_.reset(new BallUpdateGadget(
        this->pb, in_state[0], in_state[2], in_state[1], in_state[3],
        FMT(this->annotation_prefix, " ball_update")));
    
    // ========== 3. 球拍碰撞检测与响应 ==========
    paddle_collision_gadget_.reset(new PaddleCollisionGadget(
        this->pb,
        ball_update_gadget_->ret_ball_x(),   // ball_x (位置更新+边界反弹后)
        ball_update_gadget_->ret_ball_y(),   // ball_y (位置更新后)
        ball_update_gadget_->ret_ball_vx(),  // ball_vx (边界反弹后)
        in_state[3],                          // ball_vy (原始值，Y速度不受边界反弹影响)
        paddle1_update_gadget_->ret(),        // paddle1_x (更新后)
        paddle2_update_gadget_->ret(),        // paddle2_x (更新后)
        FMT(this->annotation_prefix, " paddle_collision")));
    
    // ========== 4. 得分检测 ==========
    score_update_gadget_.reset(new ScoreUpdateGadget(
        this->pb, 
        ball_update_gadget_->ret_ball_x(),        // ball_x (边界反弹后)
        paddle_collision_gadget_->ret_ball_y(),   // ball_y (碰撞后)
        paddle_collision_gadget_->ret_ball_vx(),  // ball_vx (碰撞后)
        paddle_collision_gadget_->ret_ball_vy(),  // ball_vy (碰撞后)
        in_state[6],  // score1
        in_state[7],  // score2
        random_vx,    // random_vx (方向指示, -1 或 1)
        FMT(this->annotation_prefix, " score_update")));
    
    // ========== 5. Terminal 状态选择 ==========
    // 如果 in_state[8] (terminal) 为 1，则输出状态保持不变
    // 否则输出状态为计算结果
    
    // terminal 条件: in_state[8] 作为选择条件
    libsnark::linear_combination<Fr> is_terminal = in_state[8];
    
    // 为每个状态变量创建选择 gadget
    // select(cond, if_true, if_false) = cond * if_true + (1 - cond) * if_false
    // 如果 terminal=1，输出 = in_state (保持不变)
    // 如果 terminal=0，输出 = 计算结果
    // 直接使用 select_gadget 的返回值作为输出，避免额外的约束
    
    select_ball_x_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[0], score_update_gadget_->ret_ball_x(),
        FMT(this->annotation_prefix, " select_ball_x")));
    
    select_ball_y_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[1], score_update_gadget_->ret_ball_y(),
        FMT(this->annotation_prefix, " select_ball_y")));
    
    select_ball_vx_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[2], score_update_gadget_->ret_ball_vx(),
        FMT(this->annotation_prefix, " select_ball_vx")));
    
    select_ball_vy_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[3], score_update_gadget_->ret_ball_vy(),
        FMT(this->annotation_prefix, " select_ball_vy")));
    
    select_paddle1_x_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[4], paddle1_update_gadget_->ret(),
        FMT(this->annotation_prefix, " select_paddle1_x")));
    
    select_paddle2_x_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[5], paddle2_update_gadget_->ret(),
        FMT(this->annotation_prefix, " select_paddle2_x")));
    
    select_score1_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[6], score_update_gadget_->ret_score1(),
        FMT(this->annotation_prefix, " select_score1")));
    
    select_score2_.reset(new circuit::select_gadget(
        this->pb, is_terminal, in_state[7], score_update_gadget_->ret_score2(),
        FMT(this->annotation_prefix, " select_score2")));
    
    // terminal 输出: 如果已经是 terminal，保持 1；否则使用计算结果
    // 首先将 score_update_gadget 的 terminal 输出存储到变量中
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, score_update_gadget_->ret_terminal(), new_terminal_var_),
        FMT(this->annotation_prefix, " new_terminal_var_assign"));
    
    // out_terminal = is_terminal OR new_terminal = is_terminal + new_terminal - is_terminal * new_terminal
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(is_terminal, new_terminal_var_, is_terminal + new_terminal_var_ - out_terminal_),
        FMT(this->annotation_prefix, " out_terminal_final"));
  }

  void GenerateWitness() {
    auto const& in_state = get_in_state();
    int64_t ball_x = this->pb.val(in_state[0]).getInt64();
    int64_t ball_y = this->pb.val(in_state[1]).getInt64();
    int64_t ball_vx = this->pb.val(in_state[2]).getInt64();
    int64_t ball_vy = this->pb.val(in_state[3]).getInt64();
    int64_t paddle1_x = this->pb.val(in_state[4]).getInt64();
    int64_t paddle2_x = this->pb.val(in_state[5]).getInt64();
    int64_t score1 = this->pb.val(in_state[6]).getInt64();
    int64_t score2 = this->pb.val(in_state[7]).getInt64();
    int64_t terminal = this->pb.val(in_state[8]).getInt64();

    // action1 是 linear_combination，需要用 evaluate 获取值
    int act1 = get_action1().evaluate(this->pb.full_variable_assignment_ref()).getInt64();
    int act2 = this->pb.val(get_action2()).getInt64();

    int random_vx_val = this->pb.val(get_random_vx()).getInt64();

    // 1. 生成球拍更新 witness
    paddle1_update_gadget_->generate_r1cs_witness(paddle1_x, act1);
    paddle2_update_gadget_->generate_r1cs_witness(paddle2_x, act2);

    // 2. 生成球位置更新 witness
    ball_update_gadget_->generate_r1cs_witness(ball_x, ball_vx, ball_y, ball_vy);

    // 获取更新后的值
    int64_t paddle1_x_after = this->pb.val(paddle1_update_gadget_->ret()).getInt64();
    int64_t paddle2_x_after = this->pb.val(paddle2_update_gadget_->ret()).getInt64();
    int64_t ball_x_after = this->pb.val(ball_update_gadget_->ret_ball_x()).getInt64();
    int64_t ball_y_after = this->pb.val(ball_update_gadget_->ret_ball_y()).getInt64();
    int64_t ball_vx_after = this->pb.val(ball_update_gadget_->ret_ball_vx()).getInt64();

    // 3. 生成球拍碰撞检测与响应 witness
    paddle_collision_gadget_->generate_r1cs_witness(
        ball_x_after, ball_y_after, ball_vx_after, ball_vy,
        paddle1_x_after, paddle2_x_after);

    // 获取碰撞后的值
    int64_t ball_x_collision = this->pb.val(ball_update_gadget_->ret_ball_x()).getInt64();
    int64_t ball_y_collision = this->pb.val(paddle_collision_gadget_->ret_ball_y()).getInt64();
    int64_t ball_vx_collision = this->pb.val(paddle_collision_gadget_->ret_ball_vx()).getInt64();
    int64_t ball_vy_collision = this->pb.val(paddle_collision_gadget_->ret_ball_vy()).getInt64();

    // 4. 生成得分更新 witness
    score_update_gadget_->generate_r1cs_witness(
        ball_x_collision, ball_y_collision, ball_vx_collision, ball_vy_collision,
        score1, score2, random_vx_val);
    
    // 5. 生成 terminal 状态选择 witness
    // 如果已经是 terminal，状态保持不变
    select_ball_x_->generate_r1cs_witness();
    select_ball_y_->generate_r1cs_witness();
    select_ball_vx_->generate_r1cs_witness();
    select_ball_vy_->generate_r1cs_witness();
    select_paddle1_x_->generate_r1cs_witness();
    select_paddle2_x_->generate_r1cs_witness();
    select_score1_->generate_r1cs_witness();
    select_score2_->generate_r1cs_witness();
    
    // 计算 terminal 输出: terminal OR new_terminal
    int64_t new_terminal = this->pb.val(score_update_gadget_->ret_terminal()).getInt64();
    this->pb.val(new_terminal_var_) = Fr(new_terminal);
    int64_t out_terminal_val = terminal | new_terminal;
    this->pb.val(out_terminal_) = Fr(out_terminal_val);
  }
};

}  // namespace circuit::pong
