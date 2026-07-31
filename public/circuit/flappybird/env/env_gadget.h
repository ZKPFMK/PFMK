#pragma once

#include "circuit/func.h"
#include "circuit/basic/select_gadget.h"
#include "circuit/flappybird/env/velocity_update_gadget.h"
#include "circuit/flappybird/env/bird_update_gadget.h"
#include "circuit/flappybird/env/pipe_update_gadget.h"
#include "circuit/flappybird/env/collision_gadget.h"
#include "circuit/flappybird/env/score_update_gadget.h"

/**
 * Flappy Bird Environment Gadget
 *
 * 实现与 Python transition_logic_r1cs 完全一致的状态转移逻辑。
 *
 * 状态向量 (8维) - 所有值都是整数:
 *   [0] bird_y       -- 鸟的Y位置 (0~404)
 *   [1] bird_vy      -- 鸟的垂直速度 (-9~10)
 *   [2] pipe1_x      -- 第一个管道的X位置 (-56~298)
 *   [3] pipe1_gap_y  -- 第一个管道的间隙Y位置
 *   [4] pipe2_x      -- 第二个管道的X位置
 *   [5] pipe2_gap_y  -- 第二个管道的间隙Y位置
 *   [6] score        -- 分数
 *   [7] terminal     -- 游戏是否结束 (0=进行中, 1=结束)
 *
 * 动作编码:
 *   action: 0=不跳, 1=跳 (单个变量或 linear_combination)
 *
 * 外部输入:
 *   next_gap_y: 下一个管道的间隙Y (确定性，由外部提供)
 *
 * 状态转移逻辑 (与 Python transition_logic_r1cs 一致):
 *   Step 1: 处理动作 -> bird_vy_after_action
 *   Step 4: 更新速度 (重力 + clamp) -> bird_vy
 *   Step 4: 更新位置 (bird_y + bird_vy, clamp >= 0) -> bird_y, bird_vy_final
 *   Step 5: 更新管道位置 (pipe_x += -4)
 *   Step 6: 管道管理 (回收离开屏幕的管道)
 *   Step 7: 碰撞检测 (地面 + 管道)
 *   Step 8: 分数更新 (得分区域检测)
 *   Step 9: 确定输出 (reward)
 *   Step 10: 如果 terminal=1，返回重置状态；否则返回新状态
 *
 * 注意:
 *   - 所有值都是整数，不使用定点数
 *   - 碰撞检测使用更新后的 bird_y 和更新后的管道位置
 *   - 分数检测使用更新后的管道位置
 *
 * 设计参考: pong/env/env_gadget.h
 */
namespace circuit::flappybird {

class EnvGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr int STATE_DIM = 8;

  // 游戏常量 (与 Python 一致)
  static constexpr int SCREEN_WIDTH = 288;
  static constexpr int SCREEN_HEIGHT = 512;
  static constexpr int BASE_Y = 404;
  static constexpr int BIRD_X = 57;
  static constexpr int BIRD_WIDTH = 34;
  static constexpr int BIRD_HEIGHT = 24;
  static constexpr int PIPE_WIDTH = 52;
  static constexpr int PIPE_GAP_SIZE = 100;

  // 重置状态常量
  static constexpr int RESET_BIRD_Y = (SCREEN_HEIGHT - BIRD_HEIGHT) / 2;  // 244
  static constexpr int RESET_PIPE1_X = SCREEN_WIDTH;                       // 288
  static constexpr int RESET_PIPE2_X = SCREEN_WIDTH * 3 / 2;              // 432

  /**
   * 构造函数
   * @param in_state 输入状态 [8维]
   * @param action 动作 (0 或 1)
   * @param next_gap_y 下一个管道间隙Y (外部输入)
   */
  EnvGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_variable_array<Fr> const& in_state,
            libsnark::linear_combination<Fr> const& action,
            libsnark::pb_variable<Fr> const& next_gap_y,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_(in_state),
        action_(action),
        next_gap_y_(next_gap_y) {
    GenerateConstraints();
  }

  /**
   * 赋值并生成witness
   */
  void generate_r1cs_witness() {
    int64_t bird_y = this->pb.val(in_state_[0]).getInt64();
    int64_t bird_vy = this->pb.val(in_state_[1]).getInt64();
    int64_t pipe1_x = this->pb.val(in_state_[2]).getInt64();
    int64_t pipe1_gap_y = this->pb.val(in_state_[3]).getInt64();
    int64_t pipe2_x = this->pb.val(in_state_[4]).getInt64();
    int64_t pipe2_gap_y = this->pb.val(in_state_[5]).getInt64();
    int64_t score = this->pb.val(in_state_[6]).getInt64();

    int action_val = action_.evaluate(
        this->pb.full_variable_assignment_ref()).getInt64();
    int64_t next_gap_y_val = this->pb.val(next_gap_y_).getInt64();

    // 1. 速度更新
    velocity_gadget_->generate_r1cs_witness(bird_vy, action_val);

    // 2. 位置更新
    bird_gadget_->generate_r1cs_witness(bird_y, this->pb.val(velocity_gadget_->ret()).getInt64());

    // 3. 管道更新
    pipe_gadget_->generate_r1cs_witness(pipe1_x, pipe1_gap_y,
                                         pipe2_x, pipe2_gap_y,
                                         next_gap_y_val);

    // 4. 碰撞检测
    collision_gadget_->generate_r1cs_witness();

    // 5. 分数更新
    int64_t new_pipe1_x = this->pb.val(pipe_gadget_->ret_pipe1_x()).getInt64();
    int64_t new_pipe2_x = this->pb.val(pipe_gadget_->ret_pipe2_x()).getInt64();
    score_gadget_->generate_r1cs_witness(new_pipe1_x, new_pipe2_x, score);

    // 6. Collision 选择 (碰撞时重置，否则正常转移)
    select_bird_y_->generate_r1cs_witness();
    select_bird_vy_->generate_r1cs_witness();
    select_pipe1_x_->generate_r1cs_witness();
    select_pipe1_gap_y_->generate_r1cs_witness();
    select_pipe2_x_->generate_r1cs_witness();
    select_pipe2_gap_y_->generate_r1cs_witness();
    select_score_->generate_r1cs_witness();

    // 7. Already-terminal 选择 (如果输入已是 terminal，保持输入状态不变)
    freeze_bird_y_->generate_r1cs_witness();
    freeze_bird_vy_->generate_r1cs_witness();
    freeze_pipe1_x_->generate_r1cs_witness();
    freeze_pipe1_gap_y_->generate_r1cs_witness();
    freeze_pipe2_x_->generate_r1cs_witness();
    freeze_pipe2_gap_y_->generate_r1cs_witness();
    freeze_score_->generate_r1cs_witness();
    freeze_terminal_->generate_r1cs_witness();
  }

  /**
   * 获取输出状态变量数组
   */
  libsnark::pb_variable_array<Fr> out_state_vars() const {
    libsnark::pb_variable_array<Fr> result;
    result.emplace_back(freeze_bird_y_->ret());       // out_state[0]: bird_y
    result.emplace_back(freeze_bird_vy_->ret());      // out_state[1]: bird_vy
    result.emplace_back(freeze_pipe1_x_->ret());      // out_state[2]: pipe1_x
    result.emplace_back(freeze_pipe1_gap_y_->ret());  // out_state[3]: pipe1_gap_y
    result.emplace_back(freeze_pipe2_x_->ret());      // out_state[4]: pipe2_x
    result.emplace_back(freeze_pipe2_gap_y_->ret());  // out_state[5]: pipe2_gap_y
    result.emplace_back(freeze_score_->ret());        // out_state[6]: score
    result.emplace_back(freeze_terminal_->ret());     // out_state[7]: terminal
    return result;
  }

  /**
   * Check if a state is terminal by reading state[7].
   * @param state 8-dim state vector, state[7] = terminal flag (0 or 1)
   */
  static bool IsTerminal(std::vector<Fr> const& state) {
    assert(static_cast<int>(state.size()) >= STATE_DIM);
    return state[7].getInt64() != 0;
  }

  /**
   * 获取碰撞结果 (terminal)
   */
  libsnark::pb_variable<Fr> ret_terminal() const {
    return collision_gadget_->ret();
  }

 private:
  // 输入变量
  libsnark::pb_variable_array<Fr> const& in_state_;
  libsnark::linear_combination<Fr> action_;
  libsnark::pb_variable<Fr> const& next_gap_y_;

  // 子 gadget
  std::unique_ptr<VelocityUpdateGadget> velocity_gadget_;
  std::unique_ptr<BirdUpdateGadget> bird_gadget_;
  std::unique_ptr<PipeUpdateGadget> pipe_gadget_;
  std::unique_ptr<CollisionGadget> collision_gadget_;
  std::unique_ptr<ScoreUpdateGadget> score_gadget_;

  // 碰撞选择 gadget (如果碰撞，输出重置状态；否则输出正常转移状态)
  std::unique_ptr<circuit::select_gadget> select_bird_y_;
  std::unique_ptr<circuit::select_gadget> select_bird_vy_;
  std::unique_ptr<circuit::select_gadget> select_pipe1_x_;
  std::unique_ptr<circuit::select_gadget> select_pipe1_gap_y_;
  std::unique_ptr<circuit::select_gadget> select_pipe2_x_;
  std::unique_ptr<circuit::select_gadget> select_pipe2_gap_y_;
  std::unique_ptr<circuit::select_gadget> select_score_;

  // 冻结选择 gadget (如果输入已是 terminal，保持输入状态不变)
  // in_state[7]==1 => 输出 in_state[i]; in_state[7]==0 => 输出 select_*->ret()
  std::unique_ptr<circuit::select_gadget> freeze_bird_y_;
  std::unique_ptr<circuit::select_gadget> freeze_bird_vy_;
  std::unique_ptr<circuit::select_gadget> freeze_pipe1_x_;
  std::unique_ptr<circuit::select_gadget> freeze_pipe1_gap_y_;
  std::unique_ptr<circuit::select_gadget> freeze_pipe2_x_;
  std::unique_ptr<circuit::select_gadget> freeze_pipe2_gap_y_;
  std::unique_ptr<circuit::select_gadget> freeze_score_;
  std::unique_ptr<circuit::select_gadget> freeze_terminal_;

  void GenerateConstraints() {
    // ========== 1. 速度更新 (Step 1 + Step 4 速度部分) ==========
    velocity_gadget_.reset(new VelocityUpdateGadget(
        this->pb, in_state_[1], action_,
        FMT(this->annotation_prefix, " velocity_update")));

    // ========== 2. 位置更新 (Step 4 位置部分) ==========
    bird_gadget_.reset(new BirdUpdateGadget(
        this->pb, in_state_[0], velocity_gadget_->ret(),
        FMT(this->annotation_prefix, " bird_update")));

    // ========== 3. 管道更新 (Step 5 + Step 6) ==========
    pipe_gadget_.reset(new PipeUpdateGadget(
        this->pb, in_state_[2], in_state_[3], in_state_[4], in_state_[5],
        next_gap_y_,
        FMT(this->annotation_prefix, " pipe_update")));

    // ========== 4. 碰撞检测 (Step 7) ==========
    collision_gadget_.reset(new CollisionGadget(
        this->pb,
        bird_gadget_->ret_bird_y(),
        pipe_gadget_->ret_pipe1_x(),
        pipe_gadget_->ret_pipe1_gap_y(),
        pipe_gadget_->ret_pipe2_x(),
        pipe_gadget_->ret_pipe2_gap_y(),
        FMT(this->annotation_prefix, " collision")));

    // ========== 5. 分数更新 (Step 8) ==========
    score_gadget_.reset(new ScoreUpdateGadget(
        this->pb,
        pipe_gadget_->ret_pipe1_x(),
        pipe_gadget_->ret_pipe2_x(),
        in_state_[6],
        FMT(this->annotation_prefix, " score_update")));

    // ========== 6. Terminal 状态选择 (Step 10) ==========
    libsnark::linear_combination<Fr> terminal = collision_gadget_->ret();

    select_bird_y_.reset(new circuit::select_gadget(
        this->pb, terminal, Fr(RESET_BIRD_Y), bird_gadget_->ret_bird_y(),
        FMT(this->annotation_prefix, " select_bird_y")));

    select_bird_vy_.reset(new circuit::select_gadget(
        this->pb, terminal, Fr(0), bird_gadget_->ret_bird_vy(),
        FMT(this->annotation_prefix, " select_bird_vy")));

    select_pipe1_x_.reset(new circuit::select_gadget(
        this->pb, terminal, Fr(RESET_PIPE1_X), pipe_gadget_->ret_pipe1_x(),
        FMT(this->annotation_prefix, " select_pipe1_x")));

    select_pipe1_gap_y_.reset(new circuit::select_gadget(
        this->pb, terminal, next_gap_y_, pipe_gadget_->ret_pipe1_gap_y(),
        FMT(this->annotation_prefix, " select_pipe1_gap_y")));

    select_pipe2_x_.reset(new circuit::select_gadget(
        this->pb, terminal, Fr(RESET_PIPE2_X), pipe_gadget_->ret_pipe2_x(),
        FMT(this->annotation_prefix, " select_pipe2_x")));

    select_pipe2_gap_y_.reset(new circuit::select_gadget(
        this->pb, terminal, next_gap_y_, pipe_gadget_->ret_pipe2_gap_y(),
        FMT(this->annotation_prefix, " select_pipe2_gap_y")));

    select_score_.reset(new circuit::select_gadget(
        this->pb, terminal, Fr(0), score_gadget_->ret_score(),
        FMT(this->annotation_prefix, " select_score")));

    // ========== 7. Already-terminal 冻结选择 (Step 0) ==========
    // 如果输入 in_state[7]==1 (已经是 terminal)，输出保持输入状态不变
    // select_gadget: b==1 => x, b==0 => y
    // 这里 b=in_state[7], x=in_state[i] (冻结), y=select_*->ret() (正常转移结果)
    libsnark::linear_combination<Fr> in_terminal = in_state_[7];

    freeze_bird_y_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[0], select_bird_y_->ret(),
        FMT(this->annotation_prefix, " freeze_bird_y")));

    freeze_bird_vy_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[1], select_bird_vy_->ret(),
        FMT(this->annotation_prefix, " freeze_bird_vy")));

    freeze_pipe1_x_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[2], select_pipe1_x_->ret(),
        FMT(this->annotation_prefix, " freeze_pipe1_x")));

    freeze_pipe1_gap_y_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[3], select_pipe1_gap_y_->ret(),
        FMT(this->annotation_prefix, " freeze_pipe1_gap_y")));

    freeze_pipe2_x_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[4], select_pipe2_x_->ret(),
        FMT(this->annotation_prefix, " freeze_pipe2_x")));

    freeze_pipe2_gap_y_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[5], select_pipe2_gap_y_->ret(),
        FMT(this->annotation_prefix, " freeze_pipe2_gap_y")));

    freeze_score_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[6], select_score_->ret(),
        FMT(this->annotation_prefix, " freeze_score")));

    // terminal 输出: 如果已是 terminal，保持 1；否则输出碰撞检测结果
    freeze_terminal_.reset(new circuit::select_gadget(
        this->pb, in_terminal, in_state_[7], collision_gadget_->ret(),
        FMT(this->annotation_prefix, " freeze_terminal")));
  }
};

}  // namespace circuit::flappybird
