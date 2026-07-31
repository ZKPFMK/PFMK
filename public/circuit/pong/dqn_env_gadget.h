#pragma once

#include <chrono>

#include "circuit/func.h"
#include "circuit/pong/render/render_gadget.h"
#include "circuit/pong/dqn/dqn_gadget.h"
#include "circuit/pong/env/env_gadget.h"
#include "circuit/basic/onehot_gadget.h"

namespace circuit::pong {

/**
 * ImagePreprocessGadget - 图片预处理电路
 *
 * 将 84x84 的图片 (0-255) 下采样为 42x42 的图片 (0-1)
 * 使用最近邻下采样 + 归一化
 *
 * 最近邻下采样原理:
 *   scale = source_size / target_size = 84 / 42 = 2
 *   输出像素(i, j) = 输入像素(int(i * scale), int(j * scale)) / 255
 *   即: 输出像素(i, j) = 输入像素(2*i, 2*j) / 255
 *
 * 输出为变量数组，通过约束确保: target_var = source * (2^24 / 255)
 */
class ImagePreprocessGadget : public libsnark::gadget<Fr> {
 public:
  static constexpr int SOURCE_SIZE = 84;
  static constexpr int TARGET_SIZE = 42;
  static constexpr int SCALE = SOURCE_SIZE / TARGET_SIZE;  // 2
  static constexpr int OUTPUT_SIZE = TARGET_SIZE * TARGET_SIZE;  // 1764

  /**
   * 构造函数
   * @param pb protoboard
   * @param source_image 输入图片 (84x84, 值范围 0-255)
   * @param annotation_prefix 注释前缀
   */
  ImagePreprocessGadget(libsnark::protoboard<Fr>& pb,
                        libsnark::pb_variable_array<Fr> const& source_image,
                        const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        source_image_(source_image) {
    // 归一化系数: 2^24 / 255 ≈ 65793 (定点数表示)
    // normalized = pixel * (2^24 / 255) ≈ pixel * 65793
    // 注意: 这是一个近似值，误差约为 0.0003%
    scale_factor_ = (int64_t(1) << 24) / 255;  // 65793
    
    // 分配输出变量
    target_image_.allocate(pb, OUTPUT_SIZE, FMT(annotation_prefix, " target_image"));
    
    // 添加约束: target_image_[tgt_idx] = source_image_[src_idx] * scale_factor
    for (int i = 0; i < TARGET_SIZE; ++i) {
      for (int j = 0; j < TARGET_SIZE; ++j) {
        int src_row = i * SCALE;
        int src_col = j * SCALE;
        int src_idx = src_row * SOURCE_SIZE + src_col;
        int tgt_idx = i * TARGET_SIZE + j;
        pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(source_image_[src_idx], Fr(scale_factor_), target_image_[tgt_idx]),
            FMT(annotation_prefix, " normalize_%d", tgt_idx));
      }
    }
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness() {
    for (int i = 0; i < TARGET_SIZE; ++i) {
      for (int j = 0; j < TARGET_SIZE; ++j) {
        int src_row = i * SCALE;
        int src_col = j * SCALE;
        int src_idx = src_row * SOURCE_SIZE + src_col;
        int tgt_idx = i * TARGET_SIZE + j;
        int64_t src_val = this->pb.val(source_image_[src_idx]).getInt64();
        this->pb.val(target_image_[tgt_idx]) = Fr(src_val * scale_factor_);
      }
    }
  }

  /**
   * 获取输出图片 (作为变量数组)
   */
  libsnark::pb_variable_array<Fr> const& output() const { return target_image_; }

 private:
  libsnark::pb_variable_array<Fr> const& source_image_;
  libsnark::pb_variable_array<Fr> target_image_;  // 输出图片 (变量形式)
  int64_t scale_factor_;
};

/**
 * DqnEnvGadget - DQN-环境组合电路 (带 frame_skip)
 *
 * 实现完整的强化学习步骤:
 * 1. 输入环境状态和前一帧图片
 * 2. 渲染当前状态得到当前图片 (84x84)
 * 3. 预处理当前帧图片 (84x84 下采样到 42x42 + 归一化)
 * 4. DQN 推理得到动作 (输入为前一帧和当前帧的组合)
 * 5. 状态转移得到新状态 (使用 DQN 动作和外部动作，执行 FRAME_SKIP 次)
 * 6. 渲染新状态得到新图片
 * 7. 输出新状态、新图片和 DQN 动作
 *
 * frame_skip 机制:
 *   DQN 选择一个动作后，该动作被执行 FRAME_SKIP 次
 *   每次使用相同的 DQN action 和外部 action，但不同的随机数
 *   如果游戏结束，提前终止 frame_skip 循环
 *
 * 与 Python 实现的对应关系:
 *   for _ in range(frame_skip):
 *       next_image, reward, done = game.next_frame(dqn_action, ai_action)
 *       if done:
 *           break
 *
 * 输入:
 *   - in_state[9]: 输入状态 (ball_x, ball_y, ball_vx, ball_vy, paddle1_x, paddle2_x, score1, score2, terminal)
 *   - prev_image[1764]: 前一帧图片 (42x42, 已归一化, 用于 DQN 输入的第一帧)
 *   - action: 外部动作 (另一个玩家的动作，在 frame_skip 期间保持不变)
 *   - random_vxs: 随机数数组 (FRAME_SKIP 个，用于球的速度变化)
 *   - random_dirs: 随机数数组 (FRAME_SKIP 个，用于球的方向变化)
 *   - DQN 权重
 *
 * 输出:
 *   - out_state[9]: 新状态
 *   - out_image[7056]: 新渲染的图片 (84x84)
 *   - out_image_42[1764]: 输出状态预处理后的图片 (42x42, 已归一化, 可作为下一步的前一帧)
 *   - dqn_action: DQN 选择的动作
 *
 * 模板参数:
 *   @tparam FRAME_SKIP 帧跳跃次数 (默认为 3)
 *   @tparam D 定点数小数位数
 *   @tparam N 定点数整数位数
 */
template <size_t FRAME_SKIP = 3, size_t D = 8, size_t N = 24>
class DqnEnvGadget : public libsnark::gadget<Fr> {
 public:
  // 状态维度 (EnvGadget 使用 9 维状态)
  static constexpr int STATE_SIZE = 9;
  
  // 图片尺寸
  static constexpr int IMAGE_SIZE_84 = 84 * 84;   // 7056
  static constexpr int IMAGE_SIZE_42 = 42 * 42;   // 1764
  static constexpr int DQN_INPUT_SIZE = 2 * 42 * 42;  // 3528 (双帧输入)

  /**
   * 构造函数
   * @param pb protoboard
   * @param in_state 输入状态 [ball_x, ball_y, ball_vx, ball_vy, paddle1_x, paddle2_x, score1, score2, terminal]
   * @param prev_image 前一帧图片 (42x42, 已归一化, 用于 DQN 输入的第一帧)
   * @param action 外部动作 (另一个玩家的动作，在 frame_skip 期间保持不变)
   * @param random_vxs 随机数数组 (FRAME_SKIP 个，用于球的速度变化)
   * @param random_dirs 随机数数组 (FRAME_SKIP 个，用于球的方向变化)
   * @param conv1_weights DQN Conv1 权重
   * @param conv2_weights DQN Conv2 权重
   * @param fc1_weights DQN FC1 权重
   * @param fc2_weights DQN FC2 权重
   * @param annotation_prefix 注释前缀
   */
  DqnEnvGadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_variable_array<Fr> const& in_state,
               libsnark::pb_variable_array<Fr> const& prev_image,
               libsnark::pb_variable<Fr> const& action,
               libsnark::pb_variable_array<Fr> const& random_vxs,
               libsnark::pb_variable_array<Fr> const& random_dirs,
               libsnark::pb_variable_array<Fr> const& conv1_weights,
               libsnark::pb_variable_array<Fr> const& conv2_weights,
               libsnark::pb_variable_array<Fr> const& fc1_weights,
               libsnark::pb_variable_array<Fr> const& fc2_weights,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_(in_state),
        prev_image_(prev_image),
        action_(action),
        random_vxs_(random_vxs),
        random_dirs_(random_dirs),
        conv1_weights_(conv1_weights),
        conv2_weights_(conv2_weights),
        fc1_weights_(fc1_weights),
        fc2_weights_(fc2_weights) {
    
    // ========== 1. 渲染当前状态 ==========
    render_gadget_.reset(new RenderGadget(
        pb, in_state_,
        FMT(annotation_prefix, " render_current")));

    // ========== 2. 预处理当前图片 ==========
    preprocess_gadget_.reset(new ImagePreprocessGadget(
        pb, render_gadget_->image(),
        FMT(annotation_prefix, " preprocess")));

    // ========== 3. DQN 推理 ==========
    auto const& cur_preprocessed = preprocess_gadget_->output();
    libsnark::pb_variable_array<Fr> dqn_input;
    dqn_input.reserve(DQN_INPUT_SIZE);
    // 第一帧: 前一帧 (已归一化，直接使用)
    for (int i = 0; i < IMAGE_SIZE_42; ++i) {
      dqn_input.emplace_back(prev_image_[i]);
    }
    // 第二帧: 当前帧 (已预处理)
    for (int i = 0; i < IMAGE_SIZE_42; ++i) {
      dqn_input.emplace_back(cur_preprocessed[i]);
    }
    dqn_gadget_.reset(new PongDqnGadget<D, N>(
        pb, dqn_input,
        conv1_weights_, conv2_weights_, fc1_weights_, fc2_weights_,
        FMT(annotation_prefix, " dqn")));
    
    // 从 DQN 的 one-hot 输出计算动作索引 (线性组合)
    // action_index = 0 * onehot[0] + 1 * onehot[1] + 2 * onehot[2] = onehot[1] + 2 * onehot[2]
    auto const& onehot = dqn_gadget_->action_onehot();
    dqn_action_lc_ = onehot[1] + onehot[2] * 2;
    
    // ========== 4 & 5. 创建 FRAME_SKIP 个 EnvGadget ==========
    // 每个使用相同的 DQN 动作和外部动作，但不同的随机数
    // EnvGadget 内部已经处理了 terminal 状态，所以直接链式调用即可
    // intermediate_states_ 直接存储每个 env 的输出状态变量，无需额外 allocate
    intermediate_states_.reserve(FRAME_SKIP);
    env_gadgets_.reserve(FRAME_SKIP);
    for (size_t i = 0; i < FRAME_SKIP; ++i) {
      // 第一步使用 in_state，后续使用上一步的输出状态
      libsnark::pb_variable_array<Fr>& input_state = (i == 0) 
          ? const_cast<libsnark::pb_variable_array<Fr>&>(in_state_) 
          : intermediate_states_[i - 1];
      
      // 创建 EnvGadget
      auto env_gadget = std::unique_ptr<EnvGadget>(new EnvGadget(
          pb, input_state, dqn_action_lc_, action_, random_vxs_[i], random_dirs_[i],
          FMT(annotation_prefix, " env_%d", i)));
      
      // 直接存储 env 的输出状态变量引用
      intermediate_states_.push_back(env_gadget->out_state_vars());
      
      env_gadgets_.push_back(std::move(env_gadget));
    }
    
    // ========== 6. 最终输出状态 ==========
    out_state_ = intermediate_states_[FRAME_SKIP - 1];
    
    // ========== 7. 输出图片 = in_state 渲染结果 (传递给 step j+1 的 prev_image) ==========
    out_image_ = render_gadget_->image();
    out_image_42_ = preprocess_gadget_->output();
  }

  /**
   * 生成 witness
   */
  void GenerateWitness() {
    // 1. 渲染当前状态
    render_gadget_->AssignFromExternal();
    
    // 2. 预处理当前图片
    preprocess_gadget_->generate_r1cs_witness();
    
    // 3. DQN 推理
    dqn_gadget_->generate_r1cs_witness();
    
    // 4. 执行 FRAME_SKIP 次状态转移
    for (size_t i = 0; i < FRAME_SKIP; ++i) {
      env_gadgets_[i]->AssignFromExternal();
    }
    
    // 5. out_image 和 out_image_42 已经在 render_gadget_ 和 preprocess_gadget_ 中处理 (无需额外操作)
  }

  /**
   * 获取输出状态
   */
  libsnark::pb_variable_array<Fr>& out_state() { return out_state_; }
  
  /**
   * 获取输出图片 (84x84)
   */
  libsnark::pb_variable_array<Fr>& out_image() { return out_image_; }
  
  /**
   * 获取输出状态预处理后的图片 (42x42, 已归一化, 可作为下一步的前一帧)
   * 注意: 这是最终状态的渲染图片预处理结果，不是当前状态的预处理图片
   */
  libsnark::pb_variable_array<Fr> const& out_image_42() const { return out_image_42_; }
  
  /**
   * 获取当前状态预处理后的图片 (42x42, 已归一化, DQN 的第二帧输入)
   * 这是拷贝约束中下一轮 prev_image 应该等于的值
   */
  libsnark::pb_variable_array<Fr> const& cur_image_42() const { return preprocess_gadget_->output(); }
  
  /**
   * 获取 DQN 动作 (作为线性组合)
   */
  libsnark::linear_combination<Fr> const& dqn_action() const { return dqn_action_lc_; }
  
  /**
   * 获取 DQN 动作索引 (需要在 generate_r1cs_witness 后调用)
   */
  int get_dqn_action_index() const { return dqn_gadget_->get_action(); }
  
  /**
   * 获取 DQN Q 值 (需要在 generate_r1cs_witness 后调用)
   */
  std::vector<Fr> get_dqn_q_values() const { return dqn_gadget_->get_q_values(); }

 private:
  // 输入
  libsnark::pb_variable_array<Fr> const& in_state_;
  libsnark::pb_variable_array<Fr> const& prev_image_;  // 前一帧 (42x42, 已归一化)
  libsnark::pb_variable<Fr> const& action_;            // 外部动作 (在 frame_skip 期间保持不变)
  libsnark::pb_variable_array<Fr> const& random_vxs_;  // FRAME_SKIP 个随机数
  libsnark::pb_variable_array<Fr> const& random_dirs_; // FRAME_SKIP 个随机数
  libsnark::pb_variable_array<Fr> const& conv1_weights_;
  libsnark::pb_variable_array<Fr> const& conv2_weights_;
  libsnark::pb_variable_array<Fr> const& fc1_weights_;
  libsnark::pb_variable_array<Fr> const& fc2_weights_;
  
  // 输出
  libsnark::pb_variable_array<Fr> out_state_;
  libsnark::pb_variable_array<Fr> out_image_;      // 84x84
  libsnark::pb_variable_array<Fr> out_image_42_;   // 42x42 (预处理后, 已归一化)
  
  // 中间变量
  libsnark::linear_combination<Fr> dqn_action_lc_;  // DQN 动作 (线性组合)
  std::vector<libsnark::pb_variable_array<Fr>> intermediate_states_;  // 每步的中间状态
  
  // 子 gadget
  std::unique_ptr<RenderGadget> render_gadget_;
  std::unique_ptr<ImagePreprocessGadget> preprocess_gadget_;
  std::unique_ptr<PongDqnGadget<D, N>> dqn_gadget_;
  std::vector<std::unique_ptr<EnvGadget>> env_gadgets_;  // FRAME_SKIP 个 EnvGadget
};

}  // namespace circuit::pong
