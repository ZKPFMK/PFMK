#pragma once

#include "circuit/func.h"
#include "circuit/flappybird/render/render_gadget.h"
#include "circuit/flappybird/dqn/dqn_gadget.h"
#include "circuit/flappybird/env/env_gadget.h"

namespace circuit::flappybird {

/**
 * ImageNormalizeGadget - 图片转换电路
 *
 * 将 84x84 的图片像素值转换为定点数表示。
 * 渲染输出像素值为 0 或 PIXEL_ON(64)。
 *
 * 转换公式:
 *   normalized = pixel * 2^N
 *   其中 pixel 范围是 0-64
 *
 * 输出为线性组合数组，无需额外变量或约束:
 *   output[i] = source[i] * 2^N (线性组合)
 *
 * 注意: 此类存储 source_image 的副本，而不是引用。
 * 这是因为调用者可能在构造后修改 source_image 的底层存储（如 vector 重新分配），
 * 导致引用失效。存储副本可以避免悬空引用问题。
 */
class ImageNormalizeGadget {
 public:
  static constexpr int IMAGE_SIZE = 84 * 84;  // 7056

  /**
   * 构造函数
   * @param source_image 输入图片 (84x84, 值为 0 或 PIXEL_ON)
   * @param scale_factor 缩放因子 (2^N)
   */
  ImageNormalizeGadget(libsnark::pb_variable_array<Fr> const& source_image,
                       int64_t scale_factor)
      : source_image_(source_image),
        scale_factor_(scale_factor) {
    assert(source_image.size() == IMAGE_SIZE);

    // 构建线性组合输出: output[i] = source[i] * scale_factor
    output_.reserve(IMAGE_SIZE);
    for (int i = 0; i < IMAGE_SIZE; ++i) {
      output_.emplace_back(libsnark::linear_combination<Fr>(source_image_[i]) * Fr(scale_factor_));
    }
  }

  /**
   * 获取输出图片 (线性组合数组)
   */
  libsnark::linear_combination_array<Fr> const& output() const { return output_; }

 private:
  libsnark::pb_variable_array<Fr> source_image_;  // 存储副本，避免悬空引用
  libsnark::linear_combination_array<Fr> output_;
  int64_t scale_factor_;
};

/**
 * DqnEnvGadget - Flappy Bird DQN-环境组合电路
 *
 * 实现完整的强化学习步骤:
 * 1. 输入环境状态和前3帧图片
 * 2. 渲染当前状态得到当前图片 (84x84)
 * 3. 归一化当前帧图片和前3帧图片
 * 4. DQN 推理得到动作 (输入为4帧: 归一化后的前3帧 + 当前帧, 共 4x84x84)
 * 5. 状态转移得到新状态 (使用 DQN 动作)
 * 6. 渲染新状态得到新图片 (不归一化)
 * 7. 输出新状态、新图片和 DQN 动作
 *
 * DQN 输入 (4帧堆叠):
 *   [frame_t-3, frame_t-2, frame_t-1, frame_t] 共 4 * 84 * 84 = 28224
 *   其中 frame_t-3 ~ frame_t-1 由外部提供 (原始像素值)，需要归一化
 *   frame_t 由渲染当前状态得到，也需要归一化
 *
 * 输入:
 *   - in_state[7]: 输入状态 (bird_y, bird_vy, pipe1_x, pipe1_gap_y, pipe2_x, pipe2_gap_y, score)
 *   - prev_images[3*7056]: 前3帧图片 (84x84, 原始像素值, 需要归一化)
 *   - next_gap_y: 下一个管道间隙Y (用于管道回收时的新间隙)
 *   - DQN 权重 (conv1, conv2, conv3, fc1, fc2)
 *
 * 输出:
 *   - out_state[8]: 新状态
 *   - out_image[7056]: 新渲染的图片 (84x84, 原始像素值, 不归一化)
 *   - dqn_action: DQN 选择的动作 (0=不跳, 1=跳)
 *
 * 模板参数:
 *   @tparam D 定点数整数位数
 *   @tparam N 定点数小数位数
 */
template <size_t D = 8, size_t N = 24>
class DqnEnvGadget : public libsnark::gadget<Fr> {
 public:
  // 状态维度 (FlappyBird EnvGadget 使用 8 维状态)
  static constexpr int STATE_SIZE = 8;

  // 图片尺寸
  static constexpr int IMAGE_SIZE_84 = 84 * 84;   // 7056
  static constexpr int NUM_PREV_FRAMES = 3;        // DQN 需要前3帧
  static constexpr int DQN_INPUT_SIZE = 4 * IMAGE_SIZE_84;  // 28224 (4帧 x 84x84)

  // 像素值缩放因子: 2^N
  // 将像素值 (0-64) 转换为定点数表示
  static constexpr int64_t NORMALIZE_FACTOR = int64_t(1) << N;

  /**
   * 构造函数
   * @param pb protoboard
   * @param in_state 输入状态 [7维]
   * @param prev_images 前3帧图片 (3 * 84*84, 原始像素值, 需要归一化)
   * @param next_gap_y 下一个管道间隙Y
   * @param conv1_weights DQN Conv1 权重
   * @param conv2_weights DQN Conv2 权重
   * @param conv3_weights DQN Conv3 权重
   * @param fc1_weights DQN FC1 权重
   * @param fc2_weights DQN FC2 权重
   * @param annotation_prefix 注释前缀
   */
  DqnEnvGadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_variable_array<Fr> const& in_state,
               libsnark::pb_variable_array<Fr> const& prev_images,
               libsnark::pb_variable<Fr> const& next_gap_y,
               libsnark::pb_variable_array<Fr> const& conv1_weights,
               libsnark::pb_variable_array<Fr> const& conv2_weights,
               libsnark::pb_variable_array<Fr> const& conv3_weights,
               libsnark::pb_variable_array<Fr> const& fc1_weights,
               libsnark::pb_variable_array<Fr> const& fc2_weights,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_(in_state),
        prev_images_(prev_images),
        next_gap_y_(next_gap_y),
        conv1_weights_(conv1_weights),
        conv2_weights_(conv2_weights),
        conv3_weights_(conv3_weights),
        fc1_weights_(fc1_weights),
        fc2_weights_(fc2_weights) {

    assert(in_state.size() == STATE_SIZE);
    assert(prev_images.size() == NUM_PREV_FRAMES * IMAGE_SIZE_84);

    // ========== 1. 渲染当前状态 ==========
    render_gadget_.reset(new RenderGadget(
        pb, in_state_,
        FMT(annotation_prefix, " render_cur")));

    // ========== 2. 归一化当前帧图片 ==========
    normalize_cur_gadget_.reset(new ImageNormalizeGadget(
        render_gadget_->image(), NORMALIZE_FACTOR));

    // ========== 3. 归一化前3帧图片 ==========
    for (int f = 0; f < NUM_PREV_FRAMES; ++f) {
      // 提取第 f 帧的变量数组
      libsnark::pb_variable_array<Fr> frame_vars;
      frame_vars.reserve(IMAGE_SIZE_84);
      for (int i = 0; i < IMAGE_SIZE_84; ++i) {
        frame_vars.emplace_back(prev_images_[f * IMAGE_SIZE_84 + i]);
      }
      prev_frame_vars_.push_back(std::move(frame_vars));

      normalize_prev_gadgets_.emplace_back(new ImageNormalizeGadget(
          prev_frame_vars_.back(), NORMALIZE_FACTOR));
    }

    // ========== 4. DQN 推理 ==========
    // 组装 DQN 输入: [prev_frame_0_norm, prev_frame_1_norm, prev_frame_2_norm, cur_frame_norm]
    // 所有帧都经过归一化 (线性组合，无需额外变量或约束)
    libsnark::linear_combination_array<Fr> dqn_input;
    dqn_input.reserve(DQN_INPUT_SIZE);

    // 前3帧 (归一化后)
    for (int f = 0; f < NUM_PREV_FRAMES; ++f) {
      auto const& norm_output = normalize_prev_gadgets_[f]->output();
      for (int i = 0; i < IMAGE_SIZE_84; ++i) {
        dqn_input.emplace_back(norm_output[i]);
      }
    }
    // 当前帧 (归一化后)
    auto const& cur_normalized = normalize_cur_gadget_->output();
    for (int i = 0; i < IMAGE_SIZE_84; ++i) {
      dqn_input.emplace_back(cur_normalized[i]);
    }

    dqn_gadget_.reset(new DqnGadget<D, N>(
        pb, dqn_input,
        conv1_weights_, conv2_weights_, conv3_weights_,
        fc1_weights_, fc2_weights_,
        FMT(annotation_prefix, " dqn")));

    // 从 DQN 的 one-hot 输出计算动作索引 (线性组合)
    // FlappyBird: 2 actions, action_index = onehot[1] (0=no_flap, 1=flap)
    auto const& onehot = dqn_gadget_->action_onehot();
    dqn_action_lc_ = onehot[1];

    // ========== 5. 状态转移 ==========
    env_gadget_.reset(new EnvGadget(
        pb, in_state_, dqn_action_lc_, next_gap_y_,
        FMT(annotation_prefix, " env")));

    // ========== 6. 最终输出状态 ==========
    out_state_ = env_gadget_->out_state_vars();

    // ========== 7. 输出图片 = in_state 渲染结果 (传递给 step j+1 的 frame2) ==========
    out_image_ = render_gadget_->image();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness() {
    // 1. 渲染当前状态
    render_gadget_->generate_r1cs_witness();

    // 2. DQN 推理 (归一化是线性组合，无需单独 generate_r1cs_witness)
    dqn_gadget_->generate_r1cs_witness();

    // 3. 状态转移
    env_gadget_->generate_r1cs_witness();

    // 4. out_image 已经在 render_gadget_ 中渲染 (无需额外操作)
  }

  /**
   * 获取输出状态
   */
  libsnark::pb_variable_array<Fr> const& out_state() const { return out_state_; }

  /**
   * 获取输出图片 (84x84, 原始像素值, 不归一化)
   */
  libsnark::pb_variable_array<Fr> const& out_image() const { return out_image_; }

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
  std::pair<Fr, Fr> get_dqn_q_values() const { return dqn_gadget_->get_q_values(); }

 private:
  // 输入
  libsnark::pb_variable_array<Fr> const& in_state_;
  libsnark::pb_variable_array<Fr> const& prev_images_;   // 前3帧 (3 * 84*84, 原始像素值)
  libsnark::pb_variable<Fr> const& next_gap_y_;          // 下一个管道间隙Y
  libsnark::pb_variable_array<Fr> const& conv1_weights_;
  libsnark::pb_variable_array<Fr> const& conv2_weights_;
  libsnark::pb_variable_array<Fr> const& conv3_weights_;
  libsnark::pb_variable_array<Fr> const& fc1_weights_;
  libsnark::pb_variable_array<Fr> const& fc2_weights_;

  // 输出
  libsnark::pb_variable_array<Fr> out_state_;
  libsnark::pb_variable_array<Fr> out_image_;       // 84x84 (原始像素值)

  // 中间变量
  libsnark::linear_combination<Fr> dqn_action_lc_;  // DQN 动作 (线性组合)
  std::vector<libsnark::pb_variable_array<Fr>> prev_frame_vars_;  // 前3帧变量数组 (用于归一化)

  // 子 gadget
  std::unique_ptr<RenderGadget> render_gadget_;                          // 渲染当前状态
  std::unique_ptr<ImageNormalizeGadget> normalize_cur_gadget_;           // 归一化当前帧
  std::vector<std::unique_ptr<ImageNormalizeGadget>> normalize_prev_gadgets_;  // 归一化前3帧
  std::unique_ptr<DqnGadget<D, N>> dqn_gadget_;                         // DQN 推理
  std::unique_ptr<EnvGadget> env_gadget_;                                // 环境状态转移
};

}  // namespace circuit::flappybird
