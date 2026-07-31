#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/flappybird/render/range_flag_gadget.h"

/**
 * Flappy Bird Render Gadget - 图片渲染电路
 *
 * 根据游戏状态渲染 84x84 图片，输出渲染后的像素值。
 * 与 Python render_image_r1cs (flappy_bird.py) 完全一致。
 *
 * 渲染规则 (与 Python render_image_r1cs 一致):
 *   对于每个像素 (i, j):
 *     1. 计算原始坐标: orig_x = i * 288 // 84, orig_y = j * 404 // 84
 *     2. 检测 Pipe 1: in_pipe_x_1 AND (in_upper_1 OR in_lower_1)
 *     3. 检测 Pipe 2: in_pipe_x_2 AND (in_upper_2 OR in_lower_2)
 *     4. 检测 Bird: in_bird_x AND in_bird_y
 *     5. pixel = (is_pipe_1 OR is_pipe_2 OR is_bird) * PIXEL_ON
 *
 * 坐标映射 (整数最近邻):
 *   orig_x[i] = i * SCREEN_WIDTH / IMAGE_SIZE = i * 288 / 84
 *   orig_y[j] = j * BASE_Y / IMAGE_SIZE = j * 404 / 84
 *
 * 注意: Python 中 image 的第一维 i 对应 orig_x (水平方向),
 *       第二维 j 对应 orig_y (垂直方向)。
 *
 * 输入状态向量 (7维):
 *   [0] bird_y       -- 鸟的Y位置
 *   [1] bird_vy      -- 鸟的垂直速度 (渲染不使用)
 *   [2] pipe1_x      -- 第一个管道的X位置
 *   [3] pipe1_gap_y  -- 第一个管道的间隙Y位置
 *   [4] pipe2_x      -- 第二个管道的X位置
 *   [5] pipe2_gap_y  -- 第二个管道的间隙Y位置
 *   [6] score        -- 分数 (渲染不使用)
 *
 * 输出:
 *   image[7056]: 渲染后的图片 (84x84, 每像素 0 或 PIXEL_ON=64)
 *
 * 设计参考: pong/render/render_gadget.h
 */
namespace circuit::flappybird {

/**
 * or1_batch_gadget - 修复版 or1_batch_gadget
 *
 * 与 circuit::or1_batch_gadget 功能相同，但修复了 z.allocate 缺少
 * annotation_prefix 导致 DEBUG 模式下断言失败的问题。
 *
 * z[i] = x[i] OR y[i] = x[i] + y[i] - x[i] * y[i]
 * 约束数量: n (batch_size)
 */
class or1_batch_gadget : public libsnark::gadget<Fr> {
 public:
  or1_batch_gadget(libsnark::protoboard<Fr>& pb,
                   libsnark::linear_combination_array<Fr> const& x,
                   libsnark::linear_combination_array<Fr> const& y,
                   const std::string& annotation_prefix)
      : x_(x), y_(y), libsnark::gadget<Fr>(pb, annotation_prefix) {
    z_.allocate(pb, x.size(), FMT(annotation_prefix, " z"));
    for (size_t i = 0; i < x.size(); ++i) {
      pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(x[i], y[i], x[i] + y[i] - z_[i]),
          FMT(annotation_prefix, " or_%zu", i));
    }
  }

  void generate_r1cs_witness() {
    auto const& assignment = pb.full_variable_assignment_ref();
    auto f = [this, &assignment](size_t i) {
      Fr vx = x_[i].evaluate(assignment);
      Fr vy = y_[i].evaluate(assignment);
      // Both vx and vy should be 0 or 1 (binary flags)
      // Use Fr comparison instead of getUint64 to avoid overflow
      bool bx = (vx != Fr(0));
      bool by = (vy != Fr(0));
      pb.val(z_[i]) = Fr(bx || by ? 1 : 0);
    };
    parallel::For(x_.size(), f);
  }

  libsnark::pb_variable<Fr> ret(size_t i) const { return z_[i]; }
  libsnark::pb_variable_array<Fr> const& ret() const { return z_; }

 private:
  libsnark::linear_combination_array<Fr> const x_, y_;
  libsnark::pb_variable_array<Fr> z_;
};

class RenderGadget : public libsnark::gadget<Fr> {
 public:
  // ========== 图像尺寸常量 ==========
  static constexpr int IMAGE_WIDTH = 84;
  static constexpr int IMAGE_HEIGHT = 84;
  static constexpr int IMAGE_SIZE = IMAGE_WIDTH * IMAGE_HEIGHT;  // 7056

  // ========== 游戏常量 (与 Python 一致) ==========
  static constexpr int SCREEN_WIDTH = 288;
  static constexpr int BASE_Y = 404;
  static constexpr int BIRD_X = 57;
  static constexpr int BIRD_WIDTH = 34;
  static constexpr int BIRD_HEIGHT = 24;
  static constexpr int PIPE_WIDTH = 52;
  static constexpr int PIPE_GAP_SIZE = 100;

  // ========== 像素值常量 ==========
  static constexpr int PIXEL_ON = 64;  // R1CS 友好的像素值 (2^6)

  /**
   * 构造函数 - 创建渲染电路
   *
   * @param pb protoboard
   * @param state 状态向量 (7维)
   * @param annotation_prefix 注释前缀
   */
  RenderGadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_variable_array<Fr> const& state,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        state_(state) {
    // 内部分配图片变量
    image_.allocate(pb, IMAGE_SIZE, FMT(annotation_prefix, " image"));

    // 预计算常量坐标映射
    PrecomputeCoordinates();

    // 生成约束
    GenerateConstraints();
  }

  /**
   * 生成 witness (从状态计算渲染图片)
   */
  void generate_r1cs_witness() {
    GenerateWitness();
  }

  /**
   * 获取渲染输出的图片
   */
  libsnark::pb_variable_array<Fr> const& image() const { return image_; }

 private:
  // ========== 外部输入引用 ==========
  libsnark::pb_variable_array<Fr> const& state_;

  // ========== 输出变量 ==========
  libsnark::pb_variable_array<Fr> image_;

  // ========== 预计算的常量坐标 ==========
  std::vector<int> orig_x_;  // orig_x[i] = i * 288 / 84, 大小 84
  std::vector<int> orig_y_;  // orig_y[j] = j * 404 / 84, 大小 84
  std::vector<bool> bird_x_const_;  // bird_x_const[i] = (BIRD_X <= orig_x[i] < BIRD_X + BIRD_WIDTH)

  // ========== Pipe 1 gadgets ==========
  std::unique_ptr<RangeFlagGadget> pipe1_x_flag_gadget_;   // pipe1_x <= orig_x[i] < pipe1_x + PIPE_WIDTH
  std::unique_ptr<LessThanFlagGadget> pipe1_upper_gadget_; // orig_y[j] < pipe1_gap_y
  std::unique_ptr<GreaterEqFlagGadget> pipe1_lower_gadget_; // orig_y[j] >= pipe1_gap_y + PIPE_GAP_SIZE

  // ========== Pipe 2 gadgets ==========
  std::unique_ptr<RangeFlagGadget> pipe2_x_flag_gadget_;
  std::unique_ptr<LessThanFlagGadget> pipe2_upper_gadget_;
  std::unique_ptr<GreaterEqFlagGadget> pipe2_lower_gadget_;

  // ========== Bird Y gadget ==========
  std::unique_ptr<RangeFlagGadget> bird_y_flag_gadget_;    // bird_y <= orig_y[j] < bird_y + BIRD_HEIGHT

  // ========== OR gadgets ==========
  // 管道 Y 方向 OR (per column): pipe_y_flag[j] = in_upper[j] OR in_lower[j]
  std::unique_ptr<or1_batch_gadget> pipe1_y_or_gadget_;
  std::unique_ptr<or1_batch_gadget> pipe2_y_or_gadget_;

  // 逐像素中间变量
  libsnark::pb_variable_array<Fr> is_pipe1_;       // is_pipe1[idx] = pipe1_x_flag[i] * pipe1_y_flag[j]
  libsnark::pb_variable_array<Fr> is_pipe2_;       // is_pipe2[idx]
  libsnark::pb_variable_array<Fr> is_any_pipe_;    // is_any_pipe[idx] = is_pipe1[idx] OR is_pipe2[idx]
  // is_any_object 仅在 bird 列分配 (非 bird 列直接用 is_any_pipe，节省一个 OR)
  libsnark::pb_variable_array<Fr> is_any_object_;  // 大小 = bird_col_count * IMAGE_HEIGHT

  /**
   * 预计算常量坐标映射
   */
  void PrecomputeCoordinates() {
    orig_x_.resize(IMAGE_WIDTH);
    orig_y_.resize(IMAGE_HEIGHT);
    bird_x_const_.resize(IMAGE_WIDTH);

    for (int i = 0; i < IMAGE_WIDTH; ++i) {
      orig_x_[i] = i * SCREEN_WIDTH / IMAGE_WIDTH;
      bird_x_const_[i] = (orig_x_[i] >= BIRD_X) && (orig_x_[i] < BIRD_X + BIRD_WIDTH);
    }

    for (int j = 0; j < IMAGE_HEIGHT; ++j) {
      orig_y_[j] = j * BASE_Y / IMAGE_HEIGHT;
    }
  }

  /**
   * 生成 R1CS 约束
   */
  void GenerateConstraints() {
    auto const& bird_y = state_[0];
    auto const& pipe1_x = state_[2];
    auto const& pipe1_gap_y = state_[3];
    auto const& pipe2_x = state_[4];
    auto const& pipe2_gap_y = state_[5];

    // ========================================================================
    // 第一步: Pipe 1 范围判断
    // ========================================================================
    pipe1_x_flag_gadget_.reset(new RangeFlagGadget(
        this->pb, pipe1_x, PIPE_WIDTH, orig_x_,
        FMT(this->annotation_prefix, " p1xf")));

    pipe1_upper_gadget_.reset(new LessThanFlagGadget(
        this->pb, pipe1_gap_y, orig_y_,
        FMT(this->annotation_prefix, " p1u")));

    libsnark::linear_combination<Fr> pipe1_lower_threshold = pipe1_gap_y + Fr(PIPE_GAP_SIZE);
    pipe1_lower_gadget_.reset(new GreaterEqFlagGadget(
        this->pb, pipe1_lower_threshold, orig_y_,
        FMT(this->annotation_prefix, " p1l")));

    // ========================================================================
    // 第二步: Pipe 2 范围判断
    // ========================================================================
    pipe2_x_flag_gadget_.reset(new RangeFlagGadget(
        this->pb, pipe2_x, PIPE_WIDTH, orig_x_,
        FMT(this->annotation_prefix, " p2xf")));

    pipe2_upper_gadget_.reset(new LessThanFlagGadget(
        this->pb, pipe2_gap_y, orig_y_,
        FMT(this->annotation_prefix, " p2u")));

    libsnark::linear_combination<Fr> pipe2_lower_threshold = pipe2_gap_y + Fr(PIPE_GAP_SIZE);
    pipe2_lower_gadget_.reset(new GreaterEqFlagGadget(
        this->pb, pipe2_lower_threshold, orig_y_,
        FMT(this->annotation_prefix, " p2l")));

    // ========================================================================
    // 第三步: Bird Y 范围判断
    // ========================================================================
    bird_y_flag_gadget_.reset(new RangeFlagGadget(
        this->pb, bird_y, BIRD_HEIGHT, orig_y_,
        FMT(this->annotation_prefix, " byf")));

    // ========================================================================
    // 第四步: 管道 Y 方向 OR (per column), 使用 or1_batch_gadget
    // ========================================================================
    // pipe_y_flag[j] = in_upper[j] OR in_lower[j]
    pipe1_y_or_gadget_.reset(new or1_batch_gadget(
        this->pb, pipe1_upper_gadget_->flag(), pipe1_lower_gadget_->flag(),
        FMT(this->annotation_prefix, " p1yor")));

    pipe2_y_or_gadget_.reset(new or1_batch_gadget(
        this->pb, pipe2_upper_gadget_->flag(), pipe2_lower_gadget_->flag(),
        FMT(this->annotation_prefix, " p2yor")));

    // ========================================================================
    // 第五步: 逐像素约束
    // ========================================================================
    is_pipe1_.allocate(this->pb, IMAGE_SIZE,
        FMT(this->annotation_prefix, " ip1"));
    is_pipe2_.allocate(this->pb, IMAGE_SIZE,
        FMT(this->annotation_prefix, " ip2"));
    is_any_pipe_.allocate(this->pb, IMAGE_SIZE,
        FMT(this->annotation_prefix, " iap"));

    // is_any_object 仅为 bird 列分配
    int bird_col_count = 0;
    for (int i = 0; i < IMAGE_WIDTH; ++i) {
      if (bird_x_const_[i]) ++bird_col_count;
    }
    is_any_object_.allocate(this->pb, bird_col_count * IMAGE_HEIGHT,
        FMT(this->annotation_prefix, " iao"));

    auto const& p1xf = pipe1_x_flag_gadget_->flag();
    auto const& p2xf = pipe2_x_flag_gadget_->flag();
    auto const& p1yf = pipe1_y_or_gadget_->ret();
    auto const& p2yf = pipe2_y_or_gadget_->ret();
    auto const& byf = bird_y_flag_gadget_->flag();

    int bird_obj_idx = 0;  // is_any_object_ 的索引
    for (int i = 0; i < IMAGE_WIDTH; ++i) {
      for (int j = 0; j < IMAGE_HEIGHT; ++j) {
        int idx = i * IMAGE_HEIGHT + j;

        // is_pipe1[idx] = pipe1_x_flag[i] * pipe1_y_or[j]
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(p1xf[i], p1yf[j], is_pipe1_[idx]),
            FMT(this->annotation_prefix, " ip1_%d", idx));

        // is_pipe2[idx] = pipe2_x_flag[i] * pipe2_y_or[j]
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(p2xf[i], p2yf[j], is_pipe2_[idx]),
            FMT(this->annotation_prefix, " ip2_%d", idx));

        // is_any_pipe[idx] = is_pipe1[idx] OR is_pipe2[idx]
        //   即 is_pipe1 * is_pipe2 = is_pipe1 + is_pipe2 - is_any_pipe
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                is_pipe1_[idx], is_pipe2_[idx],
                is_pipe1_[idx] + is_pipe2_[idx] - is_any_pipe_[idx]),
            FMT(this->annotation_prefix, " iap_%d", idx));

        if (bird_x_const_[i]) {
          // Bird 列: is_any_object = is_any_pipe OR is_bird
          //   is_bird = byf[j] (bird_x_const 是编译时常量)
          //   is_any_pipe * byf[j] = is_any_pipe + byf[j] - is_any_object
          this->pb.add_r1cs_constraint(
              libsnark::r1cs_constraint<Fr>(
                  is_any_pipe_[idx], byf[j],
                  is_any_pipe_[idx] + byf[j] - is_any_object_[bird_obj_idx]),
              FMT(this->annotation_prefix, " iao_%d", idx));

          // image[idx] = is_any_object * PIXEL_ON
          this->pb.add_r1cs_constraint(
              libsnark::r1cs_constraint<Fr>(
                  is_any_object_[bird_obj_idx], Fr(PIXEL_ON), image_[idx]),
              FMT(this->annotation_prefix, " px_%d", idx));
          ++bird_obj_idx;
        } else {
          // 非 Bird 列: is_bird = 0, 直接用 is_any_pipe，节省一个 OR
          // image[idx] = is_any_pipe[idx] * PIXEL_ON
          this->pb.add_r1cs_constraint(
              libsnark::r1cs_constraint<Fr>(
                  is_any_pipe_[idx], Fr(PIXEL_ON), image_[idx]),
              FMT(this->annotation_prefix, " px_%d", idx));
        }
      }
    }
  }

  /**
   * 生成 witness
   */
  void GenerateWitness() {
    int64_t bird_y_val = this->pb.val(state_[0]).getInt64();
    int64_t pipe1_x_val = this->pb.val(state_[2]).getInt64();
    int64_t pipe1_gap_y_val = this->pb.val(state_[3]).getInt64();
    int64_t pipe2_x_val = this->pb.val(state_[4]).getInt64();
    int64_t pipe2_gap_y_val = this->pb.val(state_[5]).getInt64();

    // ========== 第一步: 范围判断 witness ==========
    pipe1_x_flag_gadget_->generate_r1cs_witness(pipe1_x_val);
    pipe1_upper_gadget_->generate_r1cs_witness(pipe1_gap_y_val);
    pipe1_lower_gadget_->generate_r1cs_witness(pipe1_gap_y_val + PIPE_GAP_SIZE);

    pipe2_x_flag_gadget_->generate_r1cs_witness(pipe2_x_val);
    pipe2_upper_gadget_->generate_r1cs_witness(pipe2_gap_y_val);
    pipe2_lower_gadget_->generate_r1cs_witness(pipe2_gap_y_val + PIPE_GAP_SIZE);

    bird_y_flag_gadget_->generate_r1cs_witness(bird_y_val);

    // ========== 第二步: 管道 Y OR witness ==========
    pipe1_y_or_gadget_->generate_r1cs_witness();
    pipe2_y_or_gadget_->generate_r1cs_witness();

    // ========== 第三步: 逐像素 witness ==========
    int bird_obj_idx = 0;
    for (int i = 0; i < IMAGE_WIDTH; ++i) {
      int ox = orig_x_[i];
      bool in_p1x = (ox >= pipe1_x_val) && (ox < pipe1_x_val + PIPE_WIDTH);
      bool in_p2x = (ox >= pipe2_x_val) && (ox < pipe2_x_val + PIPE_WIDTH);

      for (int j = 0; j < IMAGE_HEIGHT; ++j) {
        int idx = i * IMAGE_HEIGHT + j;
        int oy = orig_y_[j];

        bool p1u = oy < pipe1_gap_y_val;
        bool p1l = oy >= pipe1_gap_y_val + PIPE_GAP_SIZE;
        bool is_p1 = in_p1x && (p1u || p1l);

        bool p2u = oy < pipe2_gap_y_val;
        bool p2l = oy >= pipe2_gap_y_val + PIPE_GAP_SIZE;
        bool is_p2 = in_p2x && (p2u || p2l);

        this->pb.val(is_pipe1_[idx]) = Fr(is_p1 ? 1 : 0);
        this->pb.val(is_pipe2_[idx]) = Fr(is_p2 ? 1 : 0);

        bool is_any_pipe = is_p1 || is_p2;
        this->pb.val(is_any_pipe_[idx]) = Fr(is_any_pipe ? 1 : 0);

        if (bird_x_const_[i]) {
          bool in_bird_y = (oy >= bird_y_val) && (oy < bird_y_val + BIRD_HEIGHT);
          bool is_any_object = is_any_pipe || in_bird_y;
          this->pb.val(is_any_object_[bird_obj_idx]) = Fr(is_any_object ? 1 : 0);
          this->pb.val(image_[idx]) = Fr(is_any_object ? PIXEL_ON : 0);
          ++bird_obj_idx;
        } else {
          this->pb.val(image_[idx]) = Fr(is_any_pipe ? PIXEL_ON : 0);
        }
      }
    }
  }
};

}  // namespace circuit::flappybird
