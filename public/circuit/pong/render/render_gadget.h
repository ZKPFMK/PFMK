#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/pong/render/paddle_col_flag_gadget.h"
#include "circuit/pong/render/ball_bbox_gadget.h"

/**
 * Pong Render Gadget - 图片渲染电路
 *
 * 根据游戏状态渲染图片，输出渲染后的像素值。
 *
 * 渲染规则 (与 Python _render_single_pixel_r1sc 一致):
 *   1. 初始化像素值为背景色 0 (黑色)
 *   2. 判断是否在上方球拍区域 (paddle1): 如果是则设为 255
 *   3. 判断是否在下方球拍区域 (paddle2): 如果是则设为 255
 *   4. 判断是否在球区域 (圆形): 如果是则设为 255 (球覆盖球拍)
 *
 * 渲染顺序决定了覆盖关系: 球拍先渲染，球最后渲染覆盖球拍。
 *
 * 输入:
 *   - state[8]: 状态向量 (使用 [0]ball_x, [1]ball_y, [4]paddle1_x, [5]paddle2_x)
 *
 * 输出:
 *   - image[7056]: 渲染后的图片 (84x84, 每像素 0 或 255) - 内部分配
 */
namespace circuit::pong {

class RenderGadget : public libsnark::gadget<Fr> {
 public:
  // ========== 图像尺寸常量 ==========
  static constexpr int IMAGE_WIDTH = 84;    // 图像宽度
  static constexpr int IMAGE_HEIGHT = 84;   // 图像高度
  static constexpr int IMAGE_SIZE = IMAGE_WIDTH * IMAGE_HEIGHT;  // 总像素数 7056

  // ========== 游戏物体参数常量 ==========
  static constexpr int BALL_RADIUS = 3;                    // 球的半径
  static constexpr int R_SQ = BALL_RADIUS * BALL_RADIUS;   // 半径平方 = 9
  static constexpr int PADDLE_WIDTH = 20;                  // 球拍宽度
  static constexpr int PADDLE_HEIGHT = 3;                  // 球拍高度
  static constexpr int PADDLE1_Y = 5;                      // 上方球拍起始行
  static constexpr int PADDLE2_Y = 76;                     // 下方球拍起始行 (84-3-5)

  // ========== 像素值常量 ==========
  static constexpr int BG_COLOR = 0;       // 背景色 (黑色)
  static constexpr int FG_COLOR = 255;     // 前景色 (白色)

  // ========== abs_gadget 比特位常量 ==========
  static constexpr size_t DIFF_BITS = 5;   // 距离差值所需比特位 (用于圆形判断)

  /**
   * 构造函数 - 创建渲染电路
   *
   * @param pb protoboard, 用于构建 R1CS 约束系统
   * @param state 状态向量 (至少 6 维, 使用 [0]ball_x, [1]ball_y, [4]paddle1_x, [5]paddle2_x)
   * @param annotation_prefix 注释前缀, 用于调试
   */
  RenderGadget(libsnark::protoboard<Fr>& pb,
               libsnark::pb_variable_array<Fr> const& state,
               const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        state_(state) {
    // 内部分配图片变量
    image_.allocate(pb, IMAGE_SIZE, FMT(annotation_prefix, " image"));
    GenerateConstraints();
  }

  /**
   * 生成 witness (从状态计算渲染图片)
   *
   * 调用前需要先设置 state 的值。
   * 此函数会计算所有中间变量和输出图片的值。
   */
  void AssignFromExternal() {
    GenerateWitness();
  }

  /**
   * 获取渲染输出的图片
   */
  libsnark::pb_variable_array<Fr> const& image() const { return image_; }

 private:
  // ========== 外部输入引用 ==========
  libsnark::pb_variable_array<Fr> const& state_;   // 输入状态向量

  // ========== 输出变量 (内部分配) ==========
  libsnark::pb_variable_array<Fr> image_;          // 输出图片

  // ========== 球拍列范围判断 gadget ==========
  std::unique_ptr<PaddleColFlagGadget> paddle1_col_flag_gadget_;  // 上方球拍列判断
  std::unique_ptr<PaddleColFlagGadget> paddle2_col_flag_gadget_;  // 下方球拍列判断

  // ========== 球 bbox (包围盒) 行列判断 gadget ==========
  std::unique_ptr<BallBboxGadget> ball_bbox_gadget_;

  // ========== 逐像素中间变量 ==========
  libsnark::pb_variable_array<Fr> is_in_bbox_;      // is_in_bbox[idx] = 1 表示像素 (row,col) 在球的 bbox 内
  libsnark::pb_variable_array<Fr> gated_diff_;      // gated_diff[idx] = is_in_bbox * (R_SQ - dx^2 - dy^2)
  std::unique_ptr<circuit::abs_batch_gadget> circle_abs_batch_;  // 批量判断 dist_sq <= R_SQ (优化性能)
  libsnark::pb_variable_array<Fr> is_in_circle_;    // is_in_circle[idx] = 1 表示像素在球内

  // ========== 像素期望值组合变量 ==========
  libsnark::pb_variable_array<Fr> circle_and_paddle_;  // circle_and_paddle[idx] = is_in_circle * is_paddle

  /**
   * 判断某行是否在上方球拍区域 (paddle1)
   * 上方球拍行范围: [PADDLE1_Y, PADDLE1_Y + PADDLE_HEIGHT) = [5, 8)
   */
  static constexpr bool IsPaddle1Row(int row) {
    return row >= PADDLE1_Y && row < PADDLE1_Y + PADDLE_HEIGHT;
  }

  /**
   * 判断某行是否在下方球拍区域 (paddle2)
   * 下方球拍行范围: [PADDLE2_Y, PADDLE2_Y + PADDLE_HEIGHT) = [76, 79)
   */
  static constexpr bool IsPaddle2Row(int row) {
    return row >= PADDLE2_Y && row < PADDLE2_Y + PADDLE_HEIGHT;
  }

  /**
   * 生成 R1CS 约束
   */
  void GenerateConstraints() {
    // ========== 提取状态中的关键变量 ==========
    auto const& ball_x = state_[0];      // 球心 X 坐标
    auto const& ball_y = state_[1];      // 球心 Y 坐标
    auto const& paddle1_x = state_[4];   // 上方球拍 X 坐标 (左边界)
    auto const& paddle2_x = state_[5];   // 下方球拍 X 坐标 (左边界)

    // ========================================================================
    // 第一步: 球拍列范围判断
    // ========================================================================
    paddle1_col_flag_gadget_.reset(new PaddleColFlagGadget(
        this->pb, paddle1_x, PADDLE_WIDTH, IMAGE_WIDTH,
        FMT(this->annotation_prefix, " p1cf")));
    paddle2_col_flag_gadget_.reset(new PaddleColFlagGadget(
        this->pb, paddle2_x, PADDLE_WIDTH, IMAGE_WIDTH,
        FMT(this->annotation_prefix, " p2cf")));

    // ========================================================================
    // 第二步: 球 bbox (包围盒) 行列判断 + 距离平方计算
    // 使用 BallBboxGadget 封装
    // ========================================================================
    ball_bbox_gadget_.reset(new BallBboxGadget(
        this->pb, ball_x, ball_y, BALL_RADIUS, IMAGE_WIDTH, IMAGE_HEIGHT,
        FMT(this->annotation_prefix, " bbox")));

    // ========================================================================
    // 第三步: 逐像素约束
    // ========================================================================
    is_in_bbox_.allocate(this->pb, IMAGE_SIZE,
                          FMT(this->annotation_prefix, " bb"));
    gated_diff_.allocate(this->pb, IMAGE_SIZE,
                          FMT(this->annotation_prefix, " gd"));
    is_in_circle_.allocate(this->pb, IMAGE_SIZE,
                            FMT(this->annotation_prefix, " ic"));
    circle_and_paddle_.allocate(this->pb, IMAGE_SIZE,
                                FMT(this->annotation_prefix, " cp"));

    // 获取 BallBboxGadget 的输出引用
    auto const& ball_row_flag = ball_bbox_gadget_->ball_row_flag();
    auto const& ball_col_flag = ball_bbox_gadget_->ball_col_flag();
    auto const& dx_sq = ball_bbox_gadget_->dx_sq();
    auto const& dy_sq = ball_bbox_gadget_->dy_sq();

    // 遍历每个像素，构建约束
    for (int row = 0; row < IMAGE_HEIGHT; ++row) {
      for (int col = 0; col < IMAGE_WIDTH; ++col) {
        int idx = row * IMAGE_WIDTH + col;  // 像素一维索引

        // ---------- 3.1 计算像素是否在球的 bbox 内 ----------
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                ball_row_flag[row], ball_col_flag[col], is_in_bbox_[idx]),
            FMT(this->annotation_prefix, " bb_%d", idx));

        // ---------- 3.2 计算 gated_diff (用于圆形判断) ----------
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                is_in_bbox_[idx],
                -dx_sq[col] - dy_sq[row] + Fr(R_SQ),
                gated_diff_[idx]),
            FMT(this->annotation_prefix, " gd_%d", idx));

        // ---------- 3.3 计算期望像素值 ----------
        // Python 渲染逻辑 (覆盖顺序: 背景 → 球拍 → 球):
        //   pixel = is_ball * 255 + (1 - is_ball) * is_paddle * 255
        //         = (is_ball + is_paddle - is_ball * is_paddle) * 255
        //         = (is_in_circle OR is_paddle) * 255
        bool is_p1_row = IsPaddle1Row(row);
        bool is_p2_row = IsPaddle2Row(row);
        libsnark::linear_combination<Fr> is_paddle_lc;
        if (is_p1_row) {
          is_paddle_lc = paddle1_col_flag_gadget_->col_flag()[col];
        } else if (is_p2_row) {
          is_paddle_lc = paddle2_col_flag_gadget_->col_flag()[col];
        } else {
          is_paddle_lc = libsnark::linear_combination<Fr>(Fr(0));
        }

        // circle_and_paddle = is_in_circle * is_paddle
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                is_in_circle_[idx], is_paddle_lc, circle_and_paddle_[idx]),
            FMT(this->annotation_prefix, " cp_%d", idx));

        // image[idx] = (is_in_circle + is_paddle - circle_and_paddle) * FG_COLOR
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<Fr>(
                is_in_circle_[idx] + is_paddle_lc - circle_and_paddle_[idx],
                Fr(FG_COLOR),
                image_[idx]),
            FMT(this->annotation_prefix, " pixel_%d", idx));
      }
    }

    // ========================================================================
    // 第四步: 批量圆形判断 (使用 abs_batch_gadget 优化性能)
    // ========================================================================
    // is_in_circle[idx] = is_in_bbox[idx] * (1 - sign[idx])
    // 其中 sign[idx] = 1 表示 gated_diff[idx] < 0 (即 dist_sq > R_SQ)
    circle_abs_batch_.reset(new circuit::abs_batch_gadget(
        this->pb, gated_diff_, DIFF_BITS,
        FMT(this->annotation_prefix, " circle_abs_batch")));

    // 为每个像素添加 is_in_circle 约束
    for (int idx = 0; idx < IMAGE_SIZE; ++idx) {
      this->pb.add_r1cs_constraint(
          libsnark::r1cs_constraint<Fr>(
              is_in_bbox_[idx],
              -circle_abs_batch_->ret_sign(idx) + Fr(1),
              is_in_circle_[idx]),
          FMT(this->annotation_prefix, " ic_%d", idx));
    }
  }

  /**
   * 生成 witness (计算所有中间变量的值)
   */
  void GenerateWitness() {
    // ========== 提取状态的整数值 ==========
    int64_t ball_x_val = this->pb.val(state_[0]).getInt64();
    int64_t ball_y_val = this->pb.val(state_[1]).getInt64();
    int64_t paddle1_x_val = this->pb.val(state_[4]).getInt64();
    int64_t paddle2_x_val = this->pb.val(state_[5]).getInt64();

    // ========================================================================
    // 第一步: 计算球拍列标志的 witness
    // ========================================================================
    paddle1_col_flag_gadget_->generate_r1cs_witness(paddle1_x_val);
    paddle2_col_flag_gadget_->generate_r1cs_witness(paddle2_x_val);

    // ========================================================================
    // 第二步: 计算球 bbox 行列标志和距离平方的 witness
    // ========================================================================
    ball_bbox_gadget_->generate_r1cs_witness(ball_x_val, ball_y_val);

    // ========================================================================
    // 第三步: 计算逐像素中间变量的 witness (并行化)
    // ========================================================================
    // 预计算所有像素的 in_bbox 和 gated_diff
    std::vector<bool> in_bbox_vec(IMAGE_SIZE);
    std::vector<int64_t> gated_diff_vec(IMAGE_SIZE);
    std::vector<bool> in_circle_vec(IMAGE_SIZE);
    std::vector<bool> is_paddle_vec(IMAGE_SIZE);

    for (int row = 0; row < IMAGE_HEIGHT; ++row) {
      for (int col = 0; col < IMAGE_WIDTH; ++col) {
        int idx = row * IMAGE_WIDTH + col;

        // 计算 dx, dy 和距离平方
        int64_t dx = col - ball_x_val;
        int64_t dy = row - ball_y_val;
        int64_t dist_sq = dx * dx + dy * dy;

        // 计算是否在球的 bbox 内
        bool in_bbox = (row >= ball_y_val - BALL_RADIUS) && 
                       (row <= ball_y_val + BALL_RADIUS) &&
                       (col >= ball_x_val - BALL_RADIUS) && 
                       (col <= ball_x_val + BALL_RADIUS);
        in_bbox_vec[idx] = in_bbox;

        // 计算 gated_diff
        gated_diff_vec[idx] = in_bbox ? (R_SQ - dist_sq) : 0;

        // 计算是否在圆内
        in_circle_vec[idx] = in_bbox && (dist_sq <= R_SQ);

        // 计算是否在球拍区域
        bool is_p1_row = IsPaddle1Row(row);
        bool is_p2_row = IsPaddle2Row(row);
        if (is_p1_row) {
          is_paddle_vec[idx] = (col >= paddle1_x_val) && (col < paddle1_x_val + PADDLE_WIDTH);
        } else if (is_p2_row) {
          is_paddle_vec[idx] = (col >= paddle2_x_val) && (col < paddle2_x_val + PADDLE_WIDTH);
        } else {
          is_paddle_vec[idx] = false;
        }
      }
    }

    // 批量设置 is_in_bbox 和 gated_diff
    for (int idx = 0; idx < IMAGE_SIZE; ++idx) {
      this->pb.val(is_in_bbox_[idx]) = Fr(in_bbox_vec[idx] ? 1 : 0);
      this->pb.val(gated_diff_[idx]) = Fr(gated_diff_vec[idx]);
    }

    // ========================================================================
    // 第四步: 批量计算圆形判断的 witness (核心优化点)
    // ========================================================================
    // 使用预计算的方法，跳过昂贵的 evaluate 调用
    circle_abs_batch_->generate_r1cs_witness_precomputed(gated_diff_vec);

    // 从批量结果中获取 is_in_circle 和输出图片
    for (int idx = 0; idx < IMAGE_SIZE; ++idx) {
      this->pb.val(is_in_circle_[idx]) = Fr(in_circle_vec[idx] ? 1 : 0);
      this->pb.val(circle_and_paddle_[idx]) = Fr((in_circle_vec[idx] && is_paddle_vec[idx]) ? 1 : 0);
      
      // 计算输出像素值
      bool is_pixel = in_circle_vec[idx] || is_paddle_vec[idx];
      this->pb.val(image_[idx]) = Fr(is_pixel ? FG_COLOR : BG_COLOR);
    }
  }
};

}  // namespace circuit::pong
