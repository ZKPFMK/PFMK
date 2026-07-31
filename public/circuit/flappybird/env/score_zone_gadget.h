#pragma once

#include "circuit/func.h"
#include "circuit/basic/abs_gadget.h"
#include "circuit/basic/and_gadget.h"

/**
 * Score Zone Gadget - 单个管道得分区域检测电路
 *
 * 检测鸟是否处于单个管道的得分区域。
 *
 * 得分条件 (Python):
 *   bird_center_x = BIRD_X + BIRD_WIDTH // 2 = 74
 *   pipe_center_x = pipe_x + PIPE_WIDTH // 2 = pipe_x + 26
 *   得分: pipe_center_x < bird_center_x < pipe_center_x + 5
 *
 * 简化条件 (整数):
 *   pipe_x + 26 < 74  AND  74 < pipe_x + 26 + 5
 *   即: pipe_x < 48  AND  pipe_x > 43
 *   即: 44 <= pipe_x <= 47
 *
 * 输入：
 *   - pipe_x: 管道的X位置 (整数)
 *
 * 输出：
 *   - in_score_zone: 是否在得分区域 (0 或 1)
 *
 * 常量：
 *   BIRD_CENTER_X = 74 (鸟中心X坐标)
 *   PIPE_HALF_WIDTH = 26 (管道半宽)
 */
namespace circuit::flappybird {

class ScoreZoneGadget : public libsnark::gadget<Fr> {
 public:
  // 游戏常量
  static constexpr int BIRD_X = 57;
  static constexpr int BIRD_WIDTH = 34;
  static constexpr int PIPE_WIDTH = 52;
  static constexpr int BIRD_CENTER_X = BIRD_X + BIRD_WIDTH / 2;  // 74
  static constexpr int PIPE_HALF_WIDTH = PIPE_WIDTH / 2;          // 26
  static constexpr size_t POS_BITS = 10;

  /**
   * 构造函数
   * @param pb protoboard
   * @param pipe_x 管道X位置
   * @param annotation_prefix 注释前缀
   */
  ScoreZoneGadget(libsnark::protoboard<Fr>& pb,
                  libsnark::pb_variable<Fr> const& pipe_x,
                  const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        pipe_x_(pipe_x) {
    GenerateConstraints();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness() {
    cond1_abs_->generate_r1cs_witness();
    cond2_abs_->generate_r1cs_witness();
    zone_and_->generate_r1cs_witness();
  }

  /**
   * 获取是否在得分区域
   */
  libsnark::pb_variable<Fr> ret() const { return zone_and_->ret(); }

 private:
  // 输入
  libsnark::pb_variable<Fr> const& pipe_x_;

  // 子 gadget
  std::unique_ptr<circuit::abs_gadget> cond1_abs_;
  std::unique_ptr<circuit::abs_gadget> cond2_abs_;
  std::unique_ptr<circuit::and_gadget> zone_and_;

  void GenerateConstraints() {
    // 条件1: pipe_x + 26 < 74  =>  pipe_x < 48  =>  47 - pipe_x >= 0
    // cond1 = (47 - pipe_x >= 0) ? 1 : 0
    libsnark::linear_combination<Fr> cond1_diff =
        libsnark::linear_combination<Fr>(pipe_x_) * Fr(-1) + Fr(BIRD_CENTER_X - PIPE_HALF_WIDTH - 1);  // 47 - pipe_x
    cond1_abs_.reset(new circuit::abs_gadget(
        this->pb, cond1_diff, POS_BITS,
        FMT(this->annotation_prefix, " cond1")));
    // cond1 = 1 - sign (当 47 - pipe_x >= 0 时为1)
    libsnark::linear_combination<Fr> cond1 =
        libsnark::linear_combination<Fr>(cond1_abs_->ret_sign()) * Fr(-1) + Fr(1);

    // 条件2: 74 < pipe_x + 26 + 5  =>  pipe_x > 43  =>  pipe_x - 44 >= 0
    // cond2 = (pipe_x - 44 >= 0) ? 1 : 0
    libsnark::linear_combination<Fr> cond2_diff =
        libsnark::linear_combination<Fr>(pipe_x_) + Fr(-(BIRD_CENTER_X - PIPE_HALF_WIDTH - 5 + 1));  // pipe_x - 44
    cond2_abs_.reset(new circuit::abs_gadget(
        this->pb, cond2_diff, POS_BITS,
        FMT(this->annotation_prefix, " cond2")));
    // cond2 = 1 - sign (当 pipe_x - 44 >= 0 时为1)
    libsnark::linear_combination<Fr> cond2 =
        libsnark::linear_combination<Fr>(cond2_abs_->ret_sign()) * Fr(-1) + Fr(1);

    // in_score_zone = cond1 AND cond2
    zone_and_.reset(new circuit::and_gadget(
        this->pb, cond1, cond2,
        FMT(this->annotation_prefix, " zone")));
  }
};

}  // namespace circuit::flappybird
