#pragma once

#include "circuit/func.h"
#include "circuit/basic/or_gadget.h"
#include "circuit/flappybird/env/score_zone_gadget.h"

/**
 * Score Update Gadget - 分数更新电路
 *
 * 对应 Python transition_logic_r1cs 中的 Step 8 (分数检测):
 *
 *   bird_center_x = BIRD_X + BIRD_WIDTH // 2  # 74
 *   pipe_center_x = pipe_x + PIPE_WIDTH // 2
 *
 *   # 得分条件: pipe_center_x < bird_center_x < pipe_center_x + 5
 *   in_score_zone = (pipe_center_x < bird_center_x) AND (bird_center_x < pipe_center_x + 5)
 *
 *   score_changed = in_score_zone_1 OR in_score_zone_2
 *   score_new = score + score_changed
 *
 * 输入：
 *   - pipe1_x: 管道1的X位置 (整数)
 *   - pipe2_x: 管道2的X位置 (整数)
 *   - score: 当前分数 (整数)
 *
 * 输出：
 *   - new_score: 更新后的分数
 *   - score_changed: 分数是否变化 (0 或 1)
 *
 * 注意: 所有值都是整数。
 */
namespace circuit::flappybird {

class ScoreUpdateGadget : public libsnark::gadget<Fr> {
 public:
  /**
   * 构造函数
   */
  ScoreUpdateGadget(libsnark::protoboard<Fr>& pb,
                    libsnark::pb_variable<Fr> const& pipe1_x,
                    libsnark::pb_variable<Fr> const& pipe2_x,
                    libsnark::pb_variable<Fr> const& score,
                    const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        pipe1_x_(pipe1_x),
        pipe2_x_(pipe2_x),
        score_(score) {
    AllocateVariables();
    GenerateConstraints();
  }

  /**
   * 生成 witness
   */
  void generate_r1cs_witness(int64_t pipe1_x_val, int64_t pipe2_x_val,
                              int64_t score_val) {
    // 管道得分检测
    pipe1_zone_->generate_r1cs_witness();
    pipe2_zone_->generate_r1cs_witness();

    // 总得分
    score_changed_or_->generate_r1cs_witness();

    // new_score
    int64_t score_changed = this->pb.val(score_changed_or_->ret()).getInt64();
    this->pb.val(new_score_) = Fr(score_val + score_changed);
  }

  /**
   * 获取输出
   */
  libsnark::pb_variable<Fr> ret_score() const { return new_score_; }
  libsnark::pb_variable<Fr> ret_score_changed() const { return score_changed_or_->ret(); }

 private:
  // 输入
  libsnark::pb_variable<Fr> const& pipe1_x_;
  libsnark::pb_variable<Fr> const& pipe2_x_;
  libsnark::pb_variable<Fr> const& score_;

  // 输出
  libsnark::pb_variable<Fr> new_score_;

  // 子 gadget
  std::unique_ptr<ScoreZoneGadget> pipe1_zone_;
  std::unique_ptr<ScoreZoneGadget> pipe2_zone_;
  std::unique_ptr<circuit::or_gadget1> score_changed_or_;

  void AllocateVariables() {
    new_score_.allocate(this->pb,
                        FMT(this->annotation_prefix, " new_score"));
  }

  void GenerateConstraints() {
    // ========== 管道1得分检测 (使用 ScoreZoneGadget) ==========
    pipe1_zone_.reset(new ScoreZoneGadget(
        this->pb, pipe1_x_,
        FMT(this->annotation_prefix, " pipe1_zone")));

    // ========== 管道2得分检测 (使用 ScoreZoneGadget) ==========
    pipe2_zone_.reset(new ScoreZoneGadget(
        this->pb, pipe2_x_,
        FMT(this->annotation_prefix, " pipe2_zone")));

    // ========== 总得分 ==========
    // score_changed = zone1 OR zone2
    score_changed_or_.reset(new circuit::or_gadget1(
        this->pb,
        pipe1_zone_->ret(),
        pipe2_zone_->ret(),
        FMT(this->annotation_prefix, " score_changed_or")));

    // new_score = score + score_changed
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(1, score_ + score_changed_or_->ret(), new_score_),
        FMT(this->annotation_prefix, " new_score_calc"));
  }
};

}  // namespace circuit::flappybird
