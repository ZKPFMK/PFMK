#pragma once

#include "../basic/circuit.h"

// 在进入 circuit::frozenlake 命名空间之前 include onehot_gadget.h
// 这样 onehot_gadget 会在 circuit 命名空间中正确定义
#include "../basic/onehot_gadget.h"

namespace circuit::frozenlake {

/**
 * 0    1   2
 * 3    4   5   
 * 6    7   8
 *  每一个状态使用一个one-hot向量表示: s0, \cdots, s8, 也可以用一个整数表示: s
 *  每一个动作使用一个one-hot向量表示: a0, \cdots, a3, 也可以用一个整数表示: a
 *  a0: 左, a1: 下, a2: 右, a3: 上
 *  状态变更:
 *      如果动作为a0, 判断是否在第0列, 即 l = s0 + s3 + s6 == 1 ? 0 : 1 => l = 1 - (s0 + s3 + s6)
 *      如果动作为a1, 判断是否在第2行, 即 d = s6 + s7 + s8 == 1 ? 0 : 1 => d = 1 - (s6 + s7 + s8)
 *      如果动作为a2, 判断是否在第2列, 即 r = s2 + s5 + s8 == 1 ? 0 : 1 => r = 1 - (s2 + s5 + s8)
 *      如果动作为a3, 判断是否在第0行, 即 t = s0 + s1 + s2 == 1 ? 0 : 1 => t = 1 - (s0 + s1 + s2)
 *      s' = s - l * a0 + 3 * d * a1 + r * a2 - 3 * t * a2
 *  合法状态:
 *      最终状态的one-hot中所有陷阱的位置和为0
 * 
 * 注意：此 gadget 使用整数运算，不涉及定点数
 */

class EnvGadget : public libsnark::gadget<Fr> {
 public:
  /**
   * 构造函数：接受外部传入的状态和动作变量
   * @param pb protoboard
   * @param in_state 外部传入的状态 one-hot 向量变量
   * @param action 外部传入的动作 one-hot 向量变量
   * @param in_state_pack 外部传入的打包状态变量
   * @param annotation_prefix 注释前缀
   */
  EnvGadget(libsnark::protoboard<Fr>& pb,
            libsnark::pb_variable_array<Fr> const& in_state,
            libsnark::pb_variable_array<Fr> const& action,
            libsnark::pb_variable<Fr> const& in_state_pack,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix),
        in_state_(in_state),
        action_(action),
        in_state_pack_(in_state_pack) {
    out_state_pack_.allocate(this->pb,
                             FMT(this->annotation_prefix, " out_state_pack"));

    prod_.allocate(this->pb, n_action,
                   FMT(this->annotation_prefix, " action_flag"));

    // out_onehot_gadget: 从 out_state_pack_ 生成 one-hot bits
    out_onehot_gadget_.reset(new ::circuit::onehot_gadget(
        this->pb, out_state_pack_, n_state, FMT(this->annotation_prefix, " out_onehot")));
    generate_r1cs_constraints();
  }

  /**
   * 赋值函数：外部变量已由调用者赋值，计算输出
   */
  void AssignFromExternal() {
    generate_r1cs_witness();
  }

  libsnark::pb_variable<Fr> ret() {
    return out_state_pack_;
  }

  libsnark::pb_variable<Fr> in() {
    return in_state_pack_;
  }

 private:
  void generate_r1cs_constraints() {
    // onehot_gadget generates constraints in its constructor, no need to call generate_r1cs_constraints

    // 是否可以向该方向移动
    libsnark::linear_combination<Fr> move = in_state_pack_;
    libsnark::linear_combination<Fr> sign_top = 1;
    libsnark::linear_combination<Fr> sign_down = 1;
    libsnark::linear_combination<Fr> sign_left = 1;
    libsnark::linear_combination<Fr> sign_right = 1;
    libsnark::linear_combination<Fr> sign_trap;

    int l = (int)std::sqrt(n_state);
    for (size_t i = 0; i < (size_t)l; ++i) {
      sign_top = sign_top - in_state_[i];
      sign_down = sign_down - in_state_[n_state - l + i];
      sign_left = sign_left - in_state_[i * l];
      sign_right = sign_right - in_state_[(i + 1) * l - 1];
    }

    // 是否处于陷阱
    for (size_t i = 0; i < trap_.size(); ++i) {
      sign_trap = sign_trap + out_onehot_gadget_->bits[trap_[i]];
    }

    libsnark::pb_linear_combination<Fr> lc_sign_top;
    libsnark::pb_linear_combination<Fr> lc_sign_down;
    libsnark::pb_linear_combination<Fr> lc_sign_left;
    libsnark::pb_linear_combination<Fr> lc_sign_right;
    libsnark::pb_linear_combination<Fr> lc_sign_trap;

    lc_sign_top.assign(this->pb, sign_top);
    lc_sign_down.assign(this->pb, sign_down);
    lc_sign_left.assign(this->pb, sign_left);
    lc_sign_right.assign(this->pb, sign_right);
    lc_sign_trap.assign(this->pb, sign_trap);

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_trap, 1, 0),
        FMT(this->annotation_prefix, " move trap"));

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_left, action_[0], prod_[0]),
        FMT(this->annotation_prefix, " move left"));

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_down, action_[1], prod_[1]),
        FMT(this->annotation_prefix, " move down"));

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_right, action_[2], prod_[2]),
        FMT(this->annotation_prefix, " move right"));

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_top, action_[3], prod_[3]),
        FMT(this->annotation_prefix, " move top"));

    move = move - prod_[0];
    move = move + prod_[1] * l;
    move = move + prod_[2];
    move = move - prod_[3] * l;

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(move, 1, out_state_pack_),
        FMT(this->annotation_prefix, " move"));
  }

  void generate_r1cs_witness() {
    int l = std::sqrt(n_state);

    int in_pack = this->pb.val(in_state_pack_).getInt64();

    // Initialize all prod values to zero
    for (size_t i = 0; i < n_action; ++i) {
      this->pb.val(prod_[i]) = 0;
    }

    if (this->pb.val(action_[0]) == 1) {
      if (in_pack % l != 0) {
        this->pb.val(out_state_pack_) = in_pack - 1;
        this->pb.val(prod_[0]) = 1;
      } else {
        this->pb.val(out_state_pack_) = in_pack;
        this->pb.val(prod_[0]) = 0;
      }
    } else if (this->pb.val(action_[1]) == 1) {
      if (in_pack < (int)(n_state - l)) {
        this->pb.val(out_state_pack_) = in_pack + l;
        this->pb.val(prod_[1]) = 1;
      } else {
        this->pb.val(out_state_pack_) = in_pack;
        this->pb.val(prod_[1]) = 0;
      }
    } else if (this->pb.val(action_[2]) == 1) {
      if (in_pack % l != l - 1) {
        this->pb.val(out_state_pack_) = in_pack + 1;
        this->pb.val(prod_[2]) = 1;
      } else {
        this->pb.val(out_state_pack_) = in_pack;
        this->pb.val(prod_[2]) = 0;
      }
    } else {
      if (in_pack >= l) {
        this->pb.val(out_state_pack_) = in_pack - l;
        this->pb.val(prod_[3]) = 1;
      } else {
        this->pb.val(out_state_pack_) = in_pack;
        this->pb.val(prod_[3]) = 0;
      }
    }
    out_onehot_gadget_->generate_r1cs_witness();
  }

 private:
  size_t n_state = 64, n_action = 4;

  std::vector<int> trap_ = {
      19, 29, 35, 41, 42, 46, 49, 52, 54, 59};

  // 外部变量
  libsnark::pb_variable_array<Fr> const& in_state_;
  libsnark::pb_variable_array<Fr> const& action_;
  libsnark::pb_variable<Fr> const& in_state_pack_;

  // 输出变量
  libsnark::pb_variable_array<Fr> prod_;
  libsnark::pb_variable<Fr> out_state_pack_;

  std::unique_ptr<::circuit::onehot_gadget> out_onehot_gadget_;
};

}  // namespace circuit::frozenlake
