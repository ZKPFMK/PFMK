#pragma once

#include "../fixed_point/fixed_point.h"
#include "../fixed_point/onehot_gadget.h"

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
 */

template <size_t D, size_t N> //D=8, N=24
class EnvGadget : public libsnark::gadget<Fr> {
 public:
  EnvGadget(libsnark::protoboard<Fr>& pb, 
            size_t n_state, size_t n_action, 
            std::vector<int> trap_state,
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix), trap_state(trap_state) {
    assert(n_state > 0 && n_action > 0);

    in_state_.allocate(this->pb, n_state,
                   FMT(this->annotation_prefix, " in_state"));
    
    action_.allocate(this->pb, n_action,
                   FMT(this->annotation_prefix, " action"));
    in_state_pack.allocate(this->pb,
                   FMT(this->annotation_prefix, " in_state_pack"));  
    out_state_pack.allocate(this->pb, 
                   FMT(this->annotation_prefix, " out_state_pack"));  
    out_state_.allocate(this->pb, n_state,
                   FMT(this->annotation_prefix, " out_state"));
    prod_.allocate(this->pb, n_action,
                   FMT(this->annotation_prefix, " action_flag"));

    in_onehot_gadget_.reset(new fixed_point::OnehotGadget<D, N>(
        this->pb, in_state_, in_state_pack, FMT(this->annotation_prefix, " in_packing")));
    out_onehot_gadget_.reset(new fixed_point::OnehotGadget<D, N>(
        this->pb, out_state_, out_state_pack, FMT(this->annotation_prefix, " out_packing")));
    generate_r1cs_constraints();
  }

  void Assign(std::vector<Fr> const& state, std::vector<Fr> const& action) {
    assert(state.size() == in_state_.size() && action.size() == action_.size());

    for(int i=0; i<state.size(); i++){
        this->pb.val(in_state_[i]) = state[i];
    }
    for(int i=0; i<action.size(); i++){
        this->pb.val(action_[i]) = action[i];
    }
    generate_r1cs_witness();
  };

  libsnark::pb_variable<Fr> InState(){
    return in_state_pack;
  }

  libsnark::pb_variable<Fr> OutState(){
    return out_state_pack;
  }

  static bool Test(std::vector<Fr> const& state, std::vector<Fr> const& action, std::vector<int> const& trap_state, Fr fin_state){
    libsnark::protoboard<Fr> pb;
    EnvGadget<D, N> gadget(pb, 64, 4, trap_state, "EnvGadget");
    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    gadget.Assign(state, action);

    return pb.is_satisfied() && pb.val(gadget.out_state_pack) == fin_state;
  };

 private:
  void generate_r1cs_constraints() {
    in_onehot_gadget_->generate_r1cs_constraints(true);
    out_onehot_gadget_->generate_r1cs_constraints(true);

    int l = (int)std::sqrt(in_state_.size());
    circuit::fixed_point::RationalConst<D, N> rationalConst;

    libsnark::linear_combination<Fr> move = in_state_pack;
    libsnark::linear_combination<Fr> sign_top = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_down = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_left = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_right = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_trap;

    for (size_t i = 0; i < l; ++i) {
        sign_top = sign_top - in_state_[i];
        sign_down = sign_down - in_state_[in_state_.size() - l + i];
        sign_left = sign_left - in_state_[i * l];
        sign_right = sign_right - in_state_[(i+1) * l - 1];
    }

    for(int i=0; i<trap_state.size(); i++){
        sign_trap = sign_trap + out_state_[trap_state[i]];
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
        FMT(this->annotation_prefix, " move trap")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_left, action_[0], prod_[0]),
        FMT(this->annotation_prefix, " move left")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_down, action_[1], prod_[1]),
        FMT(this->annotation_prefix, " move down")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_right, action_[2], prod_[2]),
        FMT(this->annotation_prefix, " move right")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_top, action_[3], prod_[3]),
        FMT(this->annotation_prefix, " move top")
    );

    move = move - prod_[0];
    move = move + prod_[1] * l;
    move = move + prod_[2];
    move = move - prod_[3] * l;

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(move, 1, out_state_pack),
        FMT(this->annotation_prefix, " move")
    );
  }

  void generate_r1cs_witness() {
    int l = std::sqrt(in_state_.size());
    in_onehot_gadget_->generate_r1cs_witness_from_bits();

    circuit::fixed_point::RationalConst<D, N> rationalConst;

    int in_pack = (this->pb.lc_val(in_state_pack) / rationalConst.kFrN).getInt64();
    if(this->pb.val(action_[0]) == 1){
        if(in_pack % l != 0){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) - rationalConst.kFrN;
            this->pb.val(prod_[0]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod_[0]) = 0;
        }
    }else if(this->pb.val(action_[1]) == 1){
        if(in_pack < 56){
            this->pb.val(out_state_pack) =  this->pb.lc_val(in_state_pack) + l * rationalConst.kFrN;
            this->pb.val(prod_[1]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod_[1]) = 0;
        }
    }else if(this->pb.val(action_[2]) == 1){
        if(in_pack % l != l - 1){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) + rationalConst.kFrN;;
            this->pb.val(prod_[2]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod_[2]) = 0;
        }
    }else{
        if(in_pack >= l){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) - l * rationalConst.kFrN;
            this->pb.val(prod_[3]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod_[3]) = 0;
        }
    }
    out_onehot_gadget_->generate_r1cs_witness_from_packed();
  }

 private:
  circuit::fixed_point::RationalConst<D, N> rationalConst;

  std::vector<int> trap_state;

  libsnark::pb_variable_array<Fr> in_state_;
  libsnark::pb_variable_array<Fr> out_state_;
  libsnark::pb_variable_array<Fr> action_; //action在之前已经验证过
  libsnark::pb_variable_array<Fr> prod_;

  libsnark::pb_variable<Fr> in_state_pack;
  libsnark::pb_variable<Fr> out_state_pack;

  std::unique_ptr<fixed_point::OnehotGadget<D, N>> out_onehot_gadget_;
  std::unique_ptr<fixed_point::OnehotGadget<D, N>> in_onehot_gadget_;
  
};

inline int move(int state, int action, int l){
    if(action == 0){
        if(state % l == 0){
            return state;
        }else{
            return state - 1;
        }
    }else if(action == 1){
        if(state >= (l-1)*l){
            return state;
        }else{
            return state + l;
        }
    }else if(action == 2){
        if(state % l == l-1){
            return state;
        }else{
            return state + 1;
        }
    }else{
        if(state < l){
            return state;
        }else{
            return state - l;
        }
    }
}

inline bool EnvTest() {
  Tick tick(__FN__);
  constexpr size_t D = 8;
  constexpr size_t N = 24;

  std::vector<bool> rets;

  circuit::fixed_point::RationalConst<D, N> rationalConst;
  std::vector<Fr> state(64, 0), action(4, 0);
  std::vector<int> trap_state = {
    19, 29, 35, 41, 42, 46, 49, 52, 54, 59
  };
  

  for(int i=0; i<64; i++){
    state[i] = rationalConst.kFrN;
    for(int j=0; j<4; j++){
        action[j] = 1;
        if(std::find(trap_state.begin(), trap_state.end(), move(i, j, 8)) == trap_state.end()){
            rets.push_back(EnvGadget<D, N>::Test(state, action, trap_state, move(i, j, 8) * rationalConst.kFrN));
        }
        action[j] = 0;
    }
    state[i] = 0;
  }
  // rets.push_back(OnehotGadget<D, N>::Test({0, 0, 0, 0}, 0));

  std::cout << "\n\nret:" << std::all_of(rets.begin(), rets.end(), [](auto i) { return i; }) << "*****\n\n";
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
};  // namespace circuit::frozenlake