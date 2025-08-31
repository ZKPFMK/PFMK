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

class EnvGadget : public libsnark::gadget<Fr> {
 typedef circuit::fixed_point::OnehotGadget<8, 24> OnehotGadget;
  public:
  EnvGadget(libsnark::protoboard<Fr>& pb, 
            const std::string& annotation_prefix = "")
      : libsnark::gadget<Fr>(pb, annotation_prefix) {
    in_state.allocate(this->pb, n_state,
                   FMT(this->annotation_prefix, " in_state"));
    
    action.allocate(this->pb, n_action,
                   FMT(this->annotation_prefix, " action"));

    in_state_pack.allocate(this->pb,
                   FMT(this->annotation_prefix, " in_state_pack"));

    out_state.allocate(this->pb, n_state,
                   FMT(this->annotation_prefix, " out_state"));

    out_state_pack.allocate(this->pb, 
                   FMT(this->annotation_prefix, " out_state_pack"));  

    prod.allocate(this->pb, n_action,
                   FMT(this->annotation_prefix, " action_flag"));

    in_onehot_gadget.reset(new OnehotGadget(
        this->pb, in_state, in_state_pack, FMT(this->annotation_prefix, " in_packing")));

    out_onehot_gadget.reset(new OnehotGadget(
        this->pb, out_state, out_state_pack, FMT(this->annotation_prefix, " out_packing")));
    generate_r1cs_constraints();
  }

  void Assign(std::vector<Fr> const& state, std::vector<Fr> const& action) {
    assert(state.size() == n_state && action.size() == n_action);

    for(int i=0; i<state.size(); i++){
        this->pb.val(in_state[i]) = state[i];
    }
    for(int i=0; i<action.size(); i++){
        this->pb.val(this->action[i]) = action[i];
    }
    generate_r1cs_witness();
  };

  libsnark::pb_variable<Fr> ret(){
    return out_state_pack;
  }

  libsnark::pb_variable<Fr> in(){
    return in_state_pack;
  }

  static bool Test(std::vector<Fr> const& state, std::vector<Fr> const& action, Fr fin_state){
    libsnark::protoboard<Fr> pb;
    EnvGadget gadget(pb,  "EnvGadget");
    std::cout << Tick::GetIndentString()
              << "num_constraints: " << pb.num_constraints()
              << ", num_variables: " << pb.num_variables() << "\n";

    gadget.Assign(state, action);

    return pb.is_satisfied() && pb.val(gadget.out_state_pack) == fin_state;
  };

 private:
  void generate_r1cs_constraints() {
    namespace fp = circuit::fp;
    fp::RationalConst<8, 24> rationalConst;

    in_onehot_gadget->generate_r1cs_constraints(true);
    out_onehot_gadget->generate_r1cs_constraints(true);

    // 是否可以向该方向移动
    libsnark::linear_combination<Fr> move = in_state_pack;
    libsnark::linear_combination<Fr> sign_top = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_down = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_left = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_right = rationalConst.kFrN;
    libsnark::linear_combination<Fr> sign_trap;

    int l = (int)std::sqrt(n_state);
    for (size_t i = 0; i < l; ++i) {
        sign_top = sign_top - in_state[i];
        sign_down = sign_down - in_state[n_state - l + i];
        sign_left = sign_left - in_state[i * l];
        sign_right = sign_right - in_state[(i+1) * l - 1];
    }

    // 是否处于陷阱
    for(int i=0; i<trap.size(); i++){
        sign_trap = sign_trap + out_state[trap[i]];
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
        libsnark::r1cs_constraint<Fr>(lc_sign_left, action[0], prod[0]),
        FMT(this->annotation_prefix, " move left")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_down, action[1], prod[1]),
        FMT(this->annotation_prefix, " move down")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_right, action[2], prod[2]),
        FMT(this->annotation_prefix, " move right")
    );

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(lc_sign_top, action[3], prod[3]),
        FMT(this->annotation_prefix, " move top")
    );

    move = move - prod[0];
    move = move + prod[1] * l;
    move = move + prod[2];
    move = move - prod[3] * l;

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<Fr>(move, 1, out_state_pack),
        FMT(this->annotation_prefix, " move")
    );
  }

  void generate_r1cs_witness() {
    namespace fp = circuit::fp;
    fp::RationalConst<8, 24> rationalConst;

    int l = std::sqrt(n_state);
    in_onehot_gadget->generate_r1cs_witness_from_bits();

    int in_pack = (this->pb.lc_val(in_state_pack) / rationalConst.kFrN).getInt64();
    if(this->pb.val(action[0]) == 1){
        if(in_pack % l != 0){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) - rationalConst.kFrN;
            this->pb.val(prod[0]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod[0]) = 0;
        }
    }else if(this->pb.val(action[1]) == 1){
        if(in_pack < n_state - l){
            this->pb.val(out_state_pack) =  this->pb.lc_val(in_state_pack) + l * rationalConst.kFrN;
            this->pb.val(prod[1]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod[1]) = 0;
        }
    }else if(this->pb.val(action[2]) == 1){
        if(in_pack % l != l - 1){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) + rationalConst.kFrN;;
            this->pb.val(prod[2]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod[2]) = 0;
        }
    }else{
        if(in_pack >= l){
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack) - l * rationalConst.kFrN;
            this->pb.val(prod[3]) = rationalConst.kFrN;
        }else{
            this->pb.val(out_state_pack) = this->pb.lc_val(in_state_pack);
            this->pb.val(prod[3]) = 0;
        }
    }
    out_onehot_gadget->generate_r1cs_witness_from_packed();
  }

 private:
  size_t n_state = 64, n_action = 4;

  std::vector<int> trap = {
    19, 29, 35, 41, 42, 46, 49, 52, 54, 59
  };

  libsnark::pb_variable_array<Fr> in_state;
  libsnark::pb_variable_array<Fr> out_state;
  libsnark::pb_variable_array<Fr> action; //action在之前已经验证过
  libsnark::pb_variable_array<Fr> prod;

  libsnark::pb_variable<Fr> in_state_pack;
  libsnark::pb_variable<Fr> out_state_pack;

  std::unique_ptr<OnehotGadget> in_onehot_gadget;
  std::unique_ptr<OnehotGadget> out_onehot_gadget;
  
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
            rets.push_back(EnvGadget::Test(state, action, move(i, j, 8) * rationalConst.kFrN));
        }
        action[j] = 0;
    }
    state[i] = 0;
  }

  std::cout << "\n\nret:" << std::all_of(rets.begin(), rets.end(), [](auto i) { return i; }) << "*****\n\n";
  return std::all_of(rets.begin(), rets.end(), [](auto i) { return i; });
}
};  // namespace circuit::frozenlake