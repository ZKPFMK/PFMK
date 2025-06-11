#include <iostream>

#include "ecc/ecc.h"
#include "public.h"
#include "clink/frozenlake/frozenlake.h"
// #include "clink/frozenlake/frozenlake2.h"
#include "clink/mlp/mlp.h"

#include "groth09/groth09.h"
#include "libra/libra.h"
// #include "circuit/fixed_point/sign_gadget.h"
// #include "circuit/fixed_point/ip_gadget.h"
// #include "circuit/fixed_point/onehot_gadget.h"
#include "circuit/frozenlake/env_gadget.h"
#include "clink/equality3.h"
// #include "circuit/fixed_point/misc.h"
// #include "circuit/fixed_point/max_gadget.h"
#include "circuit/fixed_point/max2_gadget.h"
#include "hyrax/hyrax.h"
#include "bp/protocol31.h"

#include "public.h"

using namespace std;


bool DEBUG_CHECK = false;
bool BIG_MODE = false;
bool DISABLE_TBB = false;

bool InitAll(std::string const& data_dir) {
  InitEcc();

  std::string const kFileName = BIG_MODE ? "pds_pub_big.bin" : "pds_pub.bin";
  // pc::Base::SetGSize(68);
  auto ecc_pds_file = data_dir + "/" + kFileName;
  if (!pc::OpenOrCreatePdsPub(ecc_pds_file)) {
    std::cerr << "Open or create pds pub file " << ecc_pds_file << " failed\n";
    return false;
  }

  return true;
}

std::unique_ptr<tbb::task_scheduler_init> tbb_init;

int main(int argc, char *argv[]){
    InitAll(".");

    bool ret = true;
    
    clink::mlp::key = Fr("1210900363957837763448289850596859730946393694560926318100150438946065790197");
    clink::mlp::sk_sel = Fr("1947813665846030422559828600490533160609795549654730157211166665690478441119");
    clink::mlp::sk_buy = Fr("19909940428476593807986756695020318192734285490982501092727296391197763088211");
    clink::mlp::sk = clink::mlp::sk_sel + clink::mlp::sk_buy;
    clink::mlp::pk_sel = pc::kGetRefG1(0) * Fr("1947813665846030422559828600490533160609795549654730157211166665690478441119");
    clink::mlp::pk_buy = pc::kGetRefG1(0) * Fr("19909940428476593807986756695020318192734285490982501092727296391197763088211");
    clink::mlp::pk = clink::mlp::pk_sel + clink::mlp::pk_buy;

    libsnark::protoboard<Fr> pb_relu;
    circuit::fixed_point::Relu2Gadget<8, 48, 24> relu_gadget(pb_relu, "relu gadget");

    libsnark::protoboard<Fr> pb_mimc;
    circuit::Mimc5Gadget mimc_gadget(pb_mimc, "Mimc5Gadget");

    clink::mlp::MLP::Preprocess(pb_relu, clink::mlp::relu_A, clink::mlp::relu_B, clink::mlp::relu_C);
    clink::mlp::MLP::Preprocess(pb_mimc, clink::mlp::mimc_A, clink::mlp::mimc_B, clink::mlp::mimc_C);

    tbb_init = parallel::InitTbb((int)0);

    // hyrax::A6::Test(128);

    // ret = libra::A2::Test(m, k, n);

    // int64_t m =  atoi(argv[1]);
    // int64_t k =  atoi(argv[2]);
    // int64_t n =  atoi(argv[2]);

    // hyrax::A5::Test(m);
    // hyrax::A6::Test(m);
    // hyrax::A7::Test(m, k);

    // libra::A1::Test(m, k);
    // ret = libra::A3::Test(58, 14, 8);
    // ret = libra::A3::Test(m, k, n);

    // ret = libra::A1::TestQuickMul();

    // ret = libra::A4::Test(87, 173, 7, m, k, n);

    // ret = clink::frozenlake::FrozenLake::Test();

    // ret = circuit::fixed_point::TestMax2();
  
    // std::cout << "ret:" << ret << std::endl;

    // ret = hyrax::A5::Test(m);
    // std::cout << ret << std::endl;
    
    // clink::frozenlake::FrozenLake::TestModel();

    // clink::frozenlake::FrozenLake::Test();

    // clink::frozenlake::FrozenLake::TestKey(m, n);

    // clink::frozenlake::FrozenLake::TestEnv();

    // clink::frozenlake::FrozenLake::TestPod();

    clink::mlp::MLP::Test();


    // clink::mlp::MLP::Test();

    // clink::mlp::MLP::TestKey();

    // clink::Equality3::Test(m);

    // circuit::fixed_point::RationalConst<8, 24> rationalConst;
    // std::cout << (circuit::fixed_point::DoubleToRational<8, 24>(1) == rationalConst.kFrN) << "\n"; 

    // circuit::fixed_point::OnehotTest();

    // circuit::frozenlake::EnvTest();

    // clink::frozenlake::FrozenLake::TestSumCheck();

    // clink::ParallelR1cs<groth09::SuccinctPolicy>::Test(2, 4);

    // for(int i=2; i<256; i++)
      // ret &= libra::A1::Test(i, i);
    // ret = libra::A1::Test(6, 6);
    // cout << "ret:" << ret << endl;

    // ret = libra::A2::Test(127, 127, 127);


    using Policy = groth09::SuccinctPolicy;
    // using R1cs = typename clink::ParallelR1cs<Policy>;
    using HyraxA = typename Policy::HyraxA;
    using Sec51 = typename Policy::Sec51;
    using Sec53 = typename Policy::Sec53; //53b<51c>
    using Sec43 = typename Policy::Sec43;

    // groth09::Sec43b<Sec53, HyraxA>::Test(m, k);

    // groth09::Sec43a<Sec53, HyraxA>::Test(m, k);

    // groth09::Sec51c::Test(m);

    // hyrax::A3::Test(m);

    //  groth09::Sec53b<Sec51>::Test(m, k);

    // clink::EqualIp<HyraxA>::Test(m, k);

    // hyrax::A3::Test(3);

    // clink::Product::Test();

    // clink::frozenlake::FrozenLake::testReluGadget();

    // clink::frozenlake::testVarIdxAndAssignIdx();

    // bp::p31::Test(m);

    // circuit::frozenlake::TestPacking();
    // circuit::fixed_point::TestSignStudy();
    // circuit::fixed_point::TestIp();
    return ret;
}
