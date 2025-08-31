#include "public.h"
// #include "clink/frozenlake/frozenlake.h"
#include "clink/vgg16/vgg16.h"
#include "clink/frozenlake/frozenlake.h"
#include "clink/mlp/mlp.h"
#include "circuit/func.h"
#include "clink/mnist/mnist.h"
#include <sys/resource.h>

#define VMRSS_LINE 17

bool BIG_MODE = false;
bool DEBUG_CHECK = false;
bool DISABLE_TBB = false;

std::vector<std::vector<Fr>> max4_a, max4_b, max4_c;
std::vector<std::vector<Fr>> relu_a, relu_b, relu_c;

bool InitAll(std::string const& data_dir) {
  InitEcc();
  std::string const kFileName = BIG_MODE ? "pds_pub_big.bin" : "pds_pub.bin";
  // pc::Base::SetGSize(0);
  auto ecc_pds_file = data_dir + "/" + kFileName;
  if (!pc::OpenOrCreatePdsPub(ecc_pds_file)) {
    std::cerr << "Open or create pds pub file " << ecc_pds_file << " failed\n";
    return false;
  }
  return true;
}

int get_peak_memory_by_pid(pid_t pid) {
    char file_name[64];
    sprintf(file_name,"/proc/%d/status",pid);

    FILE *fd = fopen(file_name,"r");
    if (!fd) return 0;

    char line_buff[512];
    int vmhwm = 0;
    while (fgets(line_buff, sizeof(line_buff), fd)) {
        if (strncmp(line_buff, "VmHWM:", 6) == 0) {
            sscanf(line_buff, "%*s %d", &vmhwm);
            break;
        }
    }
    fclose(fd);
    return vmhwm; // 单位 kB
}

void Preprocess(){
  Tick tick(__FN__);
  //初始化密钥
  clink::sk_sel = Fr("1947813665846030422559828600490533160609795549654730157211166665690478441119");
  clink::sk_buy = Fr("19909940428476593807986756695020318192734285490982501092727296391197763088211");
  clink::sk = clink::sk_sel + clink::sk_buy;
  clink::pk_sel = pc::kGetRefG1(0) * clink::sk_sel;
  clink::pk_buy = pc::kGetRefG1(0) * clink::sk_buy;
  clink::pk = clink::pk_sel + clink::pk_buy;

  //初始化R1CS矩阵
  libsnark::protoboard<Fr> pb_max4;
  circuit::fixed_point::Max2Gadget<8, 48> max4_gadget(pb_max4, 4, "Max4gadget");

  libsnark::protoboard<Fr> pb_relu;
  circuit::fixed_point::Relu2Gadget<8, 24 * 2, 24> mnist_relu_gadget(pb_relu, "Relu2Gadget");

  libsnark::protoboard<Fr> pb_rlbn;
  circuit::vgg16::ReluBnGadget<8, 24> rlbn_gadget(pb_rlbn, "vgg16 relubn gadget");

  libsnark::protoboard<Fr> pb_pool; 
  circuit::vgg16::PoolingGadget<8, 24> pool_gadget(pb_pool, "vgg16 pooling gadget");

  libsnark::protoboard<Fr> pb_mimc;
  circuit::Mimc5Gadget mimc_gadget(pb_mimc, "Mimc5Gadget");

  libsnark::protoboard<Fr> pb_mnist_conv;
  circuit::mnist::ConvGadget<8, 24, 4, 4, 3, 3> mnist_conv_gadget(pb_mnist_conv, "Mnist ConvGadget");

  libsnark::protoboard<Fr> pb_frozenlake_env;
  circuit::frozenlake::EnvGadget gadget(pb_frozenlake_env, "Frozenlake EnvGadget");

  circuit::Preprocess(pb_max4, max4_a, max4_b, max4_c);
  circuit::Preprocess(pb_relu, relu_a, relu_b, relu_c);
  circuit::Preprocess(pb_mimc, clink::mimc_a, clink::mimc_b, clink::mimc_c);
  circuit::Preprocess(pb_rlbn, clink::vgg16::rlbn_a, clink::vgg16::rlbn_b, clink::vgg16::rlbn_c);
  circuit::Preprocess(pb_pool, clink::vgg16::pool_a, clink::vgg16::pool_b, clink::vgg16::pool_c);
  circuit::Preprocess(pb_mnist_conv, clink::mnist::conv_a, clink::mnist::conv_b, clink::mnist::conv_c);
  circuit::Preprocess(pb_frozenlake_env, clink::frozenlake::env_a, clink::frozenlake::env_b, clink::frozenlake::env_c);
}

std::unique_ptr<tbb::task_scheduler_init> tbb_init;

int main(int argc, char *argv[]){
  size_t m = atoi(argv[1]);
  size_t n = atoi(argv[2]);
  size_t k = atoi(argv[3]);
  size_t thread = atoi(argv[4]);
  std::cout << "m:" << m << "\n";

  InitAll(".");
  Preprocess();

  tbb_init = parallel::InitTbb(thread);

  Eigen::initParallel();
  Eigen::setNbThreads(thread);
  std::cout << "Eigen intends to use "
            << Eigen::nbThreads()
            << " threads\n";

  //vgg16测试
  bool ret = true;
  ret &= clink::vgg16::Test();

  // ret &= clink::mnist::Mnist::Test();

  // ret &= clink::frozenlake::FrozenLake::TestModel();
  // ret &= clink::frozenlake::FrozenLake::TestEnv();
  // ret &= clink::frozenlake::FrozenLake::Test();

  // ret &= clink::Pod::Test(14, m);

  // ret &= circuit::frozenlake::EnvTest();

    // ret &= argument::A6::Test(m, n, k);
  // ret &= argument::A61::Test(m, n, k);
  // ret &= argument::A62::Test(m, n, k);
  // ret &= argument::A63::Test(m, n, k);
  // ret &= argument::A8::Test(m);
  // ret &= argument::A9::Test(m, n);
  std::cout << "success:" << ret << "\n\n";
  std::cout << "process consumes " << get_peak_memory_by_pid(getpid()) / 1024.0 << "MB memory" << std::endl;

  return ret;
}
