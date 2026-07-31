#include "public.h"
#include "clink/frozenlake/frozenlake.h"
#include "clink/pong/pong.h"
#include "clink/flappybird/flappybird.h"
#include "clink/pod.h"

bool BIG_MODE = false;
bool DEBUG_CHECK = false;
bool DISABLE_TBB = false;

std::vector<std::vector<Fr>> max4_a, max4_b, max4_c;
std::vector<std::vector<Fr>> relu_a, relu_b, relu_c;

bool InitAll(std::string const& data_dir) {
  InitEcc();
  std::string const kFileName = BIG_MODE ? "pds_pub_big.bin" : "pds_pub.bin";
  auto ecc_pds_file = data_dir + "/" + kFileName;
  if (!pc::OpenOrCreatePdsPub(ecc_pds_file)) {
    std::cerr << "Open or create pds pub file " << ecc_pds_file << " failed\n";
    return false;
  }
  return true;
}

decltype(parallel::InitTbb(0)) tbb_init;

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <test_name> [args...]\n";
    std::cerr << "  frozenlake <max_steps>\n";
    std::cerr << "  pong <max_steps>\n";
    std::cerr << "  flappybird <max_steps>\n";
    std::cerr << "  flappybird_phase1 <max_steps> [output_dir]  - Generate trajectory only\n";
    std::cerr << "  flappybird_phase2 [input_dir]               - Compute commitment only\n";
    std::cerr << "  flappybird_phase3 [input_dir]               - Generate proof only\n";
    std::cerr << "  flappybird_phase4 [input_dir]               - Verify proof only\n";
    std::cerr << "  flappybird_summary [input_dir]              - Print summary\n";
    std::cerr << "  pod <key_count>\n";
    return 1;
  }

  std::string test_name = argv[1];
  size_t max_steps = 0;
  size_t block_len = 0;
  std::string phase_dir = ".";
  
  if (test_name == "pod") {
    if (argc < 3) {
      std::cerr << "Usage: " << argv[0] << " pod <key_count>\n";
      return 1;
    }
    block_len = atoi(argv[2]);
    std::cout << "test: " << test_name << ", block_len: " << block_len << "\n";
  } else if (test_name == "flappybird_phase1") {
    if (argc < 3) {
      std::cerr << "Usage: " << argv[0] << " flappybird_phase1 <max_steps> [output_dir]\n";
      return 1;
    }
    max_steps = atoi(argv[2]);
    if (argc >= 4) phase_dir = argv[3];
    std::cout << "test: " << test_name << ", max_steps: " << max_steps << ", output_dir: " << phase_dir << "\n";
  } else if (test_name == "flappybird_phase2" || test_name == "flappybird_phase3" || 
             test_name == "flappybird_phase4" || test_name == "flappybird_summary") {
    if (argc >= 3) phase_dir = argv[2];
    std::cout << "test: " << test_name << ", input_dir: " << phase_dir << "\n";
  } else {
    if (argc < 3) {
      std::cerr << "Usage: " << argv[0] << " " << test_name << " <max_steps>\n";
      return 1;
    }
    max_steps = atoi(argv[2]);
    std::cout << "test: " << test_name << ", max_steps: " << max_steps << "\n";
  }

  // Set PDS size based on the environment's variable count + 5
  if (test_name == "frozenlake") {
    pc::Base::SetGSize(3400);       // 3395 variables + 5
  } else if (test_name == "pong") {
    pc::Base::SetGSize(522891);     // 522886 variables + 5
  } else if (test_name == "flappybird" || test_name.find("flappybird_phase") == 0 || test_name == "flappybird_summary") {
    pc::Base::SetGSize(12410132);   // 12410127 variables + 5
  }

  // Try multiple paths for pds_pub.bin
  std::vector<std::string> data_dirs = {"../data", "../../data", "data"};
  bool init_ok = false;
  std::string used_data_dir;
  for (auto const& dir : data_dirs) {
    if (InitAll(dir)) {
      init_ok = true;
      used_data_dir = dir;
      break;
    }
  }
  if (!init_ok) {
    std::cerr << "Failed to initialize with any data directory\n";
    return 1;
  }

  // Get CRS file size
  std::string crs_file = used_data_dir + "/" + (BIG_MODE ? "pds_pub_big.bin" : "pds_pub.bin");
  struct stat crs_stat;
  size_t crs_size_bytes = 0;
  if (stat(crs_file.c_str(), &crs_stat) == 0) {
    crs_size_bytes = crs_stat.st_size;
  }
  std::cout << "crs_size:          " << crs_size_bytes << " bytes\n";

  tbb_init = parallel::InitTbb(0);

  if (test_name == "frozenlake") {
    clink::frozenlake::IteratedFunctionProof(max_steps);
  } else if (test_name == "pong") {
    clink::pong::IteratedFunctionProof(max_steps);
  } else if (test_name == "flappybird") {
    clink::flappybird::IteratedFunctionProof(max_steps);
  } else if (test_name == "flappybird_phase1") {
    clink::flappybird::GenerateTrajectoryPhase(max_steps, "", phase_dir);
  } else if (test_name == "flappybird_phase2") {
    clink::flappybird::ComputeCommitmentPhase(phase_dir);
  } else if (test_name == "flappybird_phase3") {
    clink::flappybird::GenerateProofPhase(phase_dir);
  } else if (test_name == "flappybird_phase4") {
    clink::flappybird::VerifyProofPhase(phase_dir);
  } else if (test_name == "flappybird_summary") {
    clink::flappybird::PrintSummary(phase_dir);
  } else if (test_name == "pod") {
    clink::Pod::TestKey(block_len);
  } else {
    std::cerr << "Unknown test: " << test_name << "\n";
    return 1;
  }


  misc::PrintMemoryUsage();

  return 0;
}
