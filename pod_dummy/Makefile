#for linux(ubuntu18)
#sudo apt-get install libcrypto++-dev
#sudo apt-get install libboost-all-dev
#sudo apt install libtbb-dev

#for mac
#brew install libcryptopp
#brew install boost
#brew install tbb

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
	OS_TYPE := Darwin
	CXX11_HOME := /opt/homebrew
	CRYPTOPP_HOME := /opt/homebrew/opt/cryptopp
	BOOST_HOME := /opt/homebrew/opt/boost
	EIGEN_HOME := /opt/homebrew/opt/eigen
else ifeq ($(UNAME),Linux)
	OS_TYPE := Linux
	CXX11_HOME := /usr
else
	OS_TYPE := Unknown
	CXX11_HOME := /usr
endif

HOME = ../linux
THIRD_PARTY_HOME = ../thirdparty
YAS_HOME = ../thirdparty/yas/include
CSV_HOME = ../thirdparty/csv
PUB_HOME = ../public
SNARK_HOME = ../depends/libsnark
FF_HOME = $(SNARK_HOME)/depends/libff
FQFFT_HOME = $(SNARK_HOME)/depends/libfqfft
MCL_HOME = $(SNARK_HOME)/depends/mcl

CXXFLAGS := \
 -g3 \
 -fPIC \
 -std=c++17 \
 -Wall \
 -Wextra \
 -gdwarf-2 \
 -gstrict-dwarf \
 -Wno-parentheses \
 -Wdeprecated-declarations \
 -fmerge-all-constants  \
 -march=native \
 -mtune=native \
 -I $(CXX11_HOME)/include \
 -isystem $(SNARK_HOME) \
 -isystem $(MCL_HOME)/include \
 -isystem $(FF_HOME) \
 -isystem $(FQFFT_HOME) \
 -isystem $(YAS_HOME) \
 -isystem $(CSV_HOME) \
 -isystem $(THIRD_PARTY_HOME) \
 -I $(PUB_HOME) \
 -I. \
 -I.. \

ifeq ($(OS_TYPE),Darwin)
  CXXFLAGS += -isystem $(CRYPTOPP_HOME)/include -isystem $(BOOST_HOME)/include -isystem $(EIGEN_HOME)/include/eigen3
else
  CXXFLAGS += -fopenmp
endif

MCL_FLAGS := \
 -DMCL_DONT_USE_OPENSSL

BOOST_FLAGS := \
 -DBOOST_SPIRIT_THREADSAFE 

SNARK_FLAGS = \
 -DBN_SUPPORT_SNARK=1 \
 -DNO_PT_COMPRESSION=1 \
 -DCURVE_MCL_BN128 \
 -DUSE_ASM \
 -DNO_PROCPS \
 -DUSE_MCL_FR_DIRECTLY \

RELEASE_FLAGS := \
 -O3 \
 -DNDEBUG \
 -DLINUX \

DEBUG_FLAGS := \
 -O0 \
 -D_DEBUG \
 -DDEBUG \
 -DLINUX \
 
LDFLAGS += \
 -fmerge-all-constants

ifeq ($(OS_TYPE),Linux)
  LDFLAGS += -fopenmp
else ifeq ($(OS_TYPE),Darwin)
  LDFLAGS += -L/opt/homebrew/lib
endif

LIBS := \
 -lpthread \
 -lrt \
 -lgmpxx \
 -lgmp \
 -lcryptopp \
 -lboost_filesystem \
 -lboost_iostreams \
 -lboost_program_options \
 -ltbb \
 -ltbbmalloc_proxy \
 -ltbbmalloc \

ifeq ($(OS_TYPE),Darwin)
  TMPVAR := $(LIBS)
  LIBS := $(filter-out -lrt, $(TMPVAR))
endif

BUILD := ./build/self
BUILDPUB := ./build/public

$(shell mkdir -p $(HOME)/bin)
$(shell mkdir -p $(BUILD))
$(shell mkdir -p $(BUILDPUB)/ecc)

DIR := . 

SRC := $(foreach d, $(DIR), $(wildcard $(d)/*.cc))
SRC += ../public/ecc/ecc.cc
RELEASE_OBJ := $(patsubst %.cc, %.o, $(SRC))
DEBUG_OBJ := $(patsubst %.cc, %.d.o, $(SRC))
RELEASE_BIN := pod_dummy
DEBUG_BIN := pod_dummyd
CXX := g++

all: $(RELEASE_BIN) $(DEBUG_BIN)

release: $(RELEASE_BIN)
debug: $(DEBUG_BIN)

%.o : %.cc
	$(CXX) -c $^ $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) -o $(BUILD)/$@

%.d.o : %.cc
	$(CXX) -c $^ $(CXXFLAGS) $(DEBUG_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) -o $(BUILD)/$@

$(DEBUG_BIN) : $(DEBUG_OBJ)
	$(CXX) $(addprefix $(BUILD)/, $^) $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

$(RELEASE_BIN) : $(RELEASE_OBJ)
	$(CXX) $(addprefix $(BUILD)/, $^) $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

clean:
	find . -name "*.o" -delete
	rm -rf $(HOME)/bin/$(RELEASE_BIN) $(HOME)/bin/$(DEBUG_BIN)
	rm -rf build

# ==================== Google Test ====================
GTEST_HOME = $(SNARK_HOME)/depends/gtest/googletest
GTEST_CXXFLAGS = -isystem $(GTEST_HOME)/include
GTEST_SRC = $(GTEST_HOME)/src/gtest-all.cc
GTEST_MAIN_SRC = $(GTEST_HOME)/src/gtest_main.cc
TEST_DIR = tests

$(BUILD)/gtest-all.o : $(GTEST_SRC)
	$(CXX) -c $^ $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -I$(GTEST_HOME) -o $@

$(BUILD)/gtest_main.o : $(GTEST_MAIN_SRC)
	$(CXX) -c $^ $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -I$(GTEST_HOME) -o $@

# Common dependencies
ECC_DEPS = ../public/ecc/ecc.h ../public/ecc/funcs.h ../public/ecc/multiexp.h ../public/ecc/pc_base.h ../public/misc/misc.h ../public/misc/funcs.h

$(BUILD)/../public/ecc/ecc.test.o : ../public/ecc/ecc.cc $(ECC_DEPS)
	@mkdir -p $(BUILD)/../public/ecc
	$(CXX) -c $< $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

# ==================== FrozenLake R1CS Test ====================
TEST_FL_R1CS_SRC = $(TEST_DIR)/frozenlake_r1cs_test.cc
TEST_FL_R1CS_OBJ = $(BUILD)/frozenlake_r1cs_test.o
TEST_FL_R1CS_BIN = frozenlake_r1cs_test
TEST_FL_R1CS_DEPS = ../public/circuit/frozenlake/dqn_env_gadget.h ../public/circuit/frozenlake/env_gadget.h

$(TEST_FL_R1CS_OBJ) : $(TEST_FL_R1CS_SRC) $(TEST_FL_R1CS_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(DEBUG_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

$(TEST_FL_R1CS_BIN) : $(TEST_FL_R1CS_OBJ) $(BUILD)/gtest-all.o $(BUILD)/gtest_main.o $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_frozenlake_r1cs: $(TEST_FL_R1CS_BIN)

test_frozenlake_r1cs: $(TEST_FL_R1CS_BIN)
	$(HOME)/bin/$(TEST_FL_R1CS_BIN)

# ==================== Pong DQN Env Game Test ====================
TEST_PONG_DQN_ENV_GAME_SRC = $(TEST_DIR)/pong_dqn_env_game_test.cc
TEST_PONG_DQN_ENV_GAME_OBJ = $(BUILD)/pong_dqn_env_game_test.o
TEST_PONG_DQN_ENV_GAME_BIN = pong_dqn_env_game_test
TEST_PONG_DQN_ENV_GAME_DEPS = ../public/circuit/pong/dqn_env_gadget.h ../public/circuit/pong/render/render_gadget.h ../public/circuit/pong/dqn/dqn_gadget.h ../public/circuit/pong/env/env_gadget.h

$(TEST_PONG_DQN_ENV_GAME_OBJ) : $(TEST_PONG_DQN_ENV_GAME_SRC) $(TEST_PONG_DQN_ENV_GAME_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

$(TEST_PONG_DQN_ENV_GAME_BIN) : $(TEST_PONG_DQN_ENV_GAME_OBJ) $(BUILD)/gtest-all.o $(BUILD)/gtest_main.o $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_pong_dqn_env_game: $(TEST_PONG_DQN_ENV_GAME_BIN)

test_pong_dqn_env_game: $(TEST_PONG_DQN_ENV_GAME_BIN)
	$(HOME)/bin/$(TEST_PONG_DQN_ENV_GAME_BIN)

# ==================== Flappy Bird Render Test ====================
TEST_FB_RENDER_SRC = $(TEST_DIR)/flappybird_render_test.cc
TEST_FB_RENDER_OBJ = $(BUILD)/flappybird_render_test.o
TEST_FB_RENDER_BIN = flappybird_render_test
TEST_FB_RENDER_DEPS = ../public/circuit/flappybird/render/render_gadget.h ../public/circuit/flappybird/render/range_flag_gadget.h ../public/circuit/basic/abs_gadget.h

$(TEST_FB_RENDER_OBJ) : $(TEST_FB_RENDER_SRC) $(TEST_FB_RENDER_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(DEBUG_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

$(TEST_FB_RENDER_BIN) : $(TEST_FB_RENDER_OBJ) $(BUILD)/gtest-all.o $(BUILD)/gtest_main.o $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_flappybird_render: $(TEST_FB_RENDER_BIN)

test_flappybird_render: $(TEST_FB_RENDER_BIN)
	$(HOME)/bin/$(TEST_FB_RENDER_BIN)

# ==================== Flappy Bird DQN Env Game Test ====================
TEST_FB_DQN_ENV_GAME_SRC = $(TEST_DIR)/flappybird_dqn_env_game_test.cc
TEST_FB_DQN_ENV_GAME_OBJ = $(BUILD)/flappybird_dqn_env_game_test.o
TEST_FB_DQN_ENV_GAME_BIN = flappybird_dqn_env_game_test
TEST_FB_DQN_ENV_GAME_DEPS = ../public/circuit/flappybird/dqn_env_gadget.h ../public/circuit/flappybird/render/render_gadget.h ../public/circuit/flappybird/dqn/dqn_gadget.h ../public/circuit/flappybird/env/env_gadget.h

$(TEST_FB_DQN_ENV_GAME_OBJ) : $(TEST_FB_DQN_ENV_GAME_SRC) $(TEST_FB_DQN_ENV_GAME_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

$(TEST_FB_DQN_ENV_GAME_BIN) : $(TEST_FB_DQN_ENV_GAME_OBJ) $(BUILD)/gtest-all.o $(BUILD)/gtest_main.o $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_flappybird_dqn_env_game: $(TEST_FB_DQN_ENV_GAME_BIN)

test_flappybird_dqn_env_game: $(TEST_FB_DQN_ENV_GAME_BIN)
	$(HOME)/bin/$(TEST_FB_DQN_ENV_GAME_BIN)

# ==================== zkfrozenlake ====================
ZKFL_SRC = zkfrozenlake.cc
ZKFL_OBJ = $(BUILD)/zkfrozenlake.o
ZKFL_OBJ_RELEASE = $(BUILD)/zkfrozenlake.release.o
ZKFL_BIN = zkfrozenlake
ZKFL_DEPS = ../public/clink/frozenlake/frozenlake.h

# Debug build (default)
$(ZKFL_OBJ) : $(ZKFL_SRC) $(ZKFL_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(DEBUG_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) -o $@

$(ZKFL_BIN) : $(ZKFL_OBJ) $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_zkfrozenlake: $(ZKFL_BIN)

# Release build with maximum optimization (-O3, -DNDEBUG, -march=native, -flto)
$(ZKFL_OBJ_RELEASE) : $(ZKFL_SRC) $(ZKFL_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(RELEASE_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) -fno-omit-frame-pointer -o $@

$(ZKFL_BIN)_release : $(ZKFL_OBJ_RELEASE) $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$(ZKFL_BIN) $(LDFLAGS) $(LIBS) -flto

build_zkfrozenlake_release: $(ZKFL_BIN)_release

# ==================== Multi-Range Copy Constraint Test ====================
TEST_MULTI_RANGE_SRC = $(TEST_DIR)/multi_range_copy_constraint_test.cc
TEST_MULTI_RANGE_OBJ = $(BUILD)/multi_range_copy_constraint_test.o
TEST_MULTI_RANGE_BIN = multi_range_copy_constraint_test
TEST_MULTI_RANGE_DEPS = ../public/argument/a10.h ../public/argument/a12.h

$(TEST_MULTI_RANGE_OBJ) : $(TEST_MULTI_RANGE_SRC) $(TEST_MULTI_RANGE_DEPS)
	$(CXX) -c $< $(CXXFLAGS) $(DEBUG_FLAGS) $(MCL_FLAGS) $(SNARK_FLAGS) $(BOOST_FLAGS) $(GTEST_CXXFLAGS) -o $@

$(TEST_MULTI_RANGE_BIN) : $(TEST_MULTI_RANGE_OBJ) $(BUILD)/gtest-all.o $(BUILD)/gtest_main.o $(BUILD)/../public/ecc/ecc.test.o
	$(CXX) $^ $(MCL_HOME)/lib/libmcl.a -o $(HOME)/bin/$@ $(LDFLAGS) $(LIBS)

build_multi_range_copy_constraint: $(TEST_MULTI_RANGE_BIN)

test_multi_range_copy_constraint: $(TEST_MULTI_RANGE_BIN)
	$(HOME)/bin/$(TEST_MULTI_RANGE_BIN)

.PHONY: clean all release debug build_frozenlake_r1cs test_frozenlake_r1cs build_pong_dqn_env_game test_pong_dqn_env_game build_flappybird_render test_flappybird_render build_flappybird_dqn_env_game test_flappybird_dqn_env_game build_zkfrozenlake build_multi_range_copy_constraint test_multi_range_copy_constraint
