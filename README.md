# zkGoalPay

zkGoalPay is a zero-knowledge payment scheme for model knowledge. This
repository contains a C++ research prototype for proving iterative DQN
inference and environment transitions.

## Supported environments

- **FrozenLake** — a 64-state environment with a three-layer fully connected
  DQN (`64 -> 12 -> 8 -> 4`).
- **Pong** — a compact image-based DQN with three actions.
- **FlappyBird** — an image-based DQN with convolutional and fully connected
  layers.

The model parameters are represented as private witness variables in the R1CS
circuits. FrozenLake parameters are embedded in
`public/clink/frozenlake/frozenlake.h`; Pong and FlappyBird parameters are
stored under `data/`.

## Repository layout

- `public/circuit/` — R1CS gadgets for basic operations, fixed-point
  arithmetic, DQN inference, and environment transitions.
- `public/clink/` — proof construction and verification for the supported
  environments.
- `public/argument/` — argument-system implementations.
- `pod_dummy/` — command-line driver and benchmark script.
- `data/` — DQN parameters and reproducibility inputs for Pong and
  FlappyBird.
- `depends/` and `thirdparty/` — cryptographic and utility dependencies.

## Build

The prototype requires a C++17 compiler, GMP, Crypto++, Boost, TBB, and the
included libsnark/mcl dependencies.

```bash
cd pod_dummy
make build_zkfrozenlake
```

The executable is written to `linux/bin/zkfrozenlake`.

## Run

Run the following commands from `pod_dummy/`:

```bash
../linux/bin/zkfrozenlake frozenlake 10
../linux/bin/zkfrozenlake pong 10
../linux/bin/zkfrozenlake flappybird 10
```

The final argument is the maximum number of environment steps.

To run the benchmark wrapper:

```bash
./benchmark.sh frozenlake 10 20 50 100
./benchmark.sh pong 10 20 50 100
./benchmark.sh flappybird 10 20 50 100
```

## Reference

This prototype builds on [ZKPod](https://github.com/huyuguang/ZkPod3-lib).
