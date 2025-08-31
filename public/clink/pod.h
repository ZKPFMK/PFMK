#pragma once

#include "./details.h"
#include "utils/Elgamal.h"
#include "argument/a7.h"
#include "circuit/mimc5_gadget.h"

namespace clink {
std::vector<std::vector<Fr>> mimc_a, mimc_b, mimc_c;
Fr sk_sel, sk_buy, sk;
G1 pk_sel, pk_buy, pk;

struct Pod {

  struct KeyProof{
    // enc_b: 比特的密文
    // com_b: 比特的承诺
    G1 com_b, com_d;
    G1 com_a, com_t0, com_t1;
    std::vector<ElgamalCipher> enc_b_block, enc_d_block;


    std::vector<Fr> z, r_enc_z;
    Fr r_com_z, r_com_u, r_com_t;

    bool operator==(KeyProof const& right) const {
        return com_d == right.com_d && com_b == right.com_b && com_a == right.com_a &&
               com_t1 == right.com_t1 && com_t0 == right.com_t0 && enc_b_block == right.enc_b_block && 
               enc_d_block == right.enc_d_block && z == right.z && r_com_z == right.r_com_z && r_com_u == right.r_com_u && r_com_t == right.r_com_t;
               
    }
    bool operator!=(KeyProof const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
        ar& YAS_OBJECT_NVP("ky.p", ("cd", com_d), ("cb", com_b), ("ca", com_a), ("t0", com_t0),
                                   ("t1", com_t1), ("eb", enc_b_block), ("ed", enc_d_block), ("ez", r_enc_z),
                                   ("fz", z), ("fu", r_com_u), ("rz", r_com_z), ("rt", r_com_t));
    }

    template <typename Ar>
    void serialize(Ar& ar) {
        ar& YAS_OBJECT_NVP("ky.p", ("cd", com_d), ("cb", com_b), ("ca", com_a), ("t0", com_t0),
                                   ("t1", com_t1), ("eb", enc_b_block), ("ed", enc_d_block), ("ez", r_enc_z),
                                   ("fz", z), ("fu", r_com_u), ("rz", r_com_z), ("rt", r_com_t));
    }
  };

  struct CommitedData {
    std::vector<Fr> d;
    Fr r_com_d;
    G1  com_d;
    CommitedData(){}
    CommitedData(std::vector<Fr> const& d, Fr const& r_com_d, G1 const& com_d)
      :d(d), r_com_d(r_com_d), com_d(com_d) {
    }
  };

  struct MimcProof {
    std::vector<G1> com_w; // r1cs证据承诺
    argument::A7::Proof r1cs_proof;

     bool operator==(MimcProof const& b) const {
      return com_w == b.com_w && r1cs_proof == b.r1cs_proof;
    }

    bool operator!=(MimcProof const& b) const { return !(*this == b); }

    template <typename Ar>
    void serialize(Ar& ar) const {
      ar& YAS_OBJECT_NVP("enc.p", ("w", com_w), ("p", r1cs_proof));
    }

    template <typename Ar>
    void serialize(Ar& ar) {
      ar& YAS_OBJECT_NVP("enc.p", ("w", com_w), ("p", r1cs_proof));
    }
  };

  struct Secret {
    Fr key;
    Fr r_com_key;
    G1 g;
    G1 com_key;

    
    Fr r_com_b;
    std::vector<Fr> b;

    std::vector<Fr> b_block;
    std::vector<Fr> r_enc_b_block;
  };

  static std::vector<Fr> DivideBlock(std::vector<Fr> const& b, size_t block_len){
    size_t num = b.size() / block_len + (b.size() % block_len == 0 ? 0 : 1);
    std::vector<Fr> ret(num);
    for(int i=0; i<num; i++){
      Fr block = 0;
      size_t l = i * block_len;
      for(size_t j=0; j<block_len && l<b.size(); j++, l++){
        block += b[l] * (1 << j);
      }
      ret[i] = block;
    }
    return ret;
  }

  static void EncryptAndCom(Secret & secret, KeyProof & proof, size_t block_len){
    size_t len = 254, num = len / block_len + (len % block_len == 0 ? 0 : 1);

    Fr k = secret.key;
    secret.b.resize(len, FrZero());
    for(int i=0; i<len; i++){
        if(k.isOdd()){
          secret.b[i] = 1;
          k = k - 1; 
        }
        k = k / 2;
        if(k == FrZero()) break;
    }

    secret.r_com_b = FrRand();
    proof.com_b = pc::ComputeCom(secret.b, secret.r_com_b);

    proof.enc_b_block.resize(num);
    secret.r_enc_b_block.resize(num);
    secret.b_block = DivideBlock(secret.b, block_len);

    FrRand(secret.r_enc_b_block);
    for(int i=0; i<num; i++){
      proof.enc_b_block[i] = ElgamalCipher::Encrypt(pk, secret.b_block[i], secret.r_enc_b_block[i]);
    }
    
  }

  static void DoKeyProve(h256_t seed, Secret & secret, KeyProof & proof, size_t block_len){
    Tick tick(__FN__);
    size_t len = 254, num = secret.b_block.size();

    Fr r_com_d = FrRand();
    std::vector<Fr> d(len);
    FrRand(d);
    proof.com_d = pc::ComputeCom(d, r_com_d);

    std::vector<Fr> r_enc_d_block(num);
    std::vector<Fr> d_block = DivideBlock(d, block_len);
    FrRand(r_enc_d_block);

    proof.enc_d_block.resize(num);
    for(size_t i=0; i<num; i++){
      proof.enc_d_block[i] = ElgamalCipher::Encrypt(pk, d_block[i], r_enc_d_block[i]);
    }

    Fr a = 0, pw = 1, r_com_a = FrRand();
    for(size_t i=0; i<len; i++, pw *= 2){
      a += pw * d[i];
    }
    proof.com_a = secret.g * a + pc::PcH() * r_com_a;
  

    std::vector<Fr> t0 = HadamardProduct(d, d);
    std::vector<Fr> t1 = HadamardProduct(d, secret.b * Fr(2)) - d;
    Fr r_com_t0 = FrRand(), r_com_t1 = FrRand();
    proof.com_t0 = pc::ComputeCom(t0, r_com_t0);
    proof.com_t1 = pc::ComputeCom(t1, r_com_t1);

    UpdateSeed(seed, proof.com_t0, proof.com_t1, proof.com_a);
    Fr e = H256ToFr(seed);

    proof.z = d + secret.b * e;
    proof.r_com_z = r_com_d + secret.r_com_b * e;
    proof.r_com_t = r_com_t0 + r_com_t1 * e;
    proof.r_com_u = r_com_a + secret.r_com_key * e;
    proof.r_enc_z = r_enc_d_block + secret.r_enc_b_block * e;
  }

  static void KeyProve(KeyProof &proof, h256_t seed, Secret & secret, size_t block_len){
    Tick tick(__FN__);

    EncryptAndCom(secret, proof, block_len);
    
    DoKeyProve(seed, secret, proof, block_len);
  }

  static bool KeyVerify(h256_t seed, size_t n, G1 const& com_k, KeyProof const& proof, size_t block_len){
    Tick tick(__FN__);
    size_t len = 254;
    G1 g = pc::ComputeSigmaG(0, n);

    UpdateSeed(seed, proof.com_t0, proof.com_t1, proof.com_a);
    Fr e = H256ToFr(seed);

    bool ret = (proof.com_d + proof.com_b * e == pc::ComputeCom(proof.z, proof.r_com_z));
    ret &= (proof.com_t0 + proof.com_t1 * e == pc::ComputeCom(
        HadamardProduct(proof.z, proof.z - std::vector<Fr>(proof.z.size(), e)),
        proof.r_com_t
      ));
    Fr pw = 1, u = 0;
    for(size_t i=0; i<len; i++, pw*=2){
      u += pw * proof.z[i];
    }
    ret &= (proof.com_a + com_k * e == g * u + pc::PcH() * proof.r_com_u);

    std::vector<Fr> z_block = DivideBlock(proof.z, block_len);
    for(size_t i=0; i<proof.enc_d_block.size(); i++){
      ret &= (proof.enc_d_block[i] + proof.enc_b_block[i] * e == ElgamalCipher::Encrypt(pk, z_block[i], proof.r_enc_z[i]));
    }
    return ret;
  }

  static void EncryptAndProve(MimcProof & proof, h256_t seed,
                              Secret & secret,
                              CommitedData & commited_cipher,
                              CommitedData const& commited_data) {
    Tick _tick_(__FN__);
    auto n = commited_data.d.size();
    
    secret.key = FrRand();
    std::vector<Fr> plain(n); //ctr_i = Hash(nonce || i), 计数器
    ComputeFst(seed, "pod::nonce", plain);
    
    std::vector<G1> com_w;
    std::vector<std::vector<Fr>> w, a, b, c;
    std::vector<Fr> r_com_w, r_com_a, r_com_b, r_com_c;
    
    ComputeMimcWitness(plain, secret.key, w);
    ComputeMimcWitCom(w, r_com_w, com_w);
    UpdateSeed(seed, com_w);
    ComputeWitness(w, mimc_a, mimc_b, mimc_c, a, b, c, r_com_w, r_com_a, r_com_b, r_com_c);
    
    argument::A7::CommitmentSec sec(r_com_a, r_com_b, r_com_c);
    argument::A7::ProveInput input(a, b, c, pc::kGetRefG1);
    argument::A7::Prove(proof.r1cs_proof, seed, input, sec);

    secret.r_com_key = r_com_w[2];
    secret.com_key = com_w[2];
    secret.g = com_w[0];
    
    commited_cipher.r_com_d = r_com_w.back();
    commited_cipher.com_d = com_w.back();
    commited_cipher.d = w.back();

    proof.com_w = com_w;
  }

  static bool VerifyAndBuy(MimcProof const& proof, h256_t seed, int64_t n) {
    Tick _tick_(__FN__);

    std::vector<Fr> plain(n); //ctr_i = Hash(nonce || i), 计数器
    ComputeFst(seed, "pod::nonce", plain);
    UpdateSeed(seed, proof.com_w);

    if (proof.com_w[0] != pc::ComputeSigmaG(0, n)) {
      assert(false);
      return false;
    }

    if (proof.com_w[1] != pc::ComputeCom(plain, 0)) {
      assert(false);
      return false;
    }

    return argument::A7::Verify(n, proof.r1cs_proof, seed, mimc_a, mimc_b, mimc_c, proof.com_w, pc::kGetRefG1);
  }

  static std::vector<Fr> GenerateV(std::vector<Fr> const& plain, Fr const& key) {
    Tick _tick_(__FN__);
    std::vector<Fr> v(plain.size());
    auto parallel_f = [&v, &plain, &key](uint64_t i) {
      v[i] = circuit::Mimc5Enc(plain[i], key);
    };
    parallel::For(v.size(), parallel_f);
    return v;
  }

  static bool Test(int64_t n, int64_t block_len);

  static bool CheckCommitedData(CommitedData const& data) {
    if (!data.d.size() > pc::Base::GSize()) return false;
    return pc::ComputeCom(data.d, data.r_com_d) == data.com_d;
  }

  static void ComputeMimcWitness(std::vector<Fr> const& plain, Fr key, std::vector<std::vector<Fr>> & w){
    Tick tick(__FN__);

    libsnark::protoboard<Fr> pb;
    circuit::Mimc5Gadget mimc_gadget(pb, "Mimc5Gadget");

    size_t m = pb.num_variables(), n = plain.size();

    w.resize(m+1, std::vector<Fr>(n));
    
    auto parallel_f = [&plain, &key, &w](size_t i){
      libsnark::protoboard<Fr> pb; 
      circuit::Mimc5Gadget gadget(pb, "Mimc5Gadget");
      gadget.Assign(plain[i], key);
      CopyRowToLine(w, pb.full_variable_assignment(), i, true);
    };
    parallel::For(n, parallel_f);
  }

  static void ComputeMimcWitCom(std::vector<std::vector<Fr>> const& w,
                                std::vector<Fr> & r_com_w,
                                std::vector<G1> & com_w){
    com_w.resize(w.size()); //0为常量, 1为plain, 2为key
    r_com_w.resize(w.size(), FrZero());
    
    com_w[0] = pc::ComputeSigmaG(0, w[0].size());
    com_w[1] = pc::ComputeCom(w[1], FrZero());

    r_com_w[2] = FrRand();
    com_w[2] =  com_w[0] * w[2][0] + pc::PcH() * r_com_w[2];

    auto parallel_f = [&w, &com_w, &r_com_w](int64_t i) {
      if(i == 0 || i == 1 || i == 2){
        return;
      }else{
        r_com_w[i] = FrRand();
        com_w[i] = pc::ComputeCom(w[i], r_com_w[i]);
      }
    };
    parallel::For(w.size(), parallel_f);
  }
};

bool Pod::Test(int64_t n, int64_t block_len) {
  Tick tick(__FN__);

  CommitedData commited_data;
  commited_data.r_com_d = FrRand();
  commited_data.d.resize(n);
  FrRand(commited_data.d);
  commited_data.com_d = pc::ComputeCom(commited_data.d, commited_data.r_com_d);

  h256_t seed = misc::RandH256();

  // prove
  Secret secret;
  KeyProof key_proof;
  MimcProof enc_proof;
  CommitedData commited_cph;

  EncryptAndProve(enc_proof, seed, secret, commited_cph, commited_data);
  KeyProve(key_proof, seed, secret, block_len);

  // prover send prove_output.proved_data to verifier
#ifndef DISABLE_SERIALIZE_CHECK
  // serialize to buffer
    {
      yas::mem_ostream os;
      yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
      oa.serialize(enc_proof);
      std::cout << "enc proof size: " << os.get_shared_buffer().size << "\n";
      yas::mem_istream is(os.get_intrusive_buffer());
      yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
      MimcProof proof2;
      ia.serialize(proof2);
      if (enc_proof != proof2) {
        assert(false);
        std::cout << "oops, serialize check failed\n";
        return false;
      }
    }

    {
      yas::mem_ostream os;
      yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
      oa.serialize(key_proof);
      std::cout << "key proof size: " << os.get_shared_buffer().size
                << "\n";
      yas::mem_istream is(os.get_intrusive_buffer());
      yas::binary_iarchive<yas::mem_istream, YasBinF()> ia(is);
      KeyProof proof2;
      ia.serialize(proof2);
      if (key_proof != proof2) {
        assert(false);
        std::cout << "oops, serialize check failed\n";
        return false;
      }
    } 
#endif

  if (!VerifyAndBuy(enc_proof, seed, n)) {
    assert(false);
    return false;
  }

  {
    Tick tick("client time");
    if(!KeyVerify(seed, n, secret.com_key, key_proof, block_len)){
      assert(false);
      return false;
    }

    {
      Tick tick("decrypt time");
      Fr pow = 1, decrypt_key = 0;
      for(size_t i=0; i<key_proof.enc_b_block.size(); i++){
        decrypt_key += ElgamalCipher::Decrypt(sk, key_proof.enc_b_block[i], block_len) * pow;
        pow *= (1 << block_len);
      }
      CHECK(decrypt_key == secret.key, "");
    }
  }
  return true;
}

}  // namespace clink