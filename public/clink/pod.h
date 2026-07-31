#pragma once

#include "./details.h"
#include "utils/Elgamal.h"
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

    {
      Tick tick("key to bits");
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
    }

    {
      Tick tick("commit b");
      secret.r_com_b = FrRand();
      proof.com_b = pc::ComputeCom(secret.b, secret.r_com_b);
    }

    {
      Tick tick("encrypt b block");
      proof.enc_b_block.resize(num);
      secret.r_enc_b_block.resize(num);
      secret.b_block = DivideBlock(secret.b, block_len);

      FrRand(secret.r_enc_b_block);
      for(int i=0; i<num; i++){
        proof.enc_b_block[i] = ElgamalCipher::Encrypt(pk, secret.b_block[i], secret.r_enc_b_block[i]);
      }
    }
  }

  static void DoKeyProve(h256_t seed, Secret & secret, KeyProof & proof, size_t block_len){
    Tick tick(__FN__);
    size_t len = 254, num = secret.b_block.size();

    Fr r_com_d = FrRand();
    std::vector<Fr> d(len);
    FrRand(d);

    {
      Tick tick("commit d");
      proof.com_d = pc::ComputeCom(d, r_com_d);
    }

    std::vector<Fr> r_enc_d_block(num);
    std::vector<Fr> d_block = DivideBlock(d, block_len);
    FrRand(r_enc_d_block);

    {
      Tick tick("encrypt d block");
      proof.enc_d_block.resize(num);
      for(size_t i=0; i<num; i++){
        proof.enc_d_block[i] = ElgamalCipher::Encrypt(pk, d_block[i], r_enc_d_block[i]);
      }
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

  static bool KeyVerify(h256_t seed, G1 const& com_k, KeyProof const& proof, size_t block_len){
    Tick tick(__FN__);
    size_t len = 254;

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
    ret &= (proof.com_a + com_k * e == pc::kGetRefG1(0) * u + pc::PcH() * proof.r_com_u);

    std::vector<Fr> z_block = DivideBlock(proof.z, block_len);
    for(size_t i=0; i<proof.enc_d_block.size(); i++){
      ret &= (proof.enc_d_block[i] + proof.enc_b_block[i] * e == ElgamalCipher::Encrypt(pk, z_block[i], proof.r_enc_z[i]));
    }
    return ret;
  }

  static bool TestKey(int64_t block_len);
};  // struct Pod

inline bool Pod::TestKey(int64_t block_len) {
  Tick tick(__FN__);

  h256_t seed = misc::RandH256();

  {
    Tick tick("init keys");
    clink::sk_sel = Fr("1947813665846030422559828600490533160609795549654730157211166665690478441119");
    clink::sk_buy = Fr("19909940428476593807986756695020318192734285490982501092727296391197763088211");
    clink::sk = clink::sk_sel + clink::sk_buy;
    clink::pk_sel = pc::kGetRefG1(0) * clink::sk_sel;
    clink::pk_buy = pc::kGetRefG1(0) * clink::sk_buy;
    clink::pk = clink::pk_sel + clink::pk_buy;
  }

  // prove
  Secret secret;
  KeyProof key_proof;

  {
    Tick tick("encrypt and commit");
    secret.key = sk;
    secret.r_com_key = FrRand();
    secret.g = pc::kGetRefG1(0);
    secret.com_key = pc::ComputeCom(secret.g, secret.key, secret.r_com_key);
  }

  double seller_time_ms = 0;
  double verify_time_ms = 0;
  double decrypt_time_ms = 0;

  {
    auto start = std::chrono::high_resolution_clock::now();
    Tick tick("prove time");
    KeyProve(key_proof, seed, secret, block_len);
    auto end = std::chrono::high_resolution_clock::now();
    seller_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
  }

  // print proof size using serialization
  {
    yas::mem_ostream os;
    yas::binary_oarchive<yas::mem_ostream, YasBinF()> oa(os);
    oa & key_proof;
    size_t proof_size = os.get_intrusive_buffer().size;
    std::cout << "=== Proof Size ===" << std::endl;
    std::cout << "Total proof size (bytes): " << proof_size << std::endl;
    std::cout << "==================" << std::endl;
  }

  {
    auto start = std::chrono::high_resolution_clock::now();
    Tick tick("verify time");
    if(!KeyVerify(seed, secret.com_key, key_proof, block_len)){
      assert(false);
      return false;
    }
    auto end = std::chrono::high_resolution_clock::now();
    verify_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
  }

  {
    auto start = std::chrono::high_resolution_clock::now();
    Tick tick("decrypt time");
    Fr pow = 1, decrypt_key = 0;
    for(size_t i=0; i<key_proof.enc_b_block.size(); i++){
      decrypt_key += ElgamalCipher::Decrypt(sk, key_proof.enc_b_block[i], block_len) * pow;
      pow *= (1 << block_len);
    }
    auto end = std::chrono::high_resolution_clock::now();
    decrypt_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    CHECK(decrypt_key == secret.key, "");
    std::cout << "correct key!" << std::endl;
  }

  double buyer_time_ms = verify_time_ms + decrypt_time_ms;

  std::cout << "=== Time Summary ===" << std::endl;
  std::cout << "seller_time: " << seller_time_ms << " ms" << std::endl;
  std::cout << "buyer_time: " << buyer_time_ms << " ms" << std::endl;
  std::cout << "  (verify: " << verify_time_ms << " ms, decrypt: " << decrypt_time_ms << " ms)" << std::endl;
  std::cout << "====================" << std::endl;

  return true;
}

}  // namespace clink
