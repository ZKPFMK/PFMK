#include "ecc/ecc.h"

struct ElgamalCipher{
    std::array<G1,2> c;

    ElgamalCipher operator*(Fr const& a) const{
        ElgamalCipher ret;
        ret.c[0] = c[0] * a;
        ret.c[1] = c[1] * a;
        return ret;
    }

    ElgamalCipher operator+(ElgamalCipher const& right) const{
        ElgamalCipher ret;
        ret.c[0] = c[0] + right.c[0];
        ret.c[1] = c[1] + right.c[1];
        return ret;
    }

    static Fr Decrypt(Fr sk, ElgamalCipher const& cph, size_t block_len){
        G1 msg = cph.c[1] - cph.c[0] * sk;
        for(size_t i=0; i<(1 << block_len); i++){
            if(pc::PcG(0) * i == msg){
                return i;
            }
        }
        return FrZero()-1;
    }

    static ElgamalCipher Encrypt(G1 pk, Fr msg, Fr rnd){
        ElgamalCipher cipher;
        cipher.c[0] = pc::PcG(0) * rnd;
        cipher.c[1] = pk * rnd + pc::PcG(0) * msg;
        return cipher;
    }

    bool operator==(ElgamalCipher const& right) const {
        return c == right.c;
    }
    bool operator!=(ElgamalCipher const& right) const { return !(*this == right); }

    template <typename Ar>
    void serialize(Ar& ar) const {
        ar& YAS_OBJECT_NVP("elc.p", ("c", c));
    }

    template <typename Ar>
    void serialize(Ar& ar) {
        ar& YAS_OBJECT_NVP("elc.p", ("c", c));
    }
};