#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include <cassert>
#include <iostream>

#include "algebra/convolution.h"
#include "algebra/fp_p128.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/ecdsa/verify_circuit.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256.h"
#include "proto/circuit.h"
#include "random/random.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/prover.h"
#include "util/log.h"
#include "util/readbuffer.h"
#include "zk/zk_common.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"

namespace proofs {
namespace {

class ZKTest {
  using Nat = Fp256Base::N;
  using Elt = Fp256Base::Elt;
  using Verw = VerifyWitness3<P256, Fp256Scalar>;

 public:
  ZKTest()
      : pkx_(p256_base.of_string("0x88903e4e1339bde78dd5b3d7baf3efdd72eb5bf5aaa"
                                 "f686c8f9ff5e7c6368d9c")),
        pky_(p256_base.of_string("0xeb8341fc38bb802138498d5f4c03733f457ebbafd0b"
                                 "2fe38e6f58626767f9e75")),
        omega_x_(p256_base.of_string("0xf90d338ebd84f5665cfc85c67990e3379fc9563"
                                     "b382a4a4c985a65324b242562")),
        omega_y_(p256_base.of_string("0x4617e1bc436833b35fb03d1dfef91cbf7b8c759"
                                     "c8b2dcd39240be8b09f5bc153")),
        e_("0x2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7a"
           "e"),
        r_("0xc71bcbfb28bbe06299a225f057797aaf5f22669e90475de5f64176b2612671"),
        s_("0x42ad2f2ec7b6e91360b53427690dddfe578c10d8cf480a66a6c2410ff4f6dd4"
           "0") {
    set_log_level(INFO);
    w_ = std::make_unique<Dense<Fp256Base>>(1, circuit1_->ninputs);
    DenseFiller<Fp256Base> filler(*w_);

    Verw vw(p256_scalar, p256);
    vw.compute_witness(pkx_, pky_, e_, r_, s_);
    filler.push_back(p256_base.one());
    filler.push_back(pkx_);
    filler.push_back(pky_);
    filler.push_back(p256_base.to_montgomery(e_));
    vw.fill_witness(filler);

    pub_ = std::make_unique<Dense<Fp256Base>>(1, circuit1_->ninputs);
    DenseFiller<Fp256Base> pubfill(*pub_);
    pubfill.push_back(p256_base.one());
    pubfill.push_back(pkx_);
    pubfill.push_back(pky_);
    pubfill.push_back(p256_base.to_montgomery(e_));
  }

  static void SetUpTestCase() {
    if (circuit1_ == nullptr) {
      using CompilerBackend = CompilerBackend<Fp256Base>;
      using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
      using EltW = typename LogicCircuit::EltW;
      using Verc = VerifyCircuit<LogicCircuit, Fp256Base, P256>;
      QuadCircuit<Fp256Base> Q(p256_base);
      const CompilerBackend cbk(&Q);
      const LogicCircuit lc(&cbk, p256_base);

      Verc verc(lc, p256, n256_order);

      EltW pkx = Q.input(), pky = Q.input(), e = Q.input();
      Q.private_input();
      Verc::Witness vwc;
      vwc.input(Q);
      verc.verify_signature3(pkx, pky, e, vwc);
      circuit1_ = Q.mkcircuit(1).release();
    }
  }

  static void TearDownTestCase() {
    delete circuit1_;
    circuit1_ = nullptr;
  }

  Circuit<Fp256Base>* circuit() const { return circuit1_; }
  Dense<Fp256Base>& witness() const { return *w_; }
  Dense<Fp256Base>& public_input() const { return *pub_; }
  const Elt& omega_x() const { return omega_x_; }
  const Elt& omega_y() const { return omega_y_; }

 private:
  static Circuit<Fp256Base>* circuit1_;
  std::unique_ptr<Dense<Fp256Base>> w_;
  std::unique_ptr<Dense<Fp256Base>> pub_;
  const Elt pkx_, pky_, omega_x_, omega_y_;
  const Nat e_, r_, s_;
};

Circuit<Fp256Base>* ZKTest::circuit1_ = nullptr;

void test_prover_verifier() {
  ZKTest test;
  run2_test_zk(*test.circuit(), test.witness(), test.public_input(),
               p256_base, test.omega_x(), test.omega_y(), 1ull << 31);
}
}  // namespace
}  // namespace proofs

int main() {
  std::cout << "Running ZK tests..." << std::endl;
  proofs::ZKTest::SetUpTestCase();

  proofs::test_prover_verifier();

  proofs::ZKTest::TearDownTestCase();
  std::cout << "All tests passed." << std::endl;
  return 0;
}
