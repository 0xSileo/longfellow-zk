// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "circuits/compiler/compiler.h"

#include <stddef.h>

#include <memory>

#include "algebra/fp.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<1> Field;
const Field F("18446744073709551557");

TEST(Compiler, OutputAnInput) {
  // screw case of outputting an input wire directly
  QuadCircuit<Field> Q(F);

  size_t a = Q.input();
  size_t b = Q.input();
  size_t c = Q.input();

  Q.output(a, 0);
  // add some depth
  Q.output(Q.mul(b, c), 1);

  auto CIRCUIT = Q.mkcircuit(1);
  EXPECT_EQ(Q.nwires_,
            /*one=*/1 + /*inputs=*/3 + /*mul(b,c)=*/1 + /*copy(a)*/ 1);
}

TEST(Compiler, AliasOfLinearAndCopyWire) {
  // Screw case creating an explicit linear term 1*n
  // at the same time as n is copied by the scheduler
  QuadCircuit<Field> Q(F);

  size_t a = Q.input();
  Q.output(a, 0);
  Q.output(Q.linear(a), 1);
  auto CIRCUIT = Q.mkcircuit(1);
  dump_info<Field>("AliasOfLinearAndCopyWire", Q);
  EXPECT_EQ(Q.nwires_,
            /*one*/ 1 + /*a*/ 1 + /*copy of a at d=2*/ 1 + /*linear(a)=*/1);
}

TEST(Compiler, Assert0) {
  QuadCircuit<Field> Q(F);

  // circuit verifies that a + b = c
  size_t a = Q.input();
  size_t b = Q.input();
  size_t c = Q.input();

  Q.assert0(Q.sub(Q.add(a, b), c));

  size_t nc = 1;
  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info<Field>("assert0", Q);

  Dense<Field> W(nc, 1 + 3);
  W.v_[0] = F.one();
  W.v_[1] = F.of_scalar(3);
  W.v_[2] = F.of_scalar(5);
  W.v_[3] = F.of_scalar(8);

  // no outputs
  Proof<Field> pr(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W.clone(), &pr, F);
  run_verifier<Field>(CIRCUIT.get(), W.clone(), pr, F);
}

TEST(Compiler, Output0) {
  QuadCircuit<Field> Q(F);

  size_t a = Q.konst(F.two());
  size_t b = Q.konst(F.one());
  size_t c = Q.mul(a, b);
  size_t d = Q.sub(a, c);
  Q.output(d, 0);

  size_t nc = 1;
  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info<Field>("output0", Q);

  EXPECT_EQ(Q.ninput_, 1);
  EXPECT_EQ(Q.noutput_, 1);
  EXPECT_EQ(Q.nwires_, 1);
  EXPECT_EQ(Q.nquad_terms_, 0);
}

}  // namespace
}  // namespace proofs
