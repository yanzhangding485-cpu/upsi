// UPSU Benchmark & Correctness Test

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "examples/upsu/upsu.h"
#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/blake3.h"
#include "yacl/link/test_util.h"

using namespace std;
using namespace upsu;
namespace {

// ── Test data generation ──────────────────────────────────────────

ElemSet MakeSet(size_t base, size_t n) {
  ElemSet out;
  for (size_t i = 0; i < n; ++i)
    out.push_back(yacl::crypto::Blake3_128(std::to_string(base + i)));
  return out;
}

struct TestData {
  ElemSet X, Y;           // initial private sets
  ElemSet U_ground_truth; // initial union
  vector<ElemSet> X_plus, X_minus, Y_plus, Y_minus;  // per-round updates
  vector<ElemSet> U_gt;   // ground-truth union after each round
};

TestData GenerateTestData(size_t n, size_t add_n, size_t sub_n, size_t rounds) {
  // X = [0 .. n-1]
  // Y = [n/2 .. 3n/2-1]  → overlap = n/2
  TestData d;
  d.X = MakeSet(0, n);
  d.Y = MakeSet(n / 2, n);

  set<Element> u0(d.X.begin(), d.X.end());
  u0.insert(d.Y.begin(), d.Y.end());
  d.U_ground_truth = ElemSet(u0.begin(), u0.end());

  set<Element> X_cur(d.X.begin(), d.X.end());
  set<Element> Y_cur(d.Y.begin(), d.Y.end());
  set<Element> U_cur = u0;

  for (size_t r = 0; r < rounds; ++r) {
    // Generate additions and deletions with known ground truth
    size_t add_base = (r + 2) * n + add_n;
    size_t sub_off  = (r * sub_n) % n;

    ElemSet xp, xm, yp, ym;

    // X additions: fresh elements, disjoint from X_cur
    xp = MakeSet(add_base, add_n);
    // X deletions: remove some existing elements
    for (size_t i = 0; i < sub_n; ++i) {
      xm.push_back(yacl::crypto::Blake3_128(std::to_string(sub_off + i)));
    }

    // Y additions: fresh elements, disjoint from Y_cur
    size_t y_add_base = add_base + add_n;
    yp = MakeSet(y_add_base, add_n);
    // Y deletions: remove some elements
    for (size_t i = 0; i < sub_n; ++i) {
      size_t idx = n / 2 + sub_off + i;
      if (idx < n / 2 + n) {
        ym.push_back(yacl::crypto::Blake3_128(std::to_string(idx)));
      }
    }

    d.X_plus.push_back(xp);
    d.X_minus.push_back(xm);
    d.Y_plus.push_back(yp);
    d.Y_minus.push_back(ym);

    // Update ground truth
    for (auto x : xm) { X_cur.erase(x); U_cur.erase(x); }
    // xm: some might still be in Y_cur → need to check before erasing from U
    // Actually: U_i = (U_{i-1} \ U_i^-) ∪ X_i^+ ∪ Y_i^+
    // U_i^- = (X_{i-1}\Y_{i-1} ∩ X_i^-) ∪ (Y_{i-1}\X_{i-1} ∩ Y_i^-) ∪ (X_i^- ∩ Y_i^-)
    // For simplicity: just apply by re-union
    for (auto y : ym) { Y_cur.erase(y); }
    for (auto x : xp) { X_cur.insert(x); U_cur.insert(x); }
    for (auto y : yp) { Y_cur.insert(y); U_cur.insert(y); }
    // Recompute U properly
    U_cur.clear();
    U_cur.insert(X_cur.begin(), X_cur.end());
    U_cur.insert(Y_cur.begin(), Y_cur.end());

    d.U_gt.push_back(ElemSet(U_cur.begin(), U_cur.end()));
  }

  return d;
}

// ── Timing & stats ─────────────────────────────────────────────────

struct Timer {
  chrono::high_resolution_clock::time_point t0;
  void start() { t0 = chrono::high_resolution_clock::now(); }
  double ms() {
    auto t1 = chrono::high_resolution_clock::now();
    return chrono::duration<double, milli>(t1 - t0).count();
  }
};

string MB(size_t bytes) {
  ostringstream oss;
  oss << fixed << setprecision(2) << (double(bytes) / 1024.0 / 1024.0) << " MB";
  return oss.str();
}

// ── Main benchmark ─────────────────────────────────────────────────

void RunBenchmark(size_t n, size_t add_n, size_t sub_n, size_t rounds) {
  cout << "\n=== UPSU Benchmark ===\n";
  cout << "|X| = |Y| = " << n
       << ", |X^+|=|Y^+| = " << add_n
       << ", |X^-|=|Y^-| = " << sub_n
       << ", rounds = " << rounds << "\n\n";

  auto data = GenerateTestData(n, add_n, sub_n, rounds);

  // Setup network (two parties, localhost)
  auto lctxs = yacl::link::test::SetupBrpcWorld(2);

  // Setup crypto keys and state
  Party p0, p1;

  // ── Init ──
  Timer t_init;
  t_init.start();

  auto fut_init_p0 = async(launch::async, [&]() {
    InitP0(lctxs[0], p0, data.X);
  });
  auto fut_init_p1 = async(launch::async, [&]() {
    InitP1(lctxs[1], p1, data.Y);
  });
  fut_init_p0.get(); fut_init_p1.get();
  double init_ms = t_init.ms();

  // Verify init
  set<Element> u0(p0.U.begin(), p0.U.end());
  set<Element> gt0(data.U_ground_truth.begin(), data.U_ground_truth.end());
  bool init_ok = (p0.U.size() == data.U_ground_truth.size()) && (u0 == gt0);
  cout << "Init: " << init_ms << " ms  "
       << (init_ok ? "CORRECT" : "FAIL") << "\n";

  // ── Update rounds ──
  size_t total_comm = 0;

  // Use a single Baxos per party, re-created per round with appropriate size
  okvs::Baxos baxos_p0 = MakeBaxos(std::max(add_n, sub_n));
  okvs::Baxos baxos_p1 = MakeBaxos(std::max(add_n, sub_n));

  for (size_t r = 0; r < rounds; ++r) {
    Timer t_round;
    t_round.start();

    auto fut_p0 = async(launch::async, [&]() {
      return UpdateRoundP0(lctxs[0], p0,
                           data.X_plus[r], data.X_minus[r],
                           baxos_p0);
    });
    auto fut_p1 = async(launch::async, [&]() {
      return UpdateRoundP1(lctxs[1], p1,
                           data.Y_plus[r], data.Y_minus[r],
                           baxos_p1);
    });

    auto U_p0 = fut_p0.get();
    auto U_p1 = fut_p1.get();
    double round_ms = t_round.ms();

    // Communication stats
    size_t comm = lctxs[0]->GetStats()->sent_bytes.load()
                + lctxs[0]->GetStats()->recv_bytes.load();

    // Verify correctness
    set<Element> up0(U_p0.begin(), U_p0.end());
    set<Element> up1(U_p1.begin(), U_p1.end());
    set<Element> gt(data.U_gt[r].begin(), data.U_gt[r].end());

    bool ok = (up0 == gt) && (up1 == gt);
    cout << "Round " << (r + 1) << ": " << round_ms << " ms  "
         << "comm=" << MB(comm - total_comm) << "  "
         << "|U|=" << U_p0.size() << "  "
         << (ok ? "OK" : "FAIL") << "\n";

    if (!ok) {
      cout << "  U_p0.size=" << U_p0.size()
           << "  U_p1.size=" << U_p1.size()
           << "  gt.size=" << data.U_gt[r].size() << "\n";
      // Compute differences for debugging
      set<Element> diff;
      for (auto x : gt) if (!up0.count(x)) diff.insert(x);
      cout << "  Missing from P0: " << diff.size() << "\n";
      diff.clear();
      for (auto x : up0) if (!gt.count(x)) diff.insert(x);
      cout << "  Extra in P0: " << diff.size() << "\n";
    }

    total_comm = comm;
  }

  // ── Summary ──
  cout << "\nTotal communication: " << MB(total_comm) << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  SetDefaultPsuProtocol(PsuProtocol::kKrtw);

  // Default sizes (matching Ling's UPSI benchmark: 2^17)
  size_t n     = 1 << 17;  // 131072
  size_t add_n = 1 << 8;   // 256
  size_t sub_n = 1 << 8;   // 256
  size_t rounds = 1;

  if (argc > 1) n      = atoi(argv[1]);
  if (argc > 2) add_n  = atoi(argv[2]);
  if (argc > 3) sub_n  = atoi(argv[3]);
  if (argc > 4) rounds = atoi(argv[4]);

  RunBenchmark(n, add_n, sub_n, rounds);
  return 0;
}
