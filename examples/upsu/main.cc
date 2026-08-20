// UPSU Benchmark & Correctness Test

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <iomanip>
#include <iostream>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "examples/upsu/upsu.h"
#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/okvs/baxos.h"
#include "yacl/link/test_util.h"

using namespace std;
using namespace upsu;

namespace {

// 30 min recv timeout for N=2^20
constexpr uint64_t kRecvTimeoutMs = 30 * 60 * 1000;

// ── Test data generation ──────────────────────────────────────────
// Using simple arithmetic (no Blake3), consistent with Python simulation.

ElemSet MakeSet(size_t base, size_t n) {
  ElemSet out;
  for (size_t i = 0; i < n; ++i)
    out.push_back(static_cast<uint128_t>(base + i));
  return out;
}

struct TestData {
  ElemSet X, Y;           // initial private sets
  ElemSet U_ground_truth; // initial union
  vector<ElemSet> X_plus, X_minus, Y_plus, Y_minus;  // per-round updates
  vector<ElemSet> U_gt;   // ground-truth union after each round
};

TestData GenerateTestData(size_t n, size_t add_n, size_t sub_n, size_t rounds,
                            double overlap_ratio = 0.5, bool collide = false) {
  // X = [0 .. n-1]
  // Y = [n/2 .. 3n/2-1]  ->  overlap = n/2 (range [n/2, n-1] in both sets)
  TestData d;
  d.X = MakeSet(0, n);
  d.Y = MakeSet(n / 2, n);

  set<Element> u0(d.X.begin(), d.X.end());
  u0.insert(d.Y.begin(), d.Y.end());
  d.U_ground_truth = ElemSet(u0.begin(), u0.end());

  set<Element> X_cur(d.X.begin(), d.X.end());
  set<Element> Y_cur(d.Y.begin(), d.Y.end());
  set<Element> U_cur = u0;

  std::random_device rd;
  std::mt19937_64 gen(rd());

  // Pick k distinct random elements from pool (rejection via set).
  auto pick = [&gen](const ElemSet& pool, size_t k) {
    ElemSet out;
    std::set<Element> seen;
    while (out.size() < k) {
      size_t idx = static_cast<size_t>(gen()) % pool.size();
      if (seen.insert(pool[idx]).second) out.push_back(pool[idx]);
    }
    return out;
  };

  for (size_t r = 0; r < rounds; ++r) {
    ElemSet xp, xm, yp, ym;

    // Additions: fresh random elements, disjoint from own current set.
    // Cross-party intersections are left to randomness (prob ~ nu^2/2^128),
    // so in the natural model additions never enter X&Y (intersection).
    {
      std::set<Element> xcur_set(X_cur.begin(), X_cur.end());
      while (xp.size() < add_n) {
        uint64_t hi = gen(); uint64_t lo = gen();
        Element x = (static_cast<uint128_t>(hi) << 64) | lo;
        if (!xcur_set.count(x)) { xcur_set.insert(x); xp.push_back(x); }
      }
    }
    {
      std::set<Element> ycur_set(Y_cur.begin(), Y_cur.end());
      while (yp.size() < add_n) {
        uint64_t hi = gen(); uint64_t lo = gen();
        Element y = (static_cast<uint128_t>(hi) << 64) | lo;
        if (!ycur_set.count(y)) { ycur_set.insert(y); yp.push_back(y); }
      }
    }

    // Deletions: sampled from the CURRENT sets (base elements plus elements
    // added in earlier rounds), never re-selected (membership in the current
    // set already excludes everything deleted before).
    //   J   = overlap_n joint deletions from X&Y (same batch on both sides)
    //   D_X = remaining deletions from E_X = X\Y (own exclusives, includes
    //         elements that X added in earlier rounds)
    //   D_Y = remaining deletions from E_Y = Y\X (symmetric)
    // Additions never enter the intersection, so X&Y only drains at
    // overlap_n per round. When it can no longer supply overlap_n, the
    // shortfall moves to the exclusive parts (adaptive J): both sides still
    // delete sub_n fresh elements, and |U| growth slows accordingly.
    ElemSet inter, e_x, e_y;
    {
      std::set<Element> yset(Y_cur.begin(), Y_cur.end());
      for (auto x : X_cur) {
        if (yset.count(x)) inter.push_back(x);
        else e_x.push_back(x);
      }
      for (auto y : Y_cur)
        if (!X_cur.count(y)) e_y.push_back(y);
    }
    const size_t overlap_n = static_cast<size_t>(sub_n * overlap_ratio);
    const size_t j_eff = (overlap_n < inter.size()) ? overlap_n : inter.size();
    const size_t d_size = sub_n - j_eff;
    if (d_size > e_x.size() || d_size > e_y.size()) {
      std::cerr << "GenerateTestData: exclusive pool exhausted at round "
                << r << " (sub_n too large for n)" << std::endl;
      std::exit(1);
    }

    ElemSet j_vec = pick(inter, j_eff);
    ElemSet dx_vec = pick(e_x, d_size);
    ElemSet dy_vec = pick(e_y, d_size);
    for (auto x : j_vec) { xm.push_back(x); ym.push_back(x); }
    xm.insert(xm.end(), dx_vec.begin(), dx_vec.end());
    ym.insert(ym.end(), dy_vec.begin(), dy_vec.end());

    // Collision mode: force the improbable corner cases.
    //   xp[0] = a D_Y element : D_Y & X_i^+  (X re-adds what Y deletes)
    //   yp[0] = a D_X element : D_X & Y_i^+  (Y re-adds what X deletes)
    //   yp[1] = xp[1]         : joint addition X_i^+ & Y_i^+
    if (collide && !dx_vec.empty() && !dy_vec.empty()) {
      xp[0] = dy_vec.back();
      yp[0] = dx_vec.back();
      if (add_n >= 2) yp[1] = xp[1];
    }

    d.X_plus.push_back(xp);
    d.X_minus.push_back(xm);
    d.Y_plus.push_back(yp);
    d.Y_minus.push_back(ym);

    // Update ground truth
    for (auto x : xm) X_cur.erase(x);
    for (auto y : ym) Y_cur.erase(y);
    for (auto x : xp) X_cur.insert(x);
    for (auto y : yp) Y_cur.insert(y);
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

void RunBenchmark(size_t n, size_t add_n, size_t sub_n, size_t rounds,
                  double overlap_ratio = 0.5, bool collide = false) {
  cout << "\n=== UPSU Benchmark ===\n";
  cout << "|X| = |Y| = " << n
       << ", |X^+|=|Y^+| = " << add_n
       << ", |X^-|=|Y^-| = " << sub_n
       << ", rounds = " << rounds
       << ", overlap = " << (int)(overlap_ratio * 100) << "%"
       << ", collide = " << (collide ? 1 : 0) << "\n\n";

  auto data = GenerateTestData(n, add_n, sub_n, rounds, overlap_ratio, collide);

  // Setup network (two parties, localhost)
  auto lctxs = yacl::link::test::SetupBrpcWorld(2);
  for (const auto& lctx : lctxs) {
    lctx->SetRecvTimeout(kRecvTimeoutMs);
  }

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
  size_t init_comm = lctxs[0]->GetStats()->sent_bytes.load()
                   + lctxs[0]->GetStats()->recv_bytes.load();
  cout << "Init communication: " << MB(init_comm) << "\n";

  // ── Update rounds ──
  size_t total_comm = init_comm;
  set<Element> xs(data.X.begin(), data.X.end());  // running X for PSU baseline
  set<Element> ys(data.Y.begin(), data.Y.end());  // running Y for PSU baseline
  double cum_round_ms = 0.0;
  size_t cum_round_comm = 0;
  double cum_psu_ms = 0.0;
  size_t cum_psu_comm = 0;

  for (size_t r = 0; r < rounds; ++r) {
    size_t comm_before = lctxs[0]->GetStats()->sent_bytes.load()
                       + lctxs[0]->GetStats()->recv_bytes.load();
    Timer t_round;
    t_round.start();

    auto fut_p0 = async(launch::async, [&]() {
      return UpdateRoundP0(lctxs[0], p0,
                           data.X_plus[r], data.X_minus[r],
                           add_n, sub_n);
    });
    auto fut_p1 = async(launch::async, [&]() {
      return UpdateRoundP1(lctxs[1], p1,
                           data.Y_plus[r], data.Y_minus[r],
                           add_n, sub_n);
    });

    auto U_p0 = fut_p0.get();
    auto U_p1 = fut_p1.get();
    double round_ms = t_round.ms();

    // Communication stats
    size_t comm = lctxs[0]->GetStats()->sent_bytes.load()
                + lctxs[0]->GetStats()->recv_bytes.load();
    size_t round_comm = comm - comm_before;
    cum_round_comm += round_comm;
    cum_round_ms += round_ms;

    // Verify correctness
    set<Element> up0(U_p0.begin(), U_p0.end());
    set<Element> up1(U_p1.begin(), U_p1.end());
    set<Element> gt(data.U_gt[r].begin(), data.U_gt[r].end());

    bool ok = (up0 == gt) && (up1 == gt);
    cout << "Round " << (r + 1) << ": " << round_ms << " ms  "
         << "comm=" << MB(round_comm) << "  "
         << "|U|=" << U_p0.size() << "  "
         << (ok ? "OK" : "FAIL") << "\n";

    if (!ok) {
      cout << "  U_p0.size=" << U_p0.size()
           << "  U_p1.size=" << U_p1.size()
           << "  gt.size=" << data.U_gt[r].size() << "\n";
      set<Element> diff;
      for (auto x : gt) if (!up0.count(x)) diff.insert(x);
      cout << "  Missing from P0: " << diff.size() << "\n";
      diff.clear();
      for (auto x : up0) if (!gt.count(x)) diff.insert(x);
      cout << "  Extra in P0: " << diff.size() << "\n";
    }

    total_comm = comm;
    // Fair comparison: PSUx2
    size_t psu_comm_before = lctxs[0]->GetStats()->sent_bytes.load()
                           + lctxs[0]->GetStats()->recv_bytes.load();
    {
      for (auto e : data.X_minus[r]) xs.erase(e);
      for (auto e : data.X_plus[r])  xs.insert(e);
      for (auto e : data.Y_minus[r]) ys.erase(e);
      for (auto e : data.Y_plus[r])  ys.insert(e);
      ElemSet X_new(xs.begin(), xs.end());
      ElemSet Y_new(ys.begin(), ys.end());
      cout << "  Updated: |X'|=" << X_new.size() << " |Y'|=" << Y_new.size() << "\n";
      Timer t2; t2.start();
      auto f0 = async(launch::async, [&]() { return PsuRecv(lctxs[0], X_new); });
      auto f1 = async(launch::async, [&]() { return PsuSend(lctxs[1], Y_new); });
      auto U2_p0 = f0.get(); auto U2_p1 = f1.get();
      double psu2_ms = t2.ms();
      set<Element> psu2_set(U2_p0.begin(), U2_p0.end());
      bool match = (U2_p0.size() == U2_p1.size()) && (psu2_set == gt);
      size_t psu_comm_after = lctxs[0]->GetStats()->sent_bytes.load()
                            + lctxs[0]->GetStats()->recv_bytes.load();
      size_t psu_comm = psu_comm_after - psu_comm_before;
      cum_psu_comm += psu_comm;
      cum_psu_ms += psu2_ms;
      cout << "  PSU(X',Y'): " << psu2_ms << " ms  |U|=" << U2_p0.size()
           << "  " << (match ? "MATCH" : "MISMATCH") << "\n";
      cout << "  UPSU (Round): " << round_ms << " ms  comm=" << MB(round_comm) << "\n";
      cout << "  PSU (re-run): " << psu2_ms << " ms  comm=" << MB(psu_comm) << "\n";
      cout << "  Per-round speedup: " << fixed << setprecision(2) << psu2_ms / round_ms << "x\n";
    }
  }

  cout << "\n=== Cumulative over " << rounds << " round(s) ===\n";
  cout << "UPSU total (Init + " << rounds << " rounds): " << (init_ms + cum_round_ms)
       << " ms  comm=" << MB(init_comm + cum_round_comm) << "\n";
  cout << "PSUx" << (rounds + 1) << " total: " << (init_ms + cum_psu_ms)
       << " ms  comm=" << MB(init_comm + cum_psu_comm) << "\n";
  cout << "Cumulative speedup: " << fixed << setprecision(2)
       << (init_ms + cum_psu_ms) / (init_ms + cum_round_ms) << "x\n";
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
  double overlap = 0.5;

  bool collide = false;
  if (argc > 1) n       = atoi(argv[1]);
  if (argc > 2) add_n   = atoi(argv[2]);
  if (argc > 3) sub_n   = atoi(argv[3]);
  if (argc > 4) rounds  = atoi(argv[4]);
  if (argc > 5) overlap = atof(argv[5]);
  if (argc > 6) collide = atoi(argv[6]);

  RunBenchmark(n, add_n, sub_n, rounds, overlap, collide);
  return 0;
}
