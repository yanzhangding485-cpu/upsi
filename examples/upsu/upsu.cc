#include "examples/upsu/upsu.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <future>
#include <iostream>
#include <random>
#include <set>
#include <unordered_set>

#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/rr22.h"
#include <functional>

namespace upsu {

namespace yc = yacl::crypto;

// Buffer→string conversion (SerializePoint returns yacl::Buffer)
inline std::string BufToStr(const yacl::Buffer& b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

// ── Local helper ──
inline std::string uint128_to_string(uint128_t value) {
  if (value == 0) return "0";
  std::array<char, 40> buf;
  int pos = 39;
  buf[pos] = '\0';
  while (value > 0) {
    buf[--pos] = '0' + static_cast<char>(value % 10);
    value /= 10;
  }
  return std::string(&buf[pos]);
}

// ═════════════════════════════════════════════  PRF helpers  ════════

PRFVal HashToCurve(Element x, const std::shared_ptr<yc::EcGroup>& ec) {
  auto pt = ec->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                            uint128_to_string(x));
  return BufToStr(ec->SerializePoint(pt));
}

PRFVal ComputeSinglePRF(Element x, const yc::MPInt& sk,
                        const std::shared_ptr<yc::EcGroup>& ec) {
  auto pt = ec->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                            uint128_to_string(x));
  ec->MulInplace(&pt, sk);
  return BufToStr(ec->SerializePoint(pt));
}

PRFVal RaiseToKey(const PRFVal& v, const yc::MPInt& sk,
                   const std::shared_ptr<yc::EcGroup>& ec) {
  auto pt = ec->DeserializePoint(yacl::ByteContainerView(v.data(), v.size()));
  ec->MulInplace(&pt, sk);
  return BufToStr(ec->SerializePoint(pt));
}

PRFVal StripKey(const PRFVal& v, const yc::MPInt& sk_inv,
                 const std::shared_ptr<yc::EcGroup>& ec) {
  auto pt = ec->DeserializePoint(yacl::ByteContainerView(v.data(), v.size()));
  ec->MulInplace(&pt, sk_inv);
  return BufToStr(ec->SerializePoint(pt));
}

uint128_t HashPRFToUint128(const PRFVal& v) {
  size_t h = std::hash<std::string>{}(v);
  return static_cast<uint128_t>(h);
}

std::map<PRFVal, Element> BuildHashLookup(
    const ElemSet& elements, const std::shared_ptr<yc::EcGroup>& ec) {
  std::map<PRFVal, Element> m;
  for (auto x : elements) m[HashToCurve(x, ec)] = x;
  return m;
}

// ══════════════════════════════════════════  Network I/O  ══════════

void SendPRFVec(const std::shared_ptr<yacl::link::Context>& ctx,
                const PRFSet& vec, const std::string& tag) {
  std::vector<uint8_t> buf(vec.size() * kEcPointBytes);
  for (size_t i = 0; i < vec.size(); ++i)
    std::memcpy(buf.data() + i * kEcPointBytes, vec[i].data(), kEcPointBytes);
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(buf.data(), buf.size()), tag);
}

PRFSet RecvPRFVec(const std::shared_ptr<yacl::link::Context>& ctx,
                   const std::string& tag) {
  auto raw = ctx->Recv(ctx->PrevRank(), tag);
  size_t n = raw.size() / kEcPointBytes;
  PRFSet vec(n);
  for (size_t i = 0; i < n; ++i)
    vec[i].assign(reinterpret_cast<const char*>(raw.data()) + i * kEcPointBytes,
                  kEcPointBytes);
  return vec;
}

void SendElemVec(const std::shared_ptr<yacl::link::Context>& ctx,
                 const ElemSet& vec, const std::string& tag) {
  ctx->SendAsync(ctx->NextRank(),
    yacl::ByteContainerView(vec.data(), vec.size() * sizeof(Element)), tag);
}

ElemSet RecvElemVec(const std::shared_ptr<yacl::link::Context>& ctx,
                     const std::string& tag) {
  auto raw = ctx->Recv(ctx->PrevRank(), tag);
  size_t n = raw.size() / sizeof(Element);
  ElemSet vec(n);
  if (n > 0) std::memcpy(vec.data(), raw.data(), raw.size());
  return vec;
}

void SendUint32(const std::shared_ptr<yacl::link::Context>& ctx,
                uint32_t val, const std::string& tag) {
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(&val, sizeof(val)), tag);
}

uint32_t RecvUint32(const std::shared_ptr<yacl::link::Context>& ctx,
                     const std::string& tag) {
  auto raw = ctx->Recv(ctx->PrevRank(), tag);
  return *reinterpret_cast<const uint32_t*>(raw.data());
}

// ══════════════════════════════════════  MROPRF (raw EC ops)  ═════

PRFSet MROPRF_Receiver(const std::shared_ptr<yacl::link::Context>& ctx,
                        const ElemSet& inputs,
                        const std::shared_ptr<yc::EcGroup>& ec) {
  size_t n = inputs.size();
  if (n == 0) return {};

  // Generate random blinding key
  yc::MPInt r;
  yc::MPInt::RandomLtN(ec->GetOrder(), &r);
  yc::MPInt rinv = r.InvertMod(ec->GetOrder());

  // Hash to curve + blind: H(x)^r
  std::vector<yc::EcPoint> pts(n);
  for (size_t i = 0; i < n; ++i) {
    pts[i] = ec->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                              uint128_to_string(inputs[i]));
    ec->MulInplace(&pts[i], r);
  }

  // Serialize and send
  std::vector<uint8_t> buf(n * kEcPointBytes);
  for (size_t i = 0; i < n; ++i)
    ec->SerializePoint(pts[i], buf.data() + i * kEcPointBytes, kEcPointBytes);
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(buf.data(), buf.size()), "mro_req");

  // Receive sender-masked: H(x)^{r * sender_sk}
  auto resp = ctx->Recv(ctx->PrevRank(), "mro_resp");
  YACL_ENFORCE(resp.size() == int64_t(n * kEcPointBytes));

  // Deserialize
  for (size_t i = 0; i < n; ++i) {
    pts[i] = ec->DeserializePoint(
        yacl::ByteContainerView(static_cast<const uint8_t*>(resp.data()) + i * kEcPointBytes,
                                kEcPointBytes));
  }

  // Unblind: H(x)^{r * sender_sk * r^{-1}} = H(x)^{sender_sk}
  for (size_t i = 0; i < n; ++i)
    ec->MulInplace(&pts[i], rinv);

  // Serialize to PRF values
  PRFSet out(n);
  for (size_t i = 0; i < n; ++i) {
    out[i] = BufToStr(ec->SerializePoint(pts[i]));
  }
  return out;
}

void MROPRF_Sender(const std::shared_ptr<yacl::link::Context>& ctx,
                    size_t n,
                    const yc::MPInt& sender_sk,
                    const std::shared_ptr<yc::EcGroup>& ec) {
  if (n == 0) return;

  auto raw = ctx->Recv(ctx->PrevRank(), "mro_req");
  YACL_ENFORCE(raw.size() == int64_t(n * kEcPointBytes));

  std::vector<yc::EcPoint> pts(n);
  for (size_t i = 0; i < n; ++i) {
    pts[i] = ec->DeserializePoint(
        yacl::ByteContainerView(static_cast<const uint8_t*>(raw.data()) + i * kEcPointBytes,
                                kEcPointBytes));
  }

  // Apply sender key: H(x)^{r * sender_sk}
  for (size_t i = 0; i < n; ++i)
    ec->MulInplace(&pts[i], sender_sk);

  std::vector<uint8_t> buf(n * kEcPointBytes);
  for (size_t i = 0; i < n; ++i)
    ec->SerializePoint(pts[i], buf.data() + i * kEcPointBytes, kEcPointBytes);
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(buf.data(), buf.size()), "mro_resp");
}

// ═══════════════════════════════════════  Set helpers  ═════════════

static std::set<PRFVal> ToSet(const PRFSet& v) {
  return {v.begin(), v.end()};
}

static PRFSet PRF_Intersect(const PRFSet& a, const PRFSet& b) {
  auto sb = ToSet(b);
  PRFSet out;
  for (const auto& x : a)
    if (sb.count(x)) out.push_back(x);
  return out;
}

static PRFSet PRF_Diff(const PRFSet& a, const std::set<PRFVal>& b) {
  PRFSet out;
  for (const auto& x : a)
    if (!b.count(x)) out.push_back(x);
  return out;
}

static ElemSet HashPRFSet(const PRFSet& prf_set) {
  ElemSet out;
  out.reserve(prf_set.size());
  for (const auto& v : prf_set)
    out.push_back(HashPRFToUint128(v));
  return out;
}

static PRFSet UnhashPRFSet(const ElemSet& hashed, const PRFSet& original) {
  std::map<uint128_t, PRFVal> lookup;
  for (const auto& v : original)
    lookup[HashPRFToUint128(v)] = v;
  PRFSet out;
  for (auto h : hashed) {
    auto it = lookup.find(h);
    if (it != lookup.end())
      out.push_back(it->second);
  }
  return out;
}

// ═══════════════════════════════════════  Baxos  ═══════════════════

okvs::Baxos MakeBaxos(size_t max_items) {
  okvs::Baxos b;
  size_t n = std::max(max_items, size_t(1 << 10));
  uint128_t seed = static_cast<uint128_t>(std::hash<size_t>{}(max_items));
  yc::Prg<uint128_t> prng(seed);
  prng.Fill(absl::MakeSpan(&seed, 1));
  b.Init(n, n, 3, 40, okvs::PaxosParam::DenseType::GF128, seed);
  return b;
}

// ═══════════════════════════════  Party setup  ═════════════════════

static void SetupKeys(Party& p) {
  p.ec = yc::EcGroupFactory::Instance().Create("FourQ");
  yc::MPInt::RandomLtN(p.ec->GetOrder(), &p.sk);
  p.skinv = p.sk.InvertMod(p.ec->GetOrder());
}

void InitP0(const std::shared_ptr<yacl::link::Context>& ctx,
            Party& p, const ElemSet& X) {
  SetupKeys(p);
  p.X = X;
  p.U = PsuRecv(ctx, X);
  std::set<Element> xs(X.begin(), X.end());
  for (auto u : p.U) if (!xs.count(u)) p.peer_excl.push_back(u);
}

void InitP1(const std::shared_ptr<yacl::link::Context>& ctx,
            Party& p, const ElemSet& Y) {
  SetupKeys(p);
  p.X = Y;
  p.U = PsuSend(ctx, Y);
  std::set<Element> ys(Y.begin(), Y.end());
  for (auto u : p.U) if (!ys.count(u)) p.peer_excl.push_back(u);
}

// ═══════════════════════  P0 PROTOCOL  ═════════════════════════════

ElemSet UpdateRoundP0(const std::shared_ptr<yacl::link::Context>& ctx,
                       Party& p,
                       const ElemSet& X_plus,
                       const ElemSet& X_minus,
                       okvs::Baxos& /*del_baxos*/) {
  // ────── Preprocess ──────
  // P0 queries: peer_excl ∪ X_plus → F_{k1}(peer_excl, X_plus)
  ElemSet query = p.peer_excl;
  query.insert(query.end(), X_plus.begin(), X_plus.end());

  SendUint32(ctx, uint32_t(query.size()), "p0_qsz");
  uint32_t p1_qsz = RecvUint32(ctx, "p1_qsz");

  auto fut_r = std::async(std::launch::async, [&]() {
    return MROPRF_Receiver(ctx, query, p.ec);
  });
  auto fut_s = std::async(std::launch::async, [&]() {
    MROPRF_Sender(ctx, p1_qsz, p.sk, p.ec);  // P0 uses k0 as sender key
  });
  auto vals = fut_r.get(); fut_s.get();

  // Parse: first |peer_excl| are F_{k1}(peer_excl), rest are F_{k1}(X_plus)
  p.prf_peer_excl.clear();
  p.prf_own_add.clear();
  for (size_t i = 0; i < p.peer_excl.size(); ++i)
    p.prf_peer_excl.push_back(RaiseToKey(vals[i], p.sk, p.ec));  // ^{k0} → F
  for (size_t i = 0; i < X_plus.size(); ++i)
    p.prf_own_add.push_back(
        RaiseToKey(vals[p.peer_excl.size() + i], p.sk, p.ec));

  // ────── Deletion ──────
  // Step 1: P0 → P1  F_{k0}(X_i^-)
  PRFSet fk0_Xm;
  for (auto x : X_minus)
    fk0_Xm.push_back(ComputeSinglePRF(x, p.sk, p.ec));
  SendPRFVec(ctx, fk0_Xm, "d_k0xm");

  // Step 2: P1 → P0  F_{k1}(Y_i^-)
  PRFSet fk1_Ym = RecvPRFVec(ctx, "d_k1ym");
  p.prf_peer_del.clear();
  for (const auto& v : fk1_Ym)
    p.prf_peer_del.push_back(RaiseToKey(v, p.sk, p.ec));  // ^{k0} → F(Y_i^-)

  // Step 3: F(D_X) = F(peer_excl) ∩ F(Y_i^-)
  p.prf_D_own = PRF_Intersect(p.prf_peer_excl, p.prf_peer_del);

  // Step 5: PSI(F(Y_i^-), F(X_i^-)) → F(X_i^- ∩ Y_i^-)
  ElemSet psi_p0 = HashPRFSet(p.prf_peer_del);
  SendUint32(ctx, uint32_t(psi_p0.size()), "d_psz0");
  uint32_t psi_sz1 = RecvUint32(ctx, "d_psz1");
  size_t psi_max = std::max(psi_p0.size(), size_t(psi_sz1));

  PRFSet prf_Xi_cap_Yi;
  if (psi_max > 0) {
    okvs::Baxos psi_bx = MakeBaxos(psi_max);
    auto fut_psi = std::async(std::launch::async, [&]() {
      return rr22::RR22PsiRecv(ctx, psi_p0, psi_bx);
    });
    prf_Xi_cap_Yi = UnhashPRFSet(fut_psi.get(), p.prf_peer_del);
  }

  // Step 6-7: Exchange F(D_X) ↔ F(D_Y)
  PRFSet prf_DY = RecvPRFVec(ctx, "d_dy");
  SendPRFVec(ctx, p.prf_D_own, "d_dx");

  // Step 8: F(U_i^-) = F(D_X) ∪ F(D_Y) ∪ F(X_i^- ∩ Y_i^-)
  std::set<PRFVal> u_set = ToSet(prf_Xi_cap_Yi);
  for (const auto& v : prf_DY) u_set.insert(v);
  for (const auto& v : p.prf_D_own) u_set.insert(v);
  p.prf_U_minus = {u_set.begin(), u_set.end()};

  // ────── Addition (blind) ──────
  // Step 1: P1 → P0  F_{k1}(U_{i-1})
  PRFSet fk1_Uprev = RecvPRFVec(ctx, "a_k1u");
  PRFSet f_Uprev;
  for (const auto& v : fk1_Uprev)
    f_Uprev.push_back(RaiseToKey(v, p.sk, p.ec));

  // Remove F(U_i^-), add F(X_i^+)
  PRFSet f_partial = PRF_Diff(f_Uprev, u_set);
  for (const auto& v : p.prf_own_add) f_partial.push_back(v);

  // Step 3: → P1  F(U_{i-1}\U_i^- ∪ X_i^+)
  SendPRFVec(ctx, f_partial, "a_part");

  // Step 5: ← P1  F_{k0}(U_i)
  PRFSet fk0_Ui = RecvPRFVec(ctx, "a_k0u");

  // Step 6: Strip k0 → H(U_i), map to plaintext
  std::map<PRFVal, Element> htab = BuildHashLookup(p.U, p.ec);
  for (auto x : X_plus) htab[HashToCurve(x, p.ec)] = x;

  ElemSet Ui_new;
  PRFSet unmapped;
  for (const auto& v : fk0_Ui) {
    auto h = StripKey(v, p.skinv, p.ec);
    auto it = htab.find(h);
    if (it != htab.end()) Ui_new.push_back(it->second);
    else unmapped.push_back(h);
  }

  // Step 7-8: resolve unmapped (Y_i^+)
  SendPRFVec(ctx, unmapped, "a_unm");
  ElemSet peer_pl = RecvElemVec(ctx, "a_ppl");
  Ui_new.insert(Ui_new.end(), peer_pl.begin(), peer_pl.end());

  // Step 9: → P1  final U_i
  SendElemVec(ctx, Ui_new, "a_uf");

  // Update state: X_i = (X_{i-1} \ X_i^-) ∪ X_i^+
  {
    std::set<Element> xs(p.X.begin(), p.X.end());
    for (auto x : X_minus) xs.erase(x);
    for (auto x : X_plus) xs.insert(x);
    p.X = ElemSet(xs.begin(), xs.end());
  }
  p.U = Ui_new;
  p.peer_excl.clear();
  std::set<Element> xs(p.X.begin(), p.X.end());
  for (auto u : p.U) if (!xs.count(u)) p.peer_excl.push_back(u);

  return Ui_new;
}

// ═══════════════════════  P1 PROTOCOL (symmetric)  ═════════════════

ElemSet UpdateRoundP1(const std::shared_ptr<yacl::link::Context>& ctx,
                       Party& p,
                       const ElemSet& Y_plus,
                       const ElemSet& Y_minus,
                       okvs::Baxos& /*del_baxos*/) {
  // ────── Preprocess ──────
  ElemSet query = p.peer_excl;
  query.insert(query.end(), Y_plus.begin(), Y_plus.end());

  uint32_t p0_qsz = RecvUint32(ctx, "p0_qsz");
  SendUint32(ctx, uint32_t(query.size()), "p1_qsz");

  auto fut_r = std::async(std::launch::async, [&]() {
    return MROPRF_Receiver(ctx, query, p.ec);
  });
  auto fut_s = std::async(std::launch::async, [&]() {
    MROPRF_Sender(ctx, p0_qsz, p.sk, p.ec);  // P1 uses k1 as sender key
  });
  auto vals = fut_r.get(); fut_s.get();

  p.prf_peer_excl.clear();
  p.prf_own_add.clear();
  for (size_t i = 0; i < p.peer_excl.size(); ++i)
    p.prf_peer_excl.push_back(RaiseToKey(vals[i], p.sk, p.ec));
  for (size_t i = 0; i < Y_plus.size(); ++i)
    p.prf_own_add.push_back(
        RaiseToKey(vals[p.peer_excl.size() + i], p.sk, p.ec));

  // ────── Deletion ──────
  // Step 1 (sym): P1 ← P0  F_{k0}(X_i^-)
  PRFSet fk0_Xm = RecvPRFVec(ctx, "d_k0xm");
  p.prf_peer_del.clear();
  for (const auto& v : fk0_Xm)
    p.prf_peer_del.push_back(RaiseToKey(v, p.sk, p.ec));  // ^{k1} → F(X_i^-)

  // Step 2 (sym): P1 → P0  F_{k1}(Y_i^-)
  PRFSet fk1_Ym;
  for (auto y : Y_minus)
    fk1_Ym.push_back(ComputeSinglePRF(y, p.sk, p.ec));
  SendPRFVec(ctx, fk1_Ym, "d_k1ym");

  // Step 3: F(D_Y) = F(peer_excl) ∩ F(X_i^-)
  p.prf_D_own = PRF_Intersect(p.prf_peer_excl, p.prf_peer_del);

  // Step 5: PSI(F(X_i^-), F(Y_i^-)) → F(X_i^- ∩ Y_i^-)
  uint32_t psi_sz0 = RecvUint32(ctx, "d_psz0");
  ElemSet psi_p1 = HashPRFSet(p.prf_peer_del);
  SendUint32(ctx, uint32_t(psi_p1.size()), "d_psz1");
  size_t psi_max = std::max(size_t(psi_sz0), psi_p1.size());

  PRFSet prf_Xi_cap_Yi;
  if (psi_max > 0) {
    okvs::Baxos psi_bx = MakeBaxos(psi_max);
    auto fut_psi = std::async(std::launch::async, [&]() {
      return rr22::RR22PsiSend(ctx, psi_p1, psi_bx);
    });
    prf_Xi_cap_Yi = UnhashPRFSet(fut_psi.get(), p.prf_peer_del);
  }

  // Step 6-7: Exchange F(D_Y) ↔ F(D_X)
  SendPRFVec(ctx, p.prf_D_own, "d_dy");
  PRFSet prf_DX = RecvPRFVec(ctx, "d_dx");

  // Step 8: F(U_i^-)
  std::set<PRFVal> u_set = ToSet(prf_Xi_cap_Yi);
  for (const auto& v : prf_DX) u_set.insert(v);
  for (const auto& v : p.prf_D_own) u_set.insert(v);
  p.prf_U_minus = {u_set.begin(), u_set.end()};

  // ────── Addition ──────
  // Step 1: P1 → P0  F_{k1}(U_{i-1})
  PRFSet fk1_Uprev;
  for (auto u : p.U)
    fk1_Uprev.push_back(ComputeSinglePRF(u, p.sk, p.ec));
  SendPRFVec(ctx, fk1_Uprev, "a_k1u");

  // Step 3: ← P0  F(U_{i-1}\U_i^- ∪ X_i^+)
  PRFSet f_partial = RecvPRFVec(ctx, "a_part");

  // Step 4: add F(Y_i^+), strip k1 → F_{k0}(U_i)
  for (const auto& v : p.prf_own_add) f_partial.push_back(v);

  PRFSet fk0_Ui;
  for (const auto& v : f_partial)
    fk0_Ui.push_back(StripKey(v, p.skinv, p.ec));  // F(Y_i^+ included)

  // Step 5: → P0  F_{k0}(U_i)
  SendPRFVec(ctx, fk0_Ui, "a_k0u");

  // Step 7: ← P0  unmapped H values
  PRFSet unmapped = RecvPRFVec(ctx, "a_unm");

  // Step 8: map unmapped H → Y_plus (and current Y) plaintext
  std::map<PRFVal, Element> htab;
  for (auto y : Y_plus) htab[HashToCurve(y, p.ec)] = y;
  for (auto y : p.X)   htab[HashToCurve(y, p.ec)] = y;

  ElemSet peer_pl;
  for (const auto& h : unmapped) {
    auto it = htab.find(h);
    if (it != htab.end()) peer_pl.push_back(it->second);
  }
  SendElemVec(ctx, peer_pl, "a_ppl");

  // Step 10: ← P0  final U_i
  ElemSet Ui_new = RecvElemVec(ctx, "a_uf");

  // Update state: Y_i = (Y_{i-1} \ Y_i^-) ∪ Y_i^+
  {
    std::set<Element> ys(p.X.begin(), p.X.end());
    for (auto y : Y_minus) ys.erase(y);
    for (auto y : Y_plus) ys.insert(y);
    p.X = ElemSet(ys.begin(), ys.end());
  }
  p.U = Ui_new;
  p.peer_excl.clear();
  std::set<Element> ys(p.X.begin(), p.X.end());
  for (auto u : p.U) if (!ys.count(u)) p.peer_excl.push_back(u);

  return Ui_new;
}

}  // namespace upsu
