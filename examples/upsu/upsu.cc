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
#include "yacl/crypto/hash/hash_utils.h"

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
  // Use raw EC point bytes — deterministic and collision-resistant.
  // v is 32 bytes, take first 16 as uint128_t.
  uint128_t out = 0;
  std::memcpy(&out, v.data(), std::min(sizeof(out), v.size()));
  return out;
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

// Append random dummy elements (outside U) until `out` reaches `target`.
static void AppendDummies(ElemSet& out, size_t target, const ElemSet& U) {
  std::set<Element> u_set(U.begin(), U.end());
  std::random_device rd;
  std::mt19937_64 gen(rd());
  while (out.size() < target) {
    uint64_t hi = gen();
    uint64_t lo = gen();
    Element x = (static_cast<uint128_t>(hi) << 64) | lo;
    if (!u_set.count(x)) out.push_back(x);
  }
}

// ═══════════════════════════════════════  Baxos  ═══════════════════

okvs::Baxos MakeBaxos(size_t max_items) {
  okvs::Baxos b;
  size_t n = std::max(max_items, size_t(32));
  uint128_t seed = static_cast<uint128_t>(std::hash<size_t>{}(max_items));
  yc::Prg<uint128_t> prng(seed);
  prng.Fill(absl::MakeSpan(&seed, 1));
  b.Init(n * 2, n, 3, 40, okvs::PaxosParam::DenseType::GF128, seed);
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
                       size_t add_max, size_t sub_max) {
  // ────── Preprocess ──────
  // Fixed public sizes (identical on both sides): F_MROPRF/F_PSI reveal
  // no counts, so the real protocol must not leak them either.
  const size_t F_MRO = p.U.size() + add_max + sub_max;
  const size_t F_PSI = p.U.size() + sub_max;

  // P0 queries: (peer_excl \ X_plus) ∪ X_plus ∪ X_minus, padded with
  // random dummies outside U_{i-1} to the fixed size F_MRO.
  std::set<Element> xp_set(X_plus.begin(), X_plus.end());
  ElemSet excl_no_plus;
  for (auto e : p.peer_excl)
    if (!xp_set.count(e)) excl_no_plus.push_back(e);

  ElemSet query = excl_no_plus;
  query.insert(query.end(), X_plus.begin(), X_plus.end());
  query.insert(query.end(), X_minus.begin(), X_minus.end());
  AppendDummies(query, F_MRO, p.U);

  auto fut_r = std::async(std::launch::async, [&]() {
    return MROPRF_Receiver(ctx, query, p.ec);
  });
  auto fut_s = std::async(std::launch::async, [&]() {
    MROPRF_Sender(ctx, F_MRO, p.sk, p.ec);  // P0 uses k0 as sender key
  });
  auto vals = fut_r.get(); fut_s.get();

  // Parse: excl | own_add | own_del | dummies
  const size_t n1 = excl_no_plus.size();
  const size_t n2 = X_plus.size();
  const size_t n3 = X_minus.size();
  p.prf_peer_excl.clear();
  p.prf_own_add.clear();
  p.prf_own_del.clear();
  for (size_t i = 0; i < n1; ++i)
    p.prf_peer_excl.push_back(RaiseToKey(vals[i], p.sk, p.ec));  // ^{k0} → F
  for (size_t i = 0; i < n2; ++i)
    p.prf_own_add.push_back(RaiseToKey(vals[n1 + i], p.sk, p.ec));
  for (size_t i = 0; i < n3; ++i)
    p.prf_own_del.push_back(RaiseToKey(vals[n1 + n2 + i], p.sk, p.ec));

  // ────── Deletion: single symmetric PSI ──────
  // P0's padded input: F((Y\\X)\\X_i^+) ∪ F(X_i^-) ∪ dummies, size F_PSI.
  // Set union, not concatenation: a wrapped deletion window can re-select
  // an element that was deleted in an earlier round and now lives in the
  // peer-exclusive set. Without dedup the same PRF value would enter the
  // OKVS twice and crash the Paxos solver with duplicate keys.
  PRFSet psi_in;
  {
    std::set<PRFVal> psi_set;
    for (const auto& v : p.prf_peer_excl)
      if (psi_set.insert(v).second) psi_in.push_back(v);
    for (const auto& v : p.prf_own_del)
      if (psi_set.insert(v).second) psi_in.push_back(v);
  }
  // Padding: F_PSI - |set| dummy F-values from the Preprocess dummy pool.
  // If dedup shrank the union, the pool runs short; overflow entries are
  // re-raised pool images (one extra secret-key exponentiation keeps them
  // outside both parties' sets).
  const size_t n_dummy = F_PSI - psi_in.size();
  const size_t n_pool = vals.size() - n1 - n2 - n3;
  for (size_t i = 0; i < n_dummy; ++i) {
    PRFVal d;
    if (i < n_pool) {
      d = RaiseToKey(vals[n1 + n2 + n3 + i], p.sk, p.ec);
    } else {
      d = RaiseToKey(vals[n1 + n2 + n3 + (i - n_pool)], p.sk, p.ec);
      d = RaiseToKey(d, p.sk, p.ec);
    }
    psi_in.push_back(d);
  }

  ElemSet psi_p0 = HashPRFSet(psi_in);
  p.prf_U_minus.clear();
  if (F_PSI > 0) {
    okvs::Baxos psi_bx = MakeBaxos(F_PSI);
    auto fut_psi = std::async(std::launch::async, [&]() {
      return rr22::RR22PsiRecv(ctx, psi_p0, psi_bx);
    });
    p.prf_U_minus = UnhashPRFSet(fut_psi.get(), psi_in);
  }

  // ────── Addition ──────
  // Step 1: → P1  F_{k0}(U_{i-1}), then add_max blank values H(b)^{k0}
  // with b outside U_{i-1}. P1 forwards the blanks as size padding when
  // building the masked set below.
  PRFSet fk0_Uprev;
  for (auto u : p.U)
    fk0_Uprev.push_back(ComputeSinglePRF(u, p.sk, p.ec));
  SendPRFVec(ctx, fk0_Uprev, "a_fk0u");

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::set<Element> u_plain(p.U.begin(), p.U.end());
  PRFSet blanks;
  while (blanks.size() < add_max) {
    uint64_t hi = gen();
    uint64_t lo = gen();
    Element r = (static_cast<uint128_t>(hi) << 64) | lo;
    if (u_plain.count(r)) continue;
    blanks.push_back(ComputeSinglePRF(r, p.sk, p.ec));
  }
  SendPRFVec(ctx, blanks, "a_blanks");

  // Step 2: ← P1  S1 = F_{k0}(U_{i-1} minus U_i^-) ∪ {H(y)^{k0 r'}}
  // ∪ blanks, of the public size |U_{i-1}| - |U_i^-| + add_max.
  PRFSet s1 = RecvPRFVec(ctx, "a_s1");
  YACL_ENFORCE(s1.size() == p.U.size() - p.prf_U_minus.size() + add_max);

  // Step 3: ← P1  two OKVS instances of capacity add_max (public size
  // and seed): one stores the plaintext of each Y_i^+ element, the other
  // a tag of F_{k0}(y). Decoding is local, so P1 learns nothing about
  // which elements P0 can map.
  okvs::Baxos bx1 = MakeBaxos(add_max);
  okvs::Baxos bx2 = MakeBaxos(add_max);
  std::vector<uint128_t> okvs1(bx1.size()), okvs2(bx2.size());
  if (add_max > 0) {
    auto raw1 = ctx->Recv(ctx->PrevRank(), "a_okvs1");
    auto raw2 = ctx->Recv(ctx->PrevRank(), "a_okvs2");
    YACL_ENFORCE(raw1.size() == int64_t(bx1.size() * sizeof(uint128_t)));
    YACL_ENFORCE(raw2.size() == int64_t(bx2.size() * sizeof(uint128_t)));
    std::memcpy(okvs1.data(), raw1.data(), raw1.size());
    std::memcpy(okvs2.data(), raw2.data(), raw2.size());
  }

  // Step 4: strip k0 → H and map via U_{i-1} (surviving elements). The
  // unmapped values are queried against the OKVS pair with their raw
  // (unstripped) form, since the OKVS keys are the r'-blinded images. A
  // decoded pair is accepted iff the tag matches F_{k0}(y); for a blank
  // query this fails with probability 2^{-128} and the element is dropped.
  std::map<PRFVal, Element> htab = BuildHashLookup(p.U, p.ec);
  ElemSet Ui_new;
  std::vector<uint128_t> qkeys;
  for (const auto& v : s1) {
    auto h = StripKey(v, p.skinv, p.ec);
    auto it = htab.find(h);
    if (it != htab.end()) {
      Ui_new.push_back(it->second);
    } else {
      qkeys.push_back(HashPRFToUint128(v));
    }
  }
  if (!qkeys.empty()) {
    std::vector<uint128_t> y_dec(qkeys.size()), tag_dec(qkeys.size());
    bx1.Decode(absl::MakeSpan(qkeys), absl::MakeSpan(y_dec),
               absl::MakeSpan(okvs1), 8);
    bx2.Decode(absl::MakeSpan(qkeys), absl::MakeSpan(tag_dec),
               absl::MakeSpan(okvs2), 8);
    for (size_t i = 0; i < qkeys.size(); ++i) {
      PRFVal fk0_y = ComputeSinglePRF(y_dec[i], p.sk, p.ec);
      if (tag_dec[i] != HashPRFToUint128(fk0_y)) continue;
      Ui_new.push_back(y_dec[i]);  // Y_i^+ minus X_i^+, output-derivable
    }
  }

  // Step 5: add own X_i^+ locally (P1 never sees it) and send final U_i.
  {
    std::set<Element> ui_set(Ui_new.begin(), Ui_new.end());
    for (auto x : X_plus) ui_set.insert(x);
    Ui_new.assign(ui_set.begin(), ui_set.end());
  }
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
                       size_t add_max, size_t sub_max) {
  // ────── Preprocess ──────
  const size_t F_MRO = p.U.size() + add_max + sub_max;
  const size_t F_PSI = p.U.size() + sub_max;

  // P1 queries: (peer_excl \ Y_plus) ∪ Y_plus ∪ Y_minus, padded with
  // random dummies outside U_{i-1} to the fixed size F_MRO.
  std::set<Element> yp_set(Y_plus.begin(), Y_plus.end());
  ElemSet excl_no_plus;
  for (auto e : p.peer_excl)
    if (!yp_set.count(e)) excl_no_plus.push_back(e);

  ElemSet query = excl_no_plus;
  query.insert(query.end(), Y_plus.begin(), Y_plus.end());
  query.insert(query.end(), Y_minus.begin(), Y_minus.end());
  AppendDummies(query, F_MRO, p.U);

  auto fut_r = std::async(std::launch::async, [&]() {
    return MROPRF_Receiver(ctx, query, p.ec);
  });
  auto fut_s = std::async(std::launch::async, [&]() {
    MROPRF_Sender(ctx, F_MRO, p.sk, p.ec);  // P1 uses k1 as sender key
  });
  auto vals = fut_r.get(); fut_s.get();

  // Parse: excl | own_add | own_del | dummies
  const size_t n1 = excl_no_plus.size();
  const size_t n2 = Y_plus.size();
  const size_t n3 = Y_minus.size();
  p.prf_peer_excl.clear();
  p.prf_own_add.clear();
  p.prf_own_del.clear();
  for (size_t i = 0; i < n1; ++i)
    p.prf_peer_excl.push_back(RaiseToKey(vals[i], p.sk, p.ec));  // ^{k1} → F
  for (size_t i = 0; i < n2; ++i)
    p.prf_own_add.push_back(RaiseToKey(vals[n1 + i], p.sk, p.ec));
  for (size_t i = 0; i < n3; ++i)
    p.prf_own_del.push_back(RaiseToKey(vals[n1 + n2 + i], p.sk, p.ec));

  // ────── Deletion: single symmetric PSI ──────
  // Set union, not concatenation: a wrapped deletion window can re-select
  // an element that was deleted in an earlier round and now lives in the
  // peer-exclusive set. Without dedup the same PRF value would enter the
  // OKVS twice and crash the Paxos solver with duplicate keys.
  PRFSet psi_in;
  {
    std::set<PRFVal> psi_set;
    for (const auto& v : p.prf_peer_excl)
      if (psi_set.insert(v).second) psi_in.push_back(v);
    for (const auto& v : p.prf_own_del)
      if (psi_set.insert(v).second) psi_in.push_back(v);
  }
  // Padding: F_PSI - |set| dummy F-values from the Preprocess dummy pool.
  // If dedup shrank the union, the pool runs short; overflow entries are
  // re-raised pool images (one extra secret-key exponentiation keeps them
  // outside both parties' sets).
  const size_t n_dummy = F_PSI - psi_in.size();
  const size_t n_pool = vals.size() - n1 - n2 - n3;
  for (size_t i = 0; i < n_dummy; ++i) {
    PRFVal d;
    if (i < n_pool) {
      d = RaiseToKey(vals[n1 + n2 + n3 + i], p.sk, p.ec);
    } else {
      d = RaiseToKey(vals[n1 + n2 + n3 + (i - n_pool)], p.sk, p.ec);
      d = RaiseToKey(d, p.sk, p.ec);
    }
    psi_in.push_back(d);
  }

  ElemSet psi_p1 = HashPRFSet(psi_in);
  p.prf_U_minus.clear();
  if (F_PSI > 0) {
    okvs::Baxos psi_bx = MakeBaxos(F_PSI);
    auto fut_psi = std::async(std::launch::async, [&]() {
      return rr22::RR22PsiSend(ctx, psi_p1, psi_bx);
    });
    p.prf_U_minus = UnhashPRFSet(fut_psi.get(), psi_in);
  }

  // ────── Addition ──────
  // Step 1: ← P0  F_{k0}(U_{i-1}) and add_max blanks.
  PRFSet fk0_Uprev = RecvPRFVec(ctx, "a_fk0u");
  PRFSet blanks = RecvPRFVec(ctx, "a_blanks");
  YACL_ENFORCE(fk0_Uprev.size() == p.U.size());
  YACL_ENFORCE(blanks.size() == add_max);

  // Step 2: drop F_{k0}(U_i^-) (strip k1 from the PSI output F(U_i^-)),
  // append Y_i^+ images blinded by a fresh r', and pad with blanks to the
  // public size |U_{i-1}| - |U_i^-| + add_max. The r'-blinding prevents
  // P0 from testing its own additions against this set.
  yc::MPInt rp;
  yc::MPInt::RandomLtN(p.ec->GetOrder(), &rp);
  std::set<PRFVal> uminus_k0;
  for (const auto& v : p.prf_U_minus)
    uminus_k0.insert(StripKey(v, p.skinv, p.ec));
  PRFSet s1;
  for (const auto& v : fk0_Uprev)
    if (!uminus_k0.count(v)) s1.push_back(v);
  PRFSet masked_add;
  for (const auto& v : p.prf_own_add)
    masked_add.push_back(RaiseToKey(StripKey(v, p.skinv, p.ec), rp, p.ec));
  s1.insert(s1.end(), masked_add.begin(), masked_add.end());
  const size_t nb = add_max - Y_plus.size();
  s1.insert(s1.end(), blanks.begin(), blanks.begin() + nb);
  SendPRFVec(ctx, s1, "a_s1");

  // Step 3: encode two OKVS instances of capacity add_max (public size
  // and seed). Keys are the r'-blinded images; values are the plaintext
  // y and a tag of F_{k0}(y). Dummy pairs fill the capacity, so P0 cannot
  // tell the number of real additions. P0 decodes locally, so P1 learns
  // nothing about which of its additions were mapped.
  std::vector<uint128_t> keys, val_y, val_tag;
  for (size_t i = 0; i < Y_plus.size(); ++i) {
    keys.push_back(HashPRFToUint128(masked_add[i]));
    val_y.push_back(Y_plus[i]);
    val_tag.push_back(
        HashPRFToUint128(StripKey(p.prf_own_add[i], p.skinv, p.ec)));
  }
  std::random_device rd;
  std::mt19937_64 gen(rd());
  {
    std::set<uint128_t> key_set(keys.begin(), keys.end());
    while (keys.size() < add_max) {
      uint64_t hi = gen();
      uint64_t lo = gen();
      uint128_t k = (static_cast<uint128_t>(hi) << 64) | lo;
      if (key_set.count(k)) continue;
      key_set.insert(k);
      keys.push_back(k);
      val_y.push_back((static_cast<uint128_t>(gen()) << 64) | gen());
      val_tag.push_back((static_cast<uint128_t>(gen()) << 64) | gen());
    }
  }
  okvs::Baxos bx1 = MakeBaxos(add_max);
  okvs::Baxos bx2 = MakeBaxos(add_max);
  std::vector<uint128_t> okvs1(bx1.size()), okvs2(bx2.size());
  if (add_max > 0) {
    bx1.Solve(absl::MakeSpan(keys), absl::MakeSpan(val_y),
              absl::MakeSpan(okvs1), nullptr, 8);
    bx2.Solve(absl::MakeSpan(keys), absl::MakeSpan(val_tag),
              absl::MakeSpan(okvs2), nullptr, 8);
    ctx->SendAsync(ctx->NextRank(),
                   yacl::ByteContainerView(okvs1.data(),
                                           okvs1.size() * sizeof(uint128_t)),
                   "a_okvs1");
    ctx->SendAsync(ctx->NextRank(),
                   yacl::ByteContainerView(okvs2.data(),
                                           okvs2.size() * sizeof(uint128_t)),
                   "a_okvs2");
  }

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
