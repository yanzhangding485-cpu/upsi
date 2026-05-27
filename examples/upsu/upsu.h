// Updatable Private Set Union (UPSU) Protocol
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "examples/upsi/rr22/okvs/baxos.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/context.h"

namespace upsu {

namespace yc = yacl::crypto;

// ── Types ──
using Element  = uint128_t;
using PRFVal   = std::string;          // serialized EC point (32 bytes, FourQ)
using ElemSet  = std::vector<Element>;
using PRFSet   = std::vector<PRFVal>;

static constexpr size_t kEcPointBytes = 32;

// ── PRF helpers ──
PRFVal HashToCurve(Element x, const std::shared_ptr<yc::EcGroup>& ec);
PRFVal ComputeSinglePRF(Element x, const yc::MPInt& sk,
                        const std::shared_ptr<yc::EcGroup>& ec);
PRFVal RaiseToKey(const PRFVal& v, const yc::MPInt& sk,
                  const std::shared_ptr<yc::EcGroup>& ec);
PRFVal StripKey(const PRFVal& v, const yc::MPInt& sk_inv,
                const std::shared_ptr<yc::EcGroup>& ec);
uint128_t HashPRFToUint128(const PRFVal& v);
std::map<PRFVal, Element> BuildHashLookup(
    const ElemSet& elements, const std::shared_ptr<yc::EcGroup>& ec);

// ── Network I/O ──
void SendPRFVec(const std::shared_ptr<yacl::link::Context>& ctx,
                const PRFSet& vec, const std::string& tag);
PRFSet RecvPRFVec(const std::shared_ptr<yacl::link::Context>& ctx,
                   const std::string& tag);
void SendElemVec(const std::shared_ptr<yacl::link::Context>& ctx,
                 const ElemSet& vec, const std::string& tag);
ElemSet RecvElemVec(const std::shared_ptr<yacl::link::Context>& ctx,
                     const std::string& tag);
void SendUint32(const std::shared_ptr<yacl::link::Context>& ctx,
                uint32_t val, const std::string& tag);
uint32_t RecvUint32(const std::shared_ptr<yacl::link::Context>& ctx,
                     const std::string& tag);

// ── MROPRF (pure ECDH — no EcdhSender/EcdhReceiver dependency) ──

// Receiver: gets F_{sender_sk}(x) = H(x)^{sender_sk} for all queried inputs
PRFSet MROPRF_Receiver(const std::shared_ptr<yacl::link::Context>& ctx,
                        const ElemSet& inputs,
                        const std::shared_ptr<yc::EcGroup>& ec);

// Sender: applies sender_sk to the receiver's blinded points
void MROPRF_Sender(const std::shared_ptr<yacl::link::Context>& ctx,
                    size_t receiver_size,
                    const yc::MPInt& sender_sk,
                    const std::shared_ptr<yc::EcGroup>& ec);

// ── Party state ──
struct Party {
  yc::MPInt sk;       // k0 (for P0) or k1 (for P1)
  yc::MPInt skinv;    // sk^{-1} mod order
  std::shared_ptr<yc::EcGroup> ec;

  ElemSet X;           // own private set
  ElemSet U;           // union result
  ElemSet peer_excl;   // peer's exclusive elements: Y\X (P0) or X\Y (P1)

  // preprocess results — double-keyed PRF values
  PRFSet prf_peer_excl;  // F(peer_excl) — mapped to plaintext
  PRFSet prf_own_add;    // F(own additions) — mapped to plaintext

  // deletion phase
  PRFSet prf_peer_del;   // F(peer deletions) — UNmapped
  PRFSet prf_D_own;      // F(D_X) or F(D_Y) — mapped
  PRFSet prf_U_minus;    // F(U_i^-) — combined, mostly UNmapped
};

// ── Helpers ──
okvs::Baxos MakeBaxos(size_t max_items);

// ── Protocol ──
void InitP0(const std::shared_ptr<yacl::link::Context>& ctx,
            Party& p, const ElemSet& X);
void InitP1(const std::shared_ptr<yacl::link::Context>& ctx,
            Party& p, const ElemSet& Y);

ElemSet UpdateRoundP0(const std::shared_ptr<yacl::link::Context>& ctx,
                       Party& p,
                       const ElemSet& X_plus, const ElemSet& X_minus,
                       okvs::Baxos& del_baxos);
ElemSet UpdateRoundP1(const std::shared_ptr<yacl::link::Context>& ctx,
                       Party& p,
                       const ElemSet& Y_plus, const ElemSet& Y_minus,
                       okvs::Baxos& del_baxos);

}  // namespace upsu
