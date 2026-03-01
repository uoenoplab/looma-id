---
title: "Looma: Low-Latency Post-Quantum Mutual Authentication for TLS"
abbrev: "Looma"
category: info

docname: draft-ma-cfrg-looma-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: Security
workgroup: CFRG
keyword:
 - post-quantum cryptography
 - TLS authentication
 - online/offline signatures
 - WOTS+
 - Dilithium
 - mutual authentication

venue:
  group: CFRG
  type: Research Group
  mail: cfrg@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/cfrg/
  github: 
  latest: 

author:
 -
    fullname: Xinshu Ma
    organization: University of Edinburgh
    email: x.ma@ed.ac.uk
 -
    fullname: Michio Honda
    organization: University of Edinburgh
    email: michio.honda@ed.ac.uk

normative:

informative:

---

# abstract

This document specifies Looma, a low-latency post-quantum authentication architecture for TLS 1.3. Looma is designed for high-rate mutual-TLS deployments in cloud and microservice environments. It applies the online/offline signature paradigm: the expensive post-quantum signature (Dilithium-2) is performed offline, while the latency-critical path uses only a fast one-time WOTS+ signature whose public key is pre-distributed and cryptographically bound to the long-term Dilithium public key. Two fallback modes guarantee correctness on first contact or cache miss. Looma preserves EUF-CMA security at NIST Level 1 and requires only new signature formats and one optional TLS extension.


# Introduction

Quantum computers threaten the cryptographic foundations of classical TLS. Post-quantum signature schemes standardized by NIST (Dilithium, Falcon, SPHINCS+) impose significantly higher computational and bandwidth costs than classical schemes during the TLS handshake. In cloud environments these costs become a serious deployment barrier.

Modern cloud applications are built from microservices and serverless functions. Each inter-service RPC triggers a fresh TLS handshake. Containers and pods are frequently created and destroyed, rendering session resumption ineffective. Service-mesh sidecars (Istio, Linkerd, etc.) add extra mTLS hops along every path. The resulting handshake rate is orders of magnitude higher than on the public Internet.

Datacenter networks are engineered for sub-50 µs fabric latency; therefore the dominant delay is host cryptographic processing. Mutual authentication (mTLS) is mandatory inside the trust boundary to prevent unauthorized service-to-service access. In mTLS both endpoints sign and verify, doubling the authentication cost compared with server-only TLS. When post-quantum signatures are used, authentication can consume 54–70 % of total handshake latency (see {{Looma-NDSS26}} for measurements).

Existing accelerations do not close this gap:

* Hardware offloading (GPUs, SmartNICs) reduces CPU usage but adds PCIe/network round-trips that do not shrink end-to-end latency.  
* Protocol optimisations (TLS 1.3 1-RTT, KEMTLS, session resumption) reduce round-trips or replace signatures with KEMs, yet still leave the remaining signature operations on the critical path.  
* Cryptographic optimisations focus primarily on key exchange; authentication remains the bottleneck for mTLS.

Looma addresses the authentication bottleneck directly. It splits each post-quantum signature into an offline pre-computation phase (performed asynchronously by a background plane) and an ultra-fast online phase executed during the handshake. The online phase uses only a one-time WOTS+ signature whose public key has been pre-distributed through a simple KeyDist service. Two fallback modes guarantee interoperability even on first contact. The design is fully compatible with TLS 1.3 and requires no changes to the wire format of existing messages beyond new signature encodings.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals.

## Notations
TODO: Symbols that will be used in the following sections, e.g., digital signatures and Looma Authentication section.

# Digital Signatures

## Digital Signatures

A digital signature scheme is a tuple of algorithms (KeyGen, Sign, Verify) with security parameter κ:

(pk, sk) ← KeyGen(κ)  
σ ← Sign(m, sk)  
b ∈ {0,1} ← Verify(m, σ, pk)

## Online/Offline Signatures

An online/offline signature scheme extends the above with two additional algorithms (PreSign, FastSign):

ρ ← PreSign(sk)  
σ ← FastSign(m, ρ, sk)  
b ∈ {0,1} ← Verify(m, σ, pk)

The offline phase (PreSign) performs heavy computation independent of the message. The online phase (FastSign) is extremely fast. Looma instantiates this paradigm with Dilithium-2 (offline) and WOTS+ (online).

## One-Time Signatures

### One-Time Signature
TODO: overview of OTS

### WOTS+
TODO: preliminaries of WOTS+ 
Looma uses the Winternitz One-Time Signature Plus (WOTS+) scheme {{RFC8391}} {{SPHINCS+}} with parameter w = 4 and the Haraka-512 hash function (chosen for performance; SHA-256 and BLAKE3 are also permitted). A WOTS+ key pair consists of 67 secret values (for 256-bit message + checksum) and the corresponding public key obtained by iterating the chaining function w-1 times.

# TLS Authentication

## TLS 1.3 Handshake Overview

A TLS 1.3 handshake consists of two flights. The client sends ClientHello; the server replies with ServerHello, EncryptedExtensions, Certificate (server), CertificateVerify (server), and Finished. When mutual authentication is required the server also sends CertificateRequest. The client then sends Certificate (client), CertificateVerify (client), and Finished.

All signatures are computed over a transcript hash (HT) that includes every handshake message up to the point the signature is generated (see {{RFC8446}} Section 4.4.1). The transcript guarantees that the signature binds the entire handshake, including the key exchange and certificate chain.

## mTLS Messages and Processing
TODO: Explain what is mutual authentication, why cloud needs it

The three additional messages in mTLS are:

* **CertificateRequest** (sent by server in the first flight): indicates that client authentication is required and may carry extensions. In Looma this message also carries the optional "looma_cache_hint" extension (see Section 5.3.2).

* **Certificate** (sent by both endpoints): carries the X.509 certificate containing the long-term Dilithium-2 public key. Certificates are assumed to be pre-issued; their validation (including the CA signature) occurs before the handshake begins and therefore incurs no per-handshake cost.

* **CertificateVerify** (sent by both endpoints after their Certificate message): contains the digital signature over the transcript hash HT. In classical TLS this is the ECDSA/RSA signature produced with the private key corresponding to the certificate. In Looma this field carries a Looma signature (WOTS+ plus optional fallback components) instead.

The server processes the client CertificateVerify after receiving the client’s Finished message. The client processes the server CertificateVerify before sending its own Finished message. Any failure aborts the handshake with a fatal alert.

# The Looma Authentication Architecture

## Overall Design

Looma organises each endpoint into two logical planes (Figure 4 in {{Looma-NDSS26}}):

* **Foreground plane** (latency-critical path): performs only the fast online WOTS+ signing and verification operations during the TLS handshake.  
* **Background plane** (asynchronous): continuously generates fresh WOTS+ key pairs, organises them into Merkle trees, signs the roots with the long-term Dilithium-2 key, uploads the signed records to the KeyDist service, and fetches peers’ records.

A lightweight, untrusted KeyDist service acts as a simple repository for these signed public-key batches. Because every key record is cryptographically signed by the owner’s Dilithium-2 key, KeyDist may be compromised without breaking authentication security.

Each endpoint possesses a long-term Dilithium-2 key pair (PK_d2, SK_d2). The public key is certified by an internal CA in the usual X.509 fashion. During a handshake the Certificate and CertificateVerify messages still carry PK_d2 (for fallback verification) but the actual online signature is a WOTS+ signature whose public key was pre-distributed via KeyDist.

The design guarantees that, in the common case of cache hit, both signing and verification complete in < 1 µs while preserving full NIST Level 1 post-quantum security.

## Assumptions (Threat Model and System Model)

- The cloud substrate (hypervisor, host OS, service mesh proxies) is trusted at bootstrap but subject to later compromise.  
- Endpoints communicate only with a small, stable set of peers (typical of microservices).  
- AEAD record protection, hash functions, and the underlying Dilithium-2 and WOTS+ schemes are existentially unforgeable.  
- The KeyDist service is untrusted; all security is cryptographic.

## Offline Key Distribution

### Key Pre-generation

Each endpoint maintains one or more verifier groups (initially a single group containing all known peers). For each group it periodically generates a fresh batch of WOTS+ key pairs. It organises the corresponding public keys into a Merkle tree and signs the root with SK_d2. The resulting key record (public keys, Merkle root, Dilithium signature, certificate, metadata) is ready for upload.

### Key Distribution
TODO: Overview of Key Distribution and why we need it

#### KeyDist Server

KeyDist is a simple storage service reachable over a long-term TLS channel. It stores <KeyUpdate, keyrecord, owner-id> tuples and performs only syntactic validation (certificate check, Merkle-tree reconstruction, Dilithium signature verification). It does not need to be trusted for security.

#### Key Upload

The background plane uploads a new key record whenever the local queue size for any verifier group falls below a configurable threshold. The upload is sent over the long-term authenticated channel to KeyDist.

#### Key Fetch

Peers periodically issue KeyFetch requests for each known owner-id. Upon receipt they verify the Dilithium signature on the root, reconstruct the Merkle tree if needed, and cache the WOTS+ public keys indexed by their leaf identifier.

## Online Authentication
TODO: Overview of the online authentication


### Fast Signing

When the foreground plane must produce a CertificateVerify:

1. Dequeue a fresh WOTS+ secret key SK from the local queue for the appropriate verifier group.  
2. Compute the one-time signature  
   σ_wots ← FastSign(HT, SK, r)  
   where HT is the current transcript hash and r is a fresh 32-byte nonce.  
3. Construct the Looma signature according to the chosen fallback mode (Section 5.3) and place it in the CertificateVerify.payload field.


### Fast Verification

Upon receipt of a peer’s CertificateVerify:

1. Extract σ_wots, r, and pk_id.  
2. If a cached WOTS+ public key PK for (peer, pk_id) exists, reconstruct the expected public key PK* from σ_wots, HT, and r and compare it with the cached value (constant-time).  
3. If no cached key exists, invoke the fallback verification procedure of the chosen mode.

## Fallback Strategy

Looma defines two modes. The hybrid mode is RECOMMENDED for production deployments.

### Dual-Signature Fallback

The signer always includes the full set of fallback components (WOTS+ signature, Merkle proof, Merkle root, Dilithium signature on the root, nonce, pk_id). The verifier uses the cached key if present; otherwise it performs the complete verification chain. This mode adds a fixed bandwidth overhead but requires no extra TLS extension.

#### Signature Construction

Looma-dual = {
  wots_signature,
  merkle_proof,
  merkle_root,
  dilithium_signature_on_root,
  nonce,
  pk_id
}

#### Signing Operation

Same as FastSign plus construction of the Merkle proof and Dilithium signature on the root.

#### Verification Operation

If cached key present → FastVerify only.  
Else → Dilithium-Verify(root) + Merkle-Verify + WOTS+ reconstruction.


### Hybrid Fallback

The server includes a compact Bloom filter of currently cached peer IDs in a new "looma_cache_hint" extension inside CertificateRequest. The client inspects the filter for its own ID:

* Cache hit → sends the minimal hybrid-hit signature (σ_wots, r, pk_id).  
* Cache miss (or false positive) → sends the full hybrid-miss signature (identical to dual-signature).

On a Bloom-filter false positive the server detects the mismatch during verification, sends the "bad_offline_sig" alert, and falls back to a full Dilithium handshake. The Bloom filter size (56 bytes for ≤15 peers) fits comfortably inside a single extension.


#### Signature Construction

hybrid-hit = { wots_signature, nonce, pk_id }  
hybrid-miss = { wots_signature, merkle_proof, merkle_root, dilithium_signature_on_root, nonce, pk_id }

#### Signing Operation

Identical to the dual-signature case when the client’s own ID is not in the Bloom filter.

#### Verification Operation

Same as dual-signature, plus a false-positive check: on Bloom-filter false positive the server MUST send a "bad_offline_sig" alert and fall back to a full Dilithium handshake.

## Looma signature construction
 TODO: talk about any non-hash-based PQ signature can be turned into a Online/Offline style.
Example construction: Dilthium-2 and WOTS+

### Implementation Optimizations
TODO: list what we did clearly and for wots+ optimization, such that  other people can understand and do the same optimization as us.



## TLS Modifications

* CertificateVerify.payload now carries a Looma signature instead of a raw Dilithium signature.  
* An optional "looma_cache_hint" extension (IANA value to be assigned) may appear in CertificateRequest.  
* No other wire-format changes are required.



# Security Considerations

Looma achieves EUF-CMA security at NIST Level 1 provided that either Dilithium-2 or WOTS+ (with Haraka-512, n=256, w=4) remains unbroken.  

A forgery requires either:
- breaking Dilithium-2 on the Merkle root, or
- forging a WOTS+ signature on an authentic public key.

Both events have negligible probability under the respective hardness assumptions. The KeyDist service can at worst cause denial-of-service; it cannot inject forged keys because every key record carries a verifiable Dilithium-2 signature.

Implementations MUST enforce one-time use of each WOTS+ key (local indexing) and MUST reject signatures outside the validity period.

# IANA Considerations

This document has no IANA actions.  
(The "looma_cache_hint" extension value will be requested in a future version once consensus emerges.)

# References

All other values are already defined in existing registries.


--- back

# Acknowledgments
{:numbered="false"}

The authors thank the NDSS 2026 reviewers and the CFRG community for valuable feedback.