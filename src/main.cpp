/* main.cpp - PVSS dealing benchmark (fresh deal, no re-share scaffolding).
 *
 * Copyright (C) 2021, LWE-PVSS
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 **/

#include <cassert>
#include <cmath>
#include <random>
#include <chrono>
#include <string>
#include <sys/time.h>
#include <sys/resource.h>
using namespace std;

#include <NTL/version.h>
#include "regevEnc.hpp"
#include "regevProofs.hpp"
#include "bulletproof.hpp"

using namespace ALGEBRA;
using namespace REGEVENC;

int main(int argc, char** argv) {
    int nParties = 512;
    if (argc > 1) nParties = std::stoi(argv[1]);
    int tOverride = -1;
    if (argc > 2) tOverride = std::stoi(argv[2]);

    std::cout << "nParties="<<nParties;
    if (tOverride > 0) std::cout << " threshold="<<tOverride;
    std::cout << std::endl;

    KeyParams kp(nParties);
    GlobalKey gpk("testContext", kp);
    if (tOverride > 0) gpk.tee = tOverride;
    if (gpk.tee <= 0) {
        std::cerr << "tee=" << gpk.tee << " after construction/override; "
                     "pass t explicitly on the command line for small n "
                     "(the default formula ((n-1)/(2*ell))*ell yields 0)\n";
        return 1;
    }
    std::cout <<"{ kay:"<<gpk.kay<<", enn:"<<gpk.enn<<", tee:"<<gpk.tee
      <<", sigmaEnc1:"<<gpk.sigmaEnc1<<", sigmaEnc2:"<<gpk.sigmaEnc2<<" }\n";

    TernaryEMatrix::init();
    MerlinRegev mer;
    PedersenContext ped;
    SharingParams ssp(interval(1,gpk.enn+1), gpk.tee);
    VerifierData vd(gpk, ped, mer, ssp);
    ProverData pd(vd);

    // --- Key generation for all n parties (the dealer needs B = stack of all pk's) ---
    std::vector<ALGEBRA::EVector> kgNoise(gpk.enn);
    std::vector<ALGEBRA::EVector> sk(gpk.enn);
    std::vector<ALGEBRA::EVector> pk(gpk.enn);
    auto start = chrono::steady_clock::now();
    crsTicks = 0;
    for (int i=0; i<gpk.enn; i++) {
        std::tie(sk[i],pk[i]) = gpk.genKeys(&kgNoise[i]);
        gpk.addPK(pk[i]);
    }
    gpk.setKeyHash();
    auto end = chrono::steady_clock::now();
    auto ticks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    std::cout <<gpk.enn<<" keyGens in "<<ticks<<" milliseconds, avg="<<(ticks/double(gpk.enn))
        << " ("<< (crsTicks/double(gpk.enn)) << " for s x A)\n";

    // --- Fresh PVSS dealing ---
    // The dealer picks a random degree-(t-1) polynomial p, and ptxt[j-1] = p(j).
    // ssp.randomSharing fills sshr[0]=secret=p(0), sshr[i]=p(i) for i=1..n.
    ALGEBRA::SVector sshr;
    ssp.randomSharing(sshr);

    ALGEBRA::SVector ptxt;   // n-vector of shares: ptxt[j-1] = sshr[j] = p(j)
    resize(ptxt, gpk.enn);
    for (int j=0; j<gpk.enn; j++) ptxt[j] = sshr[j+1];

    // Time the single dealer encryption (this IS the PVSS dealing).
    ALGEBRA::EVector encRnd;
    REGEVENC::GlobalKey::CtxtPair eNoise;
    start = chrono::steady_clock::now();
    auto ctxt = gpk.encrypt(ptxt, encRnd, eNoise);
    end = chrono::steady_clock::now();
    ticks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    std::cout <<"encryption in "<<ticks<<" milliseconds\n";

    // --- Decrypt-share benchmark (party 0 pulls its own share out of the dealing) ---
    // In GHL21e, decrypt-share is one lattice decryption: sshr[partyIdx+1] = ptxt[partyIdx].
    int partyIdx = 0;
    ALGEBRA::Element decNoiseElt;
    start = chrono::steady_clock::now();
    ALGEBRA::Scalar myShare = gpk.decrypt(sk[partyIdx], partyIdx, ctxt, &decNoiseElt);
    end = chrono::steady_clock::now();
    auto decryptUs = chrono::duration_cast<chrono::microseconds>(end - start).count();
    std::cout <<"decryption in "<<(decryptUs/1000.0)<<" milliseconds\n";
    if (myShare != ptxt[partyIdx])
        std::cout << "decryption error\n";

    // --- Set up pt1 witness for the Shamir-structure proof (proveReShare) ---
    // proveReShare's parity-check constraint is H*[Σⱼ lagrange[j]·pt1[j], pt2[0..n-1]] = 0.
    // With pt1 = first t entries of ptxt, Σⱼ lagrange[j]·pt1[j] = p(0) = secret,
    // so the parity check holds iff the full n-vector ptxt lies on a degree-(t-1)
    // polynomial — which is exactly the Shamir-structure property a PVSS transcript
    // must prove.
    ALGEBRA::SVector pt1;
    resize(pt1, gpk.tee);
    for (int j=0; j<gpk.tee; j++) pt1[j] = ptxt[j];
    vd.pt1Com = commit(pt1, vd.pt1Idx, vd.Gs, pd.pt1Rnd);
    vd.mer->processPoint("RegevDecPtxt", vd.pt1Com);
    addSVec2Map(pd.linWitness, pt1, vd.pt1Idx);

    // Populate zero-valued witnesses at indices that proveDecryption and proveKeyGen
    // would normally fill. We skip those proofs (they're re-share / one-time-setup
    // specific and not part of a fresh PVSS deal), but the aggregated constraint
    // system still references those indices inside proveSmallness (which does
    // expandConstraints from index 0) and the Shamir parity check. Without these
    // zero placeholders, aggregateProver's witness-trimming loop cascades and erases
    // all witnesses whenever it hits an index missing from linWitness.
    {
        int skLen = gpk.kay * GlobalKey::ell;
        auto fillZeros = [&](int startIdx, int len) {
            CRV25519::Scalar zero;
            for (int i=0; i<len; i++) pd.linWitness[startIdx + i] = zero;
        };
        fillZeros(vd.sk1Idx, skLen);
        fillZeros(vd.sk2Idx, skLen);
        fillZeros(vd.dCompHiIdx, JLDIM);
        fillZeros(vd.dPadHiIdx, PAD_SIZE);
        fillZeros(vd.dCompLoIdx, JLDIM);
        fillZeros(vd.dPadLoIdx, PAD_SIZE);
        fillZeros(vd.sk2CompIdx, JLDIM);
        fillZeros(vd.sk2PadIdx, PAD_SIZE);
        fillZeros(vd.kCompHiIdx, JLDIM);
        fillZeros(vd.kPadHiIdx, PAD_SIZE);
        fillZeros(vd.kCompLoIdx, JLDIM);
        fillZeros(vd.kPadLoIdx, PAD_SIZE);
    }

    // --- Proof generation (dealer side) ---
    auto stepStart = chrono::steady_clock::now();
    proveEncryption(pd, ctxt.first, ctxt.second, ptxt, encRnd, eNoise.first, eNoise.second);
    auto stepEnd = chrono::steady_clock::now();
    auto proveEncryptionTicks =
        chrono::duration_cast<chrono::milliseconds>(stepEnd - stepStart).count();
    std::cout << "proveEncryption in "<<proveEncryptionTicks<<" milliseconds\n";

    stepStart = chrono::steady_clock::now();
    SVector lagrange = vd.sp->lagrangeCoeffs(interval(1,gpk.tee+1));
    proveReShare(pd, lagrange, pt1, ptxt);
    stepEnd = chrono::steady_clock::now();
    auto proveShamirTicks =
        chrono::duration_cast<chrono::milliseconds>(stepEnd - stepStart).count();
    std::cout << "proveShamir in "<<proveShamirTicks<<" milliseconds\n";

    stepStart = chrono::steady_clock::now();
    proveSmallness(pd);
    stepEnd = chrono::steady_clock::now();
    auto proveSmallnessTicks =
        chrono::duration_cast<chrono::milliseconds>(stepEnd - stepStart).count();
    std::cout << "proveSmallness in "<<proveSmallnessTicks<<" milliseconds\n";

    // Aggregate linear/quadratic constraints into a single pair of bulletproof statements.
    start = chrono::steady_clock::now();
    ReadyToProve rtp;
    rtp.aggregateProver(pd);

    auto merLin = *vd.mer;
    merLin.processConstraint("linear", rtp.linCnstr);
    auto merQuad = *vd.mer;
    merQuad.processConstraint("quadratic", rtp.quadCnstr);

    rtp.flattenLinPrv(pd);
    rtp.flattenQuadPrv(pd);

    ReadyToVerify rtv = rtp; // copy without the secret variables

    auto merLinVer = merLin;
    DLPROOFS::LinPfTranscript pfL("Linear");
    pfL.C = rtp.linCom;

    end = chrono::steady_clock::now();
    auto aggregateTicks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    std::cout << "aggregate in "<<aggregateTicks<<" milliseconds\n";

    // Linear bulletproof
    start = chrono::steady_clock::now();
    DLPROOFS::proveLinear(pfL, rtp.lComRnd, merLin, rtp.linWtns.data(),
            rtp.linStmnt.data(), rtp.linGs.data(), rtp.linGs.size());
    end = chrono::steady_clock::now();
    auto proveLinTicks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    std::cout << "proveLinear in "<<proveLinTicks<<" milliseconds\n";

    start = chrono::steady_clock::now();
    bool linOK = DLPROOFS::verifyLinear(pfL, rtv.linStmnt.data(), rtv.linGs.data(),
                      rtv.linGs.size(), rtv.linCnstr.equalsTo, merLinVer);
    end = chrono::steady_clock::now();
    auto verifyLinTicks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    if (!linOK) std::cout << "failed linear verification\n";
    std::cout << "verifyLinear in "<<verifyLinTicks<<" milliseconds\n";

    // Quadratic bulletproof
    auto merQuadVer = merQuad;
    DLPROOFS::QuadPfTranscript pfQ("Quadratic");
    pfQ.C = rtp.quadCom;

    start = chrono::steady_clock::now();
    DLPROOFS::proveQuadratic(pfQ, rtp.qComRnd, merQuad, rtp.quadGs.data(),
                rtp.quadWtnsG.data(), rtp.quadHs.data(), rtp.quadWtnsH.data(),
                rtp.quadGs.size());
    end = chrono::steady_clock::now();
    auto proveQuadTicks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    std::cout << "proveQuadratic in "<<proveQuadTicks<<" milliseconds\n";

    start = chrono::steady_clock::now();
    bool quadOK = DLPROOFS::verifyQuadratic(pfQ, rtv.quadGs.data(), rtv.quadHs.data(),
                        rtp.quadGs.size(), rtv.quadCnstr.equalsTo, merQuadVer,
                        rtv.offstG.data(), rtv.offstH.data());
    end = chrono::steady_clock::now();
    auto verifyQuadTicks = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    if (!quadOK) std::cout << "failed quadratic verification\n";
    std::cout << "verifyQuadratic in "<<verifyQuadTicks<<" milliseconds\n";

    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    std::cout << " max mem: " << ru.ru_maxrss << " kilobytes\n";

    // Transcript size: ciphertext + linear bulletproof + quadratic bulletproof.
    {
        constexpr size_t kPointBytes  = 32;
        constexpr size_t kScalarBytes = 32;
        size_t bytesPerElement = ALGEBRA::scalarsPerElement() * ALGEBRA::bytesPerScalar();
        size_t ctxtSize = (static_cast<size_t>(gpk.kay) + static_cast<size_t>(gpk.enn)) * bytesPerElement;
        size_t linSize = kPointBytes
                       + (pfL.Ls.size() + pfL.Rs.size()) * kPointBytes
                       + kPointBytes
                       + 2 * kScalarBytes;
        size_t quadSize = kPointBytes
                        + (pfQ.Ls.size() + pfQ.Rs.size()) * kPointBytes
                        + 2 * kPointBytes
                        + 3 * kScalarBytes;
        size_t totalBytes = ctxtSize + linSize + quadSize;
        std::cout << "transcript bytes: ctxt=" << ctxtSize
                  << ", linProof=" << linSize
                  << ", quadProof=" << quadSize
                  << ", total=" << totalBytes
                  << " (" << (totalBytes / 1024.0) << " KiB)\n";
    }

    return 0;
}
