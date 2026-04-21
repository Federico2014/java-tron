package org.tron.common.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import org.tron.common.crypto.ECKey.ECDSASignature;

/**
 * Timing benchmarks around secp256k1 signature recovery and the underlying modular inverse.
 *
 * <p>Motivation: the block #81993268 missed-block incident. Transaction
 * {@code 73350db0...} carried an ECDSA signature whose {@code r} value drove
 * {@link BigInteger#modInverse} into a pathological slow path (&gt;8 s on x86_64), exceeding
 * the 3-second block production slot.
 *
 * <p>Three tests, each emitting avg/max timings to stdout and to the test log:
 * <ol>
 *   <li>{@link #testModInverse} — isolates the modular inverse step itself across
 *       {@link InvStrategy}.
 *   <li>{@link #testSignatureRecoveryByInverseMethod} — end-to-end signature recovery with
 *       the {@code rInv} step swapped across {@link InvStrategy}.
 *   <li>{@link #testSignatureRecoveryEcKeyVsEcKeyV2} — end-to-end signature recovery comparing
 *       pure-Java {@link ECKey} against the JNI-backed {@link ECKeyV2}.
 * </ol>
 */
@Slf4j
public class ModInverseTest {

  // --- Pathological input from block #81993268 ---------------------------------------------

  private static final byte[] BLOCK_81993268_TX_HASH = Hex.decode(
      "73350db08350056f128734ec26444ea549299256ea99e0aaab7f5ad60d0d552a");
  private static final byte[] BLOCK_81993268_R = Hex.decode(
      "6f9ef9d226dc87bceb571c859614fa7dcdbe0be6e1dfea54fb99cb9970fa09af");
  private static final byte[] BLOCK_81993268_S = Hex.decode(
      "91a945e3b0eb1eea559c89cc4bd16932bfabcf0e63a0e0848fbb7fa0db4dcfd6");
  // v=0x00 on TronScan means recId 0 → header byte 27 (0x1B)
  private static final ECDSASignature BLOCK_81993268_SIG = ECDSASignature.fromComponents(
      BLOCK_81993268_R, BLOCK_81993268_S, (byte) 27);

  private enum InvStrategy {
    JDK_MOD_INVERSE,
    BC_MOD_ODD_INVERSE,
    BC_MOD_ODD_INVERSE_VAR
  }

  // =========================================================================================
  // Test 1 — isolated modular inverse
  // =========================================================================================

  @Test
  public void testModInverse() {
    BigInteger n = ECKey.CURVE.getN();
    BigInteger pathR = new BigInteger(1, BLOCK_81993268_R);
    BigInteger randR = new BigInteger(255, new Random(42)).mod(n);

    runModInverseBench("pathological r (block #81993268)", n, pathR, 2, 10);
    runModInverseBench("random r", n, randR, 10, 10);
  }

  // =========================================================================================
  // Test 2 — end-to-end recovery, rInv step parameterised by InvStrategy
  // =========================================================================================

  @Test
  public void testSignatureRecoveryByInverseMethod() {
    runRecoveryByStrategy("pathological block #81993268",
        new byte[][] {BLOCK_81993268_TX_HASH},
        new ECDSASignature[] {BLOCK_81993268_SIG}, 2, 10);

    Samples samples = randomSamples(200);
    runRecoveryByStrategy("random sigs", samples.hashes, samples.sigs, 20, samples.size());
  }

  // =========================================================================================
  // Test 3 — ECKey (pure Java) vs ECKeyV2 (JNI / libsecp256k1)
  // =========================================================================================

  @Test
  public void testSignatureRecoveryEcKeyVsEcKeyV2() {
    runRecoveryEcKeyVsV2("pathological block #81993268",
        new byte[][] {BLOCK_81993268_TX_HASH},
        new ECDSASignature[] {BLOCK_81993268_SIG}, 2, 10);

    Samples samples = randomSamples(500);
    runRecoveryEcKeyVsV2("random sigs", samples.hashes, samples.sigs, 50, samples.size());
  }

  // =========================================================================================
  // Bench drivers
  // =========================================================================================

  private static void runModInverseBench(String label, BigInteger n, BigInteger r,
      int warmup, int iterations) {
    // Correctness: all three implementations must agree, and r * rInv ≡ 1 (mod n).
    BigInteger jdkInv = r.modInverse(n);
    BigInteger bcInv = BigIntegers.modOddInverse(n, r);
    BigInteger bcVarInv = BigIntegers.modOddInverseVar(n, r);
    assertEquals("BC modOddInverse disagrees with JDK for " + label, jdkInv, bcInv);
    assertEquals("BC modOddInverseVar disagrees with JDK for " + label, jdkInv, bcVarInv);
    assertEquals("r * rInv mod n != 1 for " + label,
        BigInteger.ONE, r.multiply(jdkInv).mod(n));

    for (int i = 0; i < warmup; i++) {
      r.modInverse(n);
      BigIntegers.modOddInverse(n, r);
      BigIntegers.modOddInverseVar(n, r);
    }
    long[] jdk = timeIt(iterations, i -> r.modInverse(n));
    long[] bc = timeIt(iterations, i -> BigIntegers.modOddInverse(n, r));
    long[] bcv = timeIt(iterations, i -> BigIntegers.modOddInverseVar(n, r));

    report("modInverse", label, iterations,
        new Row("BigInteger.modInverse       ", jdk),
        new Row("BigIntegers.modOddInverse   ", bc),
        new Row("BigIntegers.modOddInverseVar", bcv));
  }

  private static void runRecoveryByStrategy(String label, byte[][] hashes,
      ECDSASignature[] sigs, int warmup, int iterations) {
    int n = hashes.length;
    // Correctness: recovery output must match byte-for-byte across all strategies.
    // Derive recId from the signature's v byte so random samples actually recover the
    // signer's public key (not a null/alt-key failure path).
    for (int j = 0; j < n; j++) {
      int recId = recIdOf(sigs[j]);
      byte[] jdk = recoverPubBytes(recId, sigs[j], hashes[j], InvStrategy.JDK_MOD_INVERSE);
      byte[] bc = recoverPubBytes(recId, sigs[j], hashes[j], InvStrategy.BC_MOD_ODD_INVERSE);
      byte[] bcv = recoverPubBytes(recId, sigs[j], hashes[j], InvStrategy.BC_MOD_ODD_INVERSE_VAR);
      assertArrayEquals("BC vs JDK recovery mismatch [" + label + "] sample " + j, jdk, bc);
      assertArrayEquals("BCVar vs JDK recovery mismatch [" + label + "] sample " + j, jdk, bcv);
    }

    for (InvStrategy s : InvStrategy.values()) {
      for (int i = 0; i < warmup; i++) {
        recoverPubBytes(recIdOf(sigs[i % n]), sigs[i % n], hashes[i % n], s);
      }
    }

    long[][] results = new long[InvStrategy.values().length][];
    int k = 0;
    for (InvStrategy s : InvStrategy.values()) {
      results[k++] = timeIt(iterations,
          i -> recoverPubBytes(recIdOf(sigs[i % n]), sigs[i % n], hashes[i % n], s));
    }

    report("sig recovery", label, iterations,
        new Row("JDK_MOD_INVERSE             ", results[0]),
        new Row("BC_MOD_ODD_INVERSE          ", results[1]),
        new Row("BC_MOD_ODD_INVERSE_VAR      ", results[2]));
  }

  private static void runRecoveryEcKeyVsV2(String label, byte[][] hashes,
      ECDSASignature[] sigs, int warmup, int iterations) {
    int n = hashes.length;
    // Correctness: pure-Java ECKey and JNI-backed ECKeyV2 must recover the same address.
    for (int j = 0; j < n; j++) {
      byte[] viaEcKey = tryRecoverAddress(true, hashes[j], sigs[j]);
      byte[] viaEcKeyV2 = tryRecoverAddress(false, hashes[j], sigs[j]);
      assertArrayEquals("ECKey vs ECKeyV2 address mismatch [" + label + "] sample " + j,
          viaEcKey, viaEcKeyV2);
    }

    for (int i = 0; i < warmup; i++) {
      safeSignatureToAddress(true, hashes[i % n], sigs[i % n]);
      safeSignatureToAddress(false, hashes[i % n], sigs[i % n]);
    }
    long[] viaEcKey = timeIt(iterations,
        i -> safeSignatureToAddress(true, hashes[i % n], sigs[i % n]));
    long[] viaEcKeyV2 = timeIt(iterations,
        i -> safeSignatureToAddress(false, hashes[i % n], sigs[i % n]));

    report("sig recovery", label, iterations,
        new Row("ECKey (pure Java, JDK modInv)", viaEcKey),
        new Row("ECKeyV2 (JNI, libsecp256k1)  ", viaEcKeyV2));
  }

  // =========================================================================================
  // Helpers
  // =========================================================================================

  @FunctionalInterface
  private interface IndexedOp {
    void run(int i);
  }

  /** Returns {@code {totalNs, maxNs}} for {@code iterations} invocations of {@code op}. */
  private static long[] timeIt(int iterations, IndexedOp op) {
    long total = 0;
    long max = 0;
    for (int i = 0; i < iterations; i++) {
      long t = System.nanoTime();
      op.run(i);
      long elapsed = System.nanoTime() - t;
      total += elapsed;
      if (elapsed > max) {
        max = elapsed;
      }
    }
    return new long[] {total, max};
  }

  private static void safeSignatureToAddress(boolean pureJava, byte[] hash, ECDSASignature sig) {
    tryRecoverAddress(pureJava, hash, sig);
  }

  /**
   * Maps {@code v ∈ {27, 28, 31, 32}} (ECKey header-byte convention) back to
   * {@code recId ∈ {0, 1}}. Mirrors the header-byte handling in
   * {@code ECKey.signatureToAddress}.
   */
  private static int recIdOf(ECDSASignature sig) {
    int header = sig.v & 0xFF;
    if (header >= 31) {
      header -= 4;
    }
    return header - 27;
  }

  /** Returns the recovered address bytes, or {@code null} if recovery fails. */
  private static byte[] tryRecoverAddress(boolean pureJava, byte[] hash, ECDSASignature sig) {
    try {
      return pureJava
          ? ECKey.signatureToAddress(hash, sig)
          : ECKeyV2.signatureToAddress(hash, sig);
    } catch (SignatureException ignored) {
      return null;
    }
  }

  private static final class Row {
    final String name;
    final long totalNs;
    final long maxNs;

    Row(String name, long[] totalAndMax) {
      this.name = name;
      this.totalNs = totalAndMax[0];
      this.maxNs = totalAndMax[1];
    }
  }

  private static void report(String category, String label, int iterations, Row... rows) {
    StringBuilder sb = new StringBuilder();
    sb.append(String.format("%s bench [%s] x%d%n", category, label, iterations));
    for (Row r : rows) {
      sb.append(String.format("  %s avg=%.3f ms  max=%.3f ms%n",
          r.name, (r.totalNs / (double) iterations) / 1_000_000.0, r.maxNs / 1_000_000.0));
    }
    String msg = sb.toString();
    logger.info(msg);
//    System.out.print(msg);
  }

  private static final class Samples {
    final byte[][] hashes;
    final ECDSASignature[] sigs;

    Samples(byte[][] hashes, ECDSASignature[] sigs) {
      this.hashes = hashes;
      this.sigs = sigs;
    }

    int size() {
      return hashes.length;
    }
  }

  private static Samples randomSamples(int n) {
    byte[][] hashes = new byte[n][];
    ECDSASignature[] sigs = new ECDSASignature[n];
    Random rng = new Random(1234);
    for (int i = 0; i < n; i++) {
      ECKey key = new ECKey();
      hashes[i] = new byte[32];
      rng.nextBytes(hashes[i]);
      sigs[i] = key.sign(hashes[i]);
    }
    return new Samples(hashes, sigs);
  }

  /**
   * Local copy of {@link ECKey#recoverPubBytesFromSignature} with the {@code rInv} step
   * parameterised by {@link InvStrategy}. Test-only, not exported.
   */
  private static byte[] recoverPubBytes(int recId, ECDSASignature sig, byte[] messageHash,
      InvStrategy strategy) {
    BigInteger n = ECKey.CURVE.getN();
    BigInteger i = BigInteger.valueOf((long) recId / 2);
    BigInteger x = sig.r.add(i.multiply(n));
    BigInteger prime = ECKey.CURVE.getCurve().getField().getCharacteristic();
    if (x.compareTo(prime) >= 0) {
      return null;
    }
    ECPoint r = decompressKey(x, (recId & 1) == 1);
    if (!r.multiply(n).isInfinity()) {
      return null;
    }
    BigInteger e = new BigInteger(1, messageHash);
    BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);

    BigInteger rInv;
    switch (strategy) {
      case BC_MOD_ODD_INVERSE:
        rInv = BigIntegers.modOddInverse(n, sig.r);
        break;
      case BC_MOD_ODD_INVERSE_VAR:
        rInv = BigIntegers.modOddInverseVar(n, sig.r);
        break;
      case JDK_MOD_INVERSE:
      default:
        rInv = sig.r.modInverse(n);
        break;
    }

    BigInteger srInv = rInv.multiply(sig.s).mod(n);
    BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
    ECPoint q = ECAlgorithms.sumOfTwoMultiplies(ECKey.CURVE.getG(), eInvrInv, r, srInv);
    return q.getEncoded(false);
  }

  private static ECPoint decompressKey(BigInteger xbn, boolean ybit) {
    X9IntegerConverter x9 = new X9IntegerConverter();
    byte[] compEnc = x9.integerToBytes(xbn, 1 + x9.getByteLength(ECKey.CURVE.getCurve()));
    compEnc[0] = (byte) (ybit ? 0x03 : 0x02);
    return ECKey.CURVE.getCurve().decodePoint(compEnc);
  }
}
