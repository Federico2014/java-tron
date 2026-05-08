package org.tron.common.crypto.sm2;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.tron.common.utils.ByteArray;

/**
 * Low-level SM2 signer used by {@link org.tron.common.crypto.sm2.SM2}.
 *
 * <p>Exposes two operations: {@link #generateHashSignature} (sign a pre-computed 32-byte hash)
 * and {@link #verifyHashSignature} (verify against a pre-computed hash). The standard SM2
 * {@code Z_A} pre-hash step is intentionally absent; see {@link org.tron.common.crypto.sm2.SM2}
 * for the rationale.
 */
public class SM2Signer
    implements ECConstants {

  private final DSAKCalculator kCalculator = new HMacDSAKCalculator(new SM3Digest());

  private ECDomainParameters ecParams;
  private ECKeyParameters ecKey;

  public void init(CipherParameters param) {
    if (param == null) {
      throw new IllegalArgumentException("CipherParameters cannot be null");
    }
    ecKey = (ECKeyParameters) param;
    ecParams = ecKey.getParameters();
  }

  /**
   * generate the signature from the 32 byte hash
   */
  public BigInteger[] generateHashSignature(byte[] hash) {
    if (ByteArray.isEmpty(hash) || hash.length != 32) {
      throw new IllegalArgumentException("Expected 32 byte input to " +
          "SM2 signature, not " + (hash == null ? "null" : hash.length));
    }
    BigInteger n = ecParams.getN();
    BigInteger e = calculateE(hash);
    BigInteger d = ((ECPrivateKeyParameters) ecKey).getD();

    BigInteger r, s;

    ECMultiplier basePointMultiplier = createBasePointMultiplier();

    // Initialize the deterministic K calculator with the private key and message hash
    kCalculator.init(n, d, hash);

    // 5.2.1 Draft RFC:  SM2 Public Key Algorithms
    do // generate s
    {
      BigInteger k;
      do // generate r
      {
        // A3
        k = kCalculator.nextK();
        // A4
        ECPoint p = basePointMultiplier.multiply(ecParams.getG(), k).normalize();

        // A5
        r = e.add(p.getAffineXCoord().toBigInteger()).mod(n);
      }
      while (r.equals(ZERO) || r.add(k).equals(n));

      // A6
      BigInteger dPlus1ModN = d.add(ONE).modInverse(n);

      s = k.subtract(r.multiply(d)).mod(n);
      s = dPlus1ModN.multiply(s).mod(n);
    }
    while (s.equals(ZERO));

    // A7
    return new BigInteger[]{r, s};
  }

  /**
   * verify the hash signature
   */
  public boolean verifyHashSignature(byte[] hash, BigInteger r, BigInteger s) {
    if (ByteArray.isEmpty(hash) || hash.length != 32) {
      throw new IllegalArgumentException("Expected 32 byte input to "
          + "SM2 signature, not " + (hash == null ? "null" : hash.length));
    }
    if (r == null || s == null) {
      throw new IllegalArgumentException("R or S cannot be null");
    }
    BigInteger n = ecParams.getN();

    // 5.3.1 Draft RFC:  SM2 Public Key Algorithms
    // B1
    if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0) {
      return false;
    }

    // B2
    if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0) {
      return false;
    }

    ECPoint q = ((ECPublicKeyParameters) ecKey).getQ();

    // B4
    BigInteger e = calculateE(hash);

    // B5
    BigInteger t = r.add(s).mod(n);
    if (t.equals(ZERO)) {
      return false;
    } else {
      // B6
      ECPoint x1y1 = ecParams.getG().multiply(s);
      x1y1 = x1y1.add(q.multiply(t)).normalize();

      // B7
      return r.equals(e.add(x1y1.getAffineXCoord().toBigInteger()).mod(n));
    }
  }

  protected ECMultiplier createBasePointMultiplier() {
    return new FixedPointCombMultiplier();
  }

  protected BigInteger calculateE(byte[] message) {
    if (message == null) {
      throw new IllegalArgumentException("Message cannot be null");
    }
    return new BigInteger(1, message);
  }

}
