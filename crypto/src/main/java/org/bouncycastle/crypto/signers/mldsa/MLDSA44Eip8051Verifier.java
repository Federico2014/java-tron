package org.bouncycastle.crypto.signers.mldsa;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.util.Arrays;

/**
 * EIP-8051 VERIFY_MLDSA verifier for ML-DSA-44 expanded public keys.
 *
 * <p>This class intentionally lives in Bouncy Castle's ML-DSA internal package so it can reuse
 * the package-private polynomial primitives. Bouncy Castle 1.84 exposes only the standard
 * FIPS-204 public key verifier ({@code rho || t1}); EIP-8051 instead supplies
 * {@code A_hat || tr || t1_ntt}.
 */
public final class MLDSA44Eip8051Verifier {

  public static final int MESSAGE_LENGTH = 32;
  public static final int SIGNATURE_LENGTH = 2420;
  public static final int EXPANDED_PUBLIC_KEY_LENGTH = 20512;
  public static final int INPUT_LENGTH =
      MESSAGE_LENGTH + SIGNATURE_LENGTH + EXPANDED_PUBLIC_KEY_LENGTH;

  private static final int K = 4;
  private static final int L = 4;
  private static final int FIELD_ELEMENT_BYTES = 4;
  private static final int MATRIX_BYTES =
      K * L * MLDSAEngine.DilithiumN * FIELD_ELEMENT_BYTES;
  private static final int TR_BYTES = 32;
  private static final int TWO_POWER_D = 1 << MLDSAEngine.DilithiumD;

  private MLDSA44Eip8051Verifier() {
  }

  public static boolean verify(byte[] message, byte[] signature, byte[] expandedPublicKey) {
    if (message == null || message.length != MESSAGE_LENGTH
        || signature == null || signature.length != SIGNATURE_LENGTH
        || expandedPublicKey == null
        || expandedPublicKey.length != EXPANDED_PUBLIC_KEY_LENGTH) {
      return false;
    }

    try {
      MLDSAEngine engine = MLDSAEngine.getInstance(MLDSAParameters.ml_dsa_44, null);
      PolyVecL[] aHat = decodeMatrix(expandedPublicKey, 0, engine);
      byte[] tr = Arrays.copyOfRange(expandedPublicKey, MATRIX_BYTES, MATRIX_BYTES + TR_BYTES);
      PolyVecK t1Ntt = decodePolyVecK(
          expandedPublicKey, MATRIX_BYTES + TR_BYTES, engine);

      return verifyInternal(message, signature, aHat, tr, t1Ntt, engine);
    } catch (RuntimeException e) {
      return false;
    }
  }

  private static boolean verifyInternal(byte[] message, byte[] signature, PolyVecL[] aHat,
      byte[] tr, PolyVecK t1Ntt, MLDSAEngine engine) {
    PolyVecK h = new PolyVecK(engine);
    PolyVecL z = new PolyVecL(engine);
    if (!Packing.unpackSignature(z, h, signature, engine)) {
      return false;
    }
    if (z.checkNorm(engine.getDilithiumGamma1() - engine.getDilithiumBeta())) {
      return false;
    }

    byte[] buf = new byte[StrictMath.max(
        MLDSAEngine.CrhBytes + K * engine.getDilithiumPolyW1PackedBytes(),
        engine.getDilithiumCTilde())];
    SHAKEDigest shake = new SHAKEDigest(256);
    shake.update(tr, 0, TR_BYTES);
    shake.update(message, 0, MESSAGE_LENGTH);
    shake.doFinal(buf, 0, MLDSAEngine.CrhBytes);

    Poly c = new Poly(engine);
    c.challenge(signature, 0, engine.getDilithiumCTilde());

    z.polyVecNtt();
    PolyVecK w1 = pointwiseMontgomery(aHat, z, engine);

    c.polyNtt();
    PolyVecK ct1 = new PolyVecK(engine);
    ct1.pointwisePolyMontgomery(c, t1Ntt);
    multiplyByTwoPowerD(ct1);

    w1.subtract(ct1);
    w1.reduce();
    w1.invNttToMont();
    w1.conditionalAddQ();
    w1.useHint(w1, h);
    w1.packW1(engine, buf, MLDSAEngine.CrhBytes);

    shake = new SHAKEDigest(256);
    shake.update(buf, 0, MLDSAEngine.CrhBytes + K * engine.getDilithiumPolyW1PackedBytes());
    shake.doFinal(buf, 0, engine.getDilithiumCTilde());
    return Arrays.constantTimeAreEqual(engine.getDilithiumCTilde(), signature, 0, buf, 0);
  }

  private static PolyVecK pointwiseMontgomery(PolyVecL[] aHat, PolyVecL z,
      MLDSAEngine engine) {
    PolyVecK out = new PolyVecK(engine);
    Poly tmp = new Poly(engine);
    for (int i = 0; i < K; i++) {
      out.getVectorIndex(i).pointwiseMontgomery(aHat[i].getVectorIndex(0), z.getVectorIndex(0));
      for (int j = 1; j < L; j++) {
        tmp.pointwiseMontgomery(aHat[i].getVectorIndex(j), z.getVectorIndex(j));
        out.getVectorIndex(i).addPoly(tmp);
      }
    }
    return out;
  }

  private static PolyVecL[] decodeMatrix(byte[] in, int offset, MLDSAEngine engine) {
    PolyVecL[] matrix = new PolyVecL[K];
    int pos = offset;
    for (int i = 0; i < K; i++) {
      matrix[i] = new PolyVecL(engine);
      for (int j = 0; j < L; j++) {
        decodePoly(in, pos, matrix[i].getVectorIndex(j));
        pos += MLDSAEngine.DilithiumN * FIELD_ELEMENT_BYTES;
      }
    }
    return matrix;
  }

  private static PolyVecK decodePolyVecK(byte[] in, int offset, MLDSAEngine engine) {
    PolyVecK out = new PolyVecK(engine);
    int pos = offset;
    for (int i = 0; i < K; i++) {
      decodePoly(in, pos, out.getVectorIndex(i));
      pos += MLDSAEngine.DilithiumN * FIELD_ELEMENT_BYTES;
    }
    return out;
  }

  private static void decodePoly(byte[] in, int offset, Poly out) {
    int pos = offset;
    for (int i = 0; i < MLDSAEngine.DilithiumN; i++) {
      long coeff = ((long) (in[pos] & 0xff) << 24)
          | ((long) (in[pos + 1] & 0xff) << 16)
          | ((long) (in[pos + 2] & 0xff) << 8)
          | (long) (in[pos + 3] & 0xff);
      if (coeff >= MLDSAEngine.DilithiumQ) {
        throw new IllegalArgumentException("invalid ML-DSA field element");
      }
      out.setCoeffIndex(i, (int) coeff);
      pos += FIELD_ELEMENT_BYTES;
    }
  }

  private static void multiplyByTwoPowerD(PolyVecK v) {
    for (int i = 0; i < K; i++) {
      Poly poly = v.getVectorIndex(i);
      for (int j = 0; j < MLDSAEngine.DilithiumN; j++) {
        long coeff = poly.getCoeffIndex(j) % (long) MLDSAEngine.DilithiumQ;
        if (coeff < 0) {
          coeff += MLDSAEngine.DilithiumQ;
        }
        poly.setCoeffIndex(j, (int) ((coeff * TWO_POWER_D) % MLDSAEngine.DilithiumQ));
      }
    }
  }
}
