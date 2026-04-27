package org.tron.common.crypto.pqc;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Static dispatch table for post-quantum signature schemes keyed by
 * {@link SignatureScheme}. Each entry binds a scheme to its public-key length,
 * signature length, and stateless sign/verify/keygen operations. Legacy
 * schemes (ECDSA secp256k1, SM2/SM3) are NOT registered — they flow through
 * the existing {@code SignInterface} path.
 */
public final class PqSignatureRegistry {

  /** Stateless sign/verify/keygen dispatch bound to a single PQ scheme. */
  public interface SignatureOps {
    byte[] sign(byte[] privateKey, byte[] message);

    boolean verify(byte[] publicKey, byte[] message, byte[] signature);

    PqSignature fromSeed(byte[] seed);
  }

  private static final class SchemeInfo {
    final int publicKeyLength;
    final int signatureLength;
    final SignatureOps ops;

    SchemeInfo(int publicKeyLength, int signatureLength, SignatureOps ops) {
      this.publicKeyLength = publicKeyLength;
      this.signatureLength = signatureLength;
      this.ops = ops;
    }
  }

  private static final Map<SignatureScheme, SchemeInfo> SCHEMES;

  static {
    EnumMap<SignatureScheme, SchemeInfo> m = new EnumMap<>(SignatureScheme.class);
    m.put(SignatureScheme.ML_DSA_44, new SchemeInfo(
        MLDSA44.PUBLIC_KEY_LENGTH, MLDSA44.SIGNATURE_LENGTH, new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return MLDSA44.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return MLDSA44.verify(publicKey, message, signature);
          }

          @Override
          public PqSignature fromSeed(byte[] seed) {
            return new MLDSA44(seed);
          }
        }));
    m.put(SignatureScheme.ML_DSA_65, new SchemeInfo(
        MLDSA65.PUBLIC_KEY_LENGTH, MLDSA65.SIGNATURE_LENGTH, new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return MLDSA65.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return MLDSA65.verify(publicKey, message, signature);
          }

          @Override
          public PqSignature fromSeed(byte[] seed) {
            return new MLDSA65(seed);
          }
        }));
    m.put(SignatureScheme.SLH_DSA, new SchemeInfo(
        SLHDSA.PUBLIC_KEY_LENGTH, SLHDSA.SIGNATURE_LENGTH, new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return SLHDSA.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return SLHDSA.verify(publicKey, message, signature);
          }

          @Override
          public PqSignature fromSeed(byte[] seed) {
            return new SLHDSA(seed);
          }
        }));
    SCHEMES = Collections.unmodifiableMap(m);
  }

  private PqSignatureRegistry() {
  }

  public static boolean contains(SignatureScheme scheme) {
    return SCHEMES.containsKey(scheme);
  }

  public static int getPublicKeyLength(SignatureScheme scheme) {
    return require(scheme).publicKeyLength;
  }

  public static int getSignatureLength(SignatureScheme scheme) {
    return require(scheme).signatureLength;
  }

  public static byte[] sign(SignatureScheme scheme, byte[] privateKey, byte[] message) {
    return require(scheme).ops.sign(privateKey, message);
  }

  public static boolean verify(
      SignatureScheme scheme, byte[] publicKey, byte[] message, byte[] signature) {
    return require(scheme).ops.verify(publicKey, message, signature);
  }

  public static PqSignature fromSeed(SignatureScheme scheme, byte[] seed) {
    return require(scheme).ops.fromSeed(seed);
  }

  private static SchemeInfo require(SignatureScheme scheme) {
    SchemeInfo info = SCHEMES.get(scheme);
    if (info == null) {
      throw new IllegalArgumentException(
          "no PqSignature registered for scheme: " + scheme);
    }
    return info;
  }
}