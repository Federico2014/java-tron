package org.tron.common.crypto.pqc;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.common.crypto.Hash;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Static dispatch table for post-quantum signature schemes keyed by
 * {@link SignatureScheme}. Each entry binds a scheme to its public-key length,
 * signature length, and stateless sign/verify/keygen operations. Legacy
 * schemes (ECDSA secp256k1, SM2/SM3) are NOT registered — they flow through
 * the existing {@code SignInterface} path.
 */
public final class PQSignatureRegistry {

  /** Stateless sign/verify/keygen dispatch bound to a single PQ scheme. */
  public interface SignatureOps {
    byte[] sign(byte[] privateKey, byte[] message);

    boolean verify(byte[] publicKey, byte[] message, byte[] signature);

    PQSignature fromSeed(byte[] seed);
  }

  private static final class SchemeInfo {
    final int publicKeyLength;
    final int signatureLength;
    final int seedLength;
    final SignatureOps ops;

    SchemeInfo(int publicKeyLength, int signatureLength, int seedLength, SignatureOps ops) {
      this.publicKeyLength = publicKeyLength;
      this.signatureLength = signatureLength;
      this.seedLength = seedLength;
      this.ops = ops;
    }
  }

  private static final Map<SignatureScheme, SchemeInfo> SCHEMES;

  static {
    EnumMap<SignatureScheme, SchemeInfo> m = new EnumMap<>(SignatureScheme.class);
    m.put(SignatureScheme.ML_DSA_44, new SchemeInfo(
        MLDSA44.PUBLIC_KEY_LENGTH, MLDSA44.SIGNATURE_LENGTH, MLDSA44.SEED_LENGTH,
        new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return MLDSA44.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return MLDSA44.verify(publicKey, message, signature);
          }

          @Override
          public PQSignature fromSeed(byte[] seed) {
            return new MLDSA44(seed);
          }
        }));
    m.put(SignatureScheme.ML_DSA_65, new SchemeInfo(
        MLDSA65.PUBLIC_KEY_LENGTH, MLDSA65.SIGNATURE_LENGTH, MLDSA65.SEED_LENGTH,
        new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return MLDSA65.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return MLDSA65.verify(publicKey, message, signature);
          }

          @Override
          public PQSignature fromSeed(byte[] seed) {
            return new MLDSA65(seed);
          }
        }));
    m.put(SignatureScheme.FN_DSA, new SchemeInfo(
        FNDSA.PUBLIC_KEY_LENGTH, FNDSA.SIGNATURE_LENGTH, FNDSA.SEED_LENGTH,
        new SignatureOps() {
          @Override
          public byte[] sign(byte[] privateKey, byte[] message) {
            return FNDSA.sign(privateKey, message);
          }

          @Override
          public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
            return FNDSA.verify(publicKey, message, signature);
          }

          @Override
          public PQSignature fromSeed(byte[] seed) {
            return new FNDSA(seed);
          }
        }));
    SCHEMES = Collections.unmodifiableMap(m);
  }

  private PQSignatureRegistry() {
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

  public static int getSeedLength(SignatureScheme scheme) {
    return require(scheme).seedLength;
  }

  /**
   * Per-scheme signature-length predicate. Fixed-length schemes (ML-DSA-44 / ML-DSA-65)
   * require exact equality with {@link #getSignatureLength(SignatureScheme)};
   * variable-length schemes (FN-DSA) treat that value as an upper bound and accept any
   * {@code 1..max}.
   */
  public static boolean isValidSignatureLength(SignatureScheme scheme, int length) {
    SchemeInfo info = require(scheme);
    if (scheme == SignatureScheme.FN_DSA) {
      return length > 0 && length <= info.signatureLength;
    }
    return length == info.signatureLength;
  }

  public static byte[] sign(SignatureScheme scheme, byte[] privateKey, byte[] message) {
    return require(scheme).ops.sign(privateKey, message);
  }

  public static boolean verify(
      SignatureScheme scheme, byte[] publicKey, byte[] message, byte[] signature) {
    return require(scheme).ops.verify(publicKey, message, signature);
  }

  public static PQSignature fromSeed(SignatureScheme scheme, byte[] seed) {
    return require(scheme).ops.fromSeed(seed);
  }

  /**
   * Derive the 21-byte TRON address from a PQ public key. Uses
   * {@code Hash.sha3omit12(publicKey)} so the mapping matches the existing
   * {@link PQSignature#getAddress()} contract.
   */
  public static byte[] computeAddress(SignatureScheme scheme, byte[] publicKey) {
    SchemeInfo info = require(scheme);
    if (publicKey == null || publicKey.length != info.publicKeyLength) {
      throw new IllegalArgumentException(
          "invalid public key length for " + scheme + ": "
              + (publicKey == null ? -1 : publicKey.length));
    }
    return Hash.sha3omit12(publicKey);
  }

  private static SchemeInfo require(SignatureScheme scheme) {
    SchemeInfo info = SCHEMES.get(scheme);
    if (info == null) {
      throw new IllegalArgumentException(
          "no PQSignature registered for scheme: " + scheme);
    }
    return info;
  }
}