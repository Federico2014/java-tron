package org.tron.common.crypto.pqc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.protos.Protocol.PQScheme;

/**
 * Static dispatch table for post-quantum signature schemes keyed by
 * {@link PQScheme}. Each entry binds a scheme to its public-key length,
 * signature length, seed length, fingerprint hash function, and stateless
 * sign/verify/keygen operations. Legacy ECDSA secp256k1 / SM2 schemes are NOT
 * registered — they flow through the existing {@code SignInterface} path.
 *
 * <p><b>Address binding (V2).</b> A PQ-derived TRON address is
 * {@code 0x41 ‖ deriveHash(scheme, public_key)[0:20]}. The hash function is
 * scheme-specific (see {@link #deriveHash}). For {@code FN_DSA_512} the hash
 * is {@code SHA-256(public_key)} — distinct from the ECDSA flow's
 * {@code Keccak-256(public_key)[12..32]} so that PQ and ECDSA addresses
 * cannot collide.
 */
public final class PQSchemeRegistry {

  /** Stateless sign/verify/keygen dispatch bound to a single PQ scheme. */
  public interface SignatureOps {
    byte[] sign(byte[] privateKey, byte[] message);

    boolean verify(byte[] publicKey, byte[] message, byte[] signature);

    PQSignature fromSeed(byte[] seed);
  }

  /**
   * Fingerprint hash used to derive a 21-byte TRON address from a PQ public key.
   * V2 first launch uses SHA-256 for FN_DSA_512; later schemes may bind to a
   * different hash if the PQ scheme has its own canonical fingerprint.
   */
  public interface FingerprintHash {
    /** Returns the full digest of {@code data} (no truncation). */
    byte[] digest(byte[] data);
  }

  private static final FingerprintHash SHA_256 = data -> {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 not available", e);
    }
  };

  private static final class SchemeInfo {
    final int publicKeyLength;
    final int signatureLength;
    final int seedLength;
    final FingerprintHash hash;
    final SignatureOps ops;

    SchemeInfo(int publicKeyLength, int signatureLength, int seedLength,
        FingerprintHash hash, SignatureOps ops) {
      this.publicKeyLength = publicKeyLength;
      this.signatureLength = signatureLength;
      this.seedLength = seedLength;
      this.hash = hash;
      this.ops = ops;
    }
  }

  private static final Map<PQScheme, SchemeInfo> SCHEMES;

  static {
    EnumMap<PQScheme, SchemeInfo> m = new EnumMap<>(PQScheme.class);
    m.put(PQScheme.FN_DSA_512, new SchemeInfo(
        FNDSA.PUBLIC_KEY_LENGTH, FNDSA.SIGNATURE_LENGTH, FNDSA.SEED_LENGTH,
        SHA_256,
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

  private PQSchemeRegistry() {
  }

  public static boolean contains(PQScheme scheme) {
    return scheme != null && SCHEMES.containsKey(scheme);
  }

  public static int getPublicKeyLength(PQScheme scheme) {
    return require(scheme).publicKeyLength;
  }

  public static int getSignatureLength(PQScheme scheme) {
    return require(scheme).signatureLength;
  }

  public static int getSeedLength(PQScheme scheme) {
    return require(scheme).seedLength;
  }

  /**
   * Per-scheme signature-length predicate. Fixed-length schemes require exact
   * equality with {@link #getSignatureLength(PQScheme)}; variable-length
   * schemes ({@code FN_DSA_512}) treat that value as an upper bound and accept
   * any {@code 1..max}.
   */
  public static boolean isValidSignatureLength(PQScheme scheme, int length) {
    SchemeInfo info = require(scheme);
    if (scheme == PQScheme.FN_DSA_512) {
      return length > 0 && length <= info.signatureLength;
    }
    return length == info.signatureLength;
  }

  public static byte[] sign(PQScheme scheme, byte[] privateKey, byte[] message) {
    return require(scheme).ops.sign(privateKey, message);
  }

  public static boolean verify(
      PQScheme scheme, byte[] publicKey, byte[] message, byte[] signature) {
    return require(scheme).ops.verify(publicKey, message, signature);
  }

  public static PQSignature fromSeed(PQScheme scheme, byte[] seed) {
    return require(scheme).ops.fromSeed(seed);
  }

  /**
   * Scheme-dispatched fingerprint hash of a PQ public key. Returns the full
   * digest; callers truncate to 20 bytes when deriving the address suffix.
   */
  public static byte[] deriveHash(PQScheme scheme, byte[] publicKey) {
    SchemeInfo info = require(scheme);
    if (publicKey == null || publicKey.length != info.publicKeyLength) {
      throw new IllegalArgumentException(
          "invalid public key length for " + scheme + ": "
              + (publicKey == null ? -1 : publicKey.length));
    }
    return info.hash.digest(publicKey);
  }

  /**
   * Derive the 21-byte TRON address from a PQ public key as
   * {@code 0x41 ‖ deriveHash(scheme, public_key)[0:20]}.
   */
  public static byte[] computeAddress(PQScheme scheme, byte[] publicKey) {
    byte[] h = deriveHash(scheme, publicKey);
    byte[] addr = new byte[21];
    addr[0] = 0x41;
    System.arraycopy(h, 0, addr, 1, 20);
    return addr;
  }

  private static SchemeInfo require(PQScheme scheme) {
    if (scheme == null) {
      throw new IllegalArgumentException("scheme must not be null");
    }
    SchemeInfo info = SCHEMES.get(scheme);
    if (info == null) {
      throw new IllegalArgumentException(
          "no PQSignature registered for scheme: " + scheme);
    }
    return info;
  }
}
