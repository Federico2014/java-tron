package org.tron.common.crypto.pqc;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Static dispatch table for post-quantum signature verification keyed by
 * {@link SignatureScheme}. Each entry binds a scheme to its public-key length,
 * signature length, and a stateless verify function (typically a method
 * reference to the concrete implementation's {@code verify}). Legacy
 * schemes (ECDSA secp256k1, SM2/SM3) are NOT registered — they flow through
 * the existing {@code SignInterface} path.
 */
public final class PqSignatureRegistry {

  @FunctionalInterface
  public interface Verifier {
    boolean verify(byte[] publicKey, byte[] message, byte[] signature);
  }

  private static final class SchemeInfo {
    final int publicKeyLength;
    final int signatureLength;
    final Verifier verifier;

    SchemeInfo(int publicKeyLength, int signatureLength, Verifier verifier) {
      this.publicKeyLength = publicKeyLength;
      this.signatureLength = signatureLength;
      this.verifier = verifier;
    }
  }

  private static final Map<SignatureScheme, SchemeInfo> SCHEMES;

  static {
    EnumMap<SignatureScheme, SchemeInfo> m = new EnumMap<>(SignatureScheme.class);
    m.put(SignatureScheme.ML_DSA_44, new SchemeInfo(
        MLDSA44.PUBLIC_KEY_LENGTH, MLDSA44.SIGNATURE_LENGTH, MLDSA44::verify));
    m.put(SignatureScheme.ML_DSA_65, new SchemeInfo(
        MLDSA65.PUBLIC_KEY_LENGTH, MLDSA65.SIGNATURE_LENGTH, MLDSA65::verify));
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

  public static boolean verify(
      SignatureScheme scheme, byte[] publicKey, byte[] message, byte[] signature) {
    return require(scheme).verifier.verify(publicKey, message, signature);
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
