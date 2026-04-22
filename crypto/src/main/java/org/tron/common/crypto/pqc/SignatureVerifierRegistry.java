package org.tron.common.crypto.pqc;

import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Static registry of post-quantum {@link SignatureVerifier} instances keyed by
 * {@link SignatureScheme}. Legacy schemes (ECDSA secp256k1, SM2/SM3) are NOT
 * registered — they flow through the existing {@code SignInterface} path.
 */
public final class SignatureVerifierRegistry {

  private static final Map<SignatureScheme, SignatureVerifier> VERIFIERS;

  static {
    EnumMap<SignatureScheme, SignatureVerifier> m = new EnumMap<>(SignatureScheme.class);
    m.put(SignatureScheme.ML_DSA_44, new MLDSA44Verifier());
    m.put(SignatureScheme.ML_DSA_65, new MLDSA65Verifier());
    VERIFIERS = Collections.unmodifiableMap(m);
  }

  private SignatureVerifierRegistry() {
  }

  public static SignatureVerifier get(SignatureScheme scheme) {
    SignatureVerifier v = VERIFIERS.get(scheme);
    if (v == null) {
      throw new IllegalArgumentException(
          "no SignatureVerifier registered for scheme: " + scheme);
    }
    return v;
  }

  public static boolean contains(SignatureScheme scheme) {
    return VERIFIERS.containsKey(scheme);
  }
}
