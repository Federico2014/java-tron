package org.tron.common.crypto.pqc;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public final class MLDSA65Signer {

  public static final int PRIVATE_KEY_LENGTH = 4032;

  private MLDSA65Signer() {
  }

  public static byte[] sign(byte[] privateKey, byte[] message) {
    if (privateKey == null || privateKey.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 private key length must be " + PRIVATE_KEY_LENGTH);
    }
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(
        MLDSAParameters.ml_dsa_65, privateKey);
    MLDSASigner signer = new MLDSASigner();
    signer.init(true, sk);
    signer.update(message, 0, message.length);
    try {
      return signer.generateSignature();
    } catch (Exception e) {
      throw new IllegalStateException("ML-DSA-65 signing failed", e);
    }
  }

  public static byte[] derivePublicKey(byte[] privateKey) {
    if (privateKey == null || privateKey.length != PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "ML-DSA-65 private key length must be " + PRIVATE_KEY_LENGTH);
    }
    MLDSAPrivateKeyParameters sk = new MLDSAPrivateKeyParameters(
        MLDSAParameters.ml_dsa_65, privateKey);
    MLDSAPublicKeyParameters pk = sk.getPublicKeyParameters();
    return pk.getEncoded();
  }
}
