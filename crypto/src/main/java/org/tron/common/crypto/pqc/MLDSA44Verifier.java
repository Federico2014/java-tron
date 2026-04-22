package org.tron.common.crypto.pqc;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * FIPS 204 ML-DSA-44 verifier. Consumes raw public key and signature bytes —
 * no SubjectPublicKeyInfo, PEM, or Base64 wrapping.
 */
public class MLDSA44Verifier implements SignatureVerifier {

  public static final int PUBLIC_KEY_LENGTH = 1312;
  public static final int SIGNATURE_LENGTH = 2420;

  @Override
  public SignatureScheme getScheme() {
    return SignatureScheme.ML_DSA_44;
  }

  @Override
  public int getPublicKeyLength() {
    return PUBLIC_KEY_LENGTH;
  }

  @Override
  public int getSignatureLength() {
    return SIGNATURE_LENGTH;
  }

  @Override
  public boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
    validatePublicKey(publicKey);
    validateSignature(signature);
    if (message == null) {
      throw new IllegalArgumentException("message must not be null");
    }
    MLDSAPublicKeyParameters pk = new MLDSAPublicKeyParameters(
        MLDSAParameters.ml_dsa_44, publicKey);
    MLDSASigner signer = new MLDSASigner();
    signer.init(false, pk);
    signer.update(message, 0, message.length);
    return signer.verifySignature(signature);
  }
}
