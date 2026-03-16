package org.tron.common.crypto;

import java.security.SecureRandom;
import java.security.SignatureException;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.crypto.sm2.SM2;
import org.tron.common.crypto.sm2.SM2.SM2Signature;

@Slf4j(topic = "crypto")
public class SignUtils {

  @Setter
  @Getter
  private static boolean useECKeyV2;

  public static SignInterface getGeneratedRandomSign(
      SecureRandom secureRandom, boolean isECKeyCryptoEngine) {
    if (isECKeyCryptoEngine) {
      if (useECKeyV2 && ECKeyV2.isECKeyV2Available()) {
        try {
          return new ECKeyV2(secureRandom);
        } catch (SignatureException e) {
          logger.warn("ECKeyV2 random key generation failed, falling back to ECKey: {}",
              e.getMessage());
        }
      }
      return new ECKey(secureRandom);
    }
    return new SM2(secureRandom);
  }

  public static SignInterface fromPrivate(byte[] privKeyBytes, boolean isECKeyCryptoEngine) {
    if (isECKeyCryptoEngine) {
      if (useECKeyV2 && ECKeyV2.isECKeyV2Available()) {
        return ECKeyV2.fromPrivate(privKeyBytes);
      }
      return ECKey.fromPrivate(privKeyBytes);
    }
    return SM2.fromPrivate(privKeyBytes);
  }

  public static byte[] signatureToAddress(
      byte[] messageHash, String signatureBase64, boolean isECKeyCryptoEngine)
      throws SignatureException {
    try {
      if (isECKeyCryptoEngine) {
        if (useECKeyV2 && ECKeyV2.isECKeyV2Available()) {
          try {
            return ECKeyV2.signatureToAddress(messageHash, signatureBase64);
          } catch (SignatureException e) {
            logger.warn(
                "ECKeyV2 signature recovery failed for base64 signature, falling back to ECKey: {}",
                e.getMessage());
          }
        }
        return ECKey.signatureToAddress(messageHash, signatureBase64);
      }
      return SM2.signatureToAddress(messageHash, signatureBase64);
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  public static SignatureInterface fromComponents(
      byte[] r, byte[] s, byte v, boolean isECKeyCryptoEngine) {
    if (isECKeyCryptoEngine) {
      return ECKey.ECDSASignature.fromComponents(r, s, v);
    }
    return SM2.SM2Signature.fromComponents(r, s, v);
  }

  public static byte[] signatureToAddress(
      byte[] messageHash, SignatureInterface signatureInterface, boolean isECKeyCryptoEngine)
      throws SignatureException {
    if (isECKeyCryptoEngine) {
      if (useECKeyV2 && ECKeyV2.isECKeyV2Available()) {
        try {
          return ECKeyV2.signatureToAddress(messageHash, (ECDSASignature) signatureInterface);
        } catch (SignatureException e) {
          logger.warn(
              "ECKeyV2 signature recovery failed for signature interface, falling back to ECKey: "
                  + "{}", e.getMessage());
        }
      }
      return ECKey.signatureToAddress(messageHash, (ECDSASignature) signatureInterface);
    }
    return SM2.signatureToAddress(messageHash, (SM2Signature) signatureInterface);
  }
}
