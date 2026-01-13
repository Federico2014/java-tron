package org.tron.common.crypto.pqc;

import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Security;

public abstract class PQCBase {

  protected PrivateKey privateKey;
  protected PublicKey publicKey;

  static {
    if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastlePQCProvider());
    }
  }

  /**
   * Get public key
   * @return public key
   */
  public PublicKey getPublicKey() {
    if (publicKey == null) {
      throw new IllegalStateException("KeyPair not initialized.");
    }
    return publicKey;
  }

  /**
   * Get private key
   * @return private key
   */
  public PrivateKey getPrivateKey() {
    if (privateKey == null) {
      throw new IllegalStateException("KeyPair not initialized.");
    }
    return privateKey;
  }

  /**
   * Get public key length
   * @return public key length (in bytes)
   */
  public int getPublicKeyLength() {
    if (publicKey == null) {
      throw new IllegalStateException("PublicKey not initialized.");
    }
    return publicKey.getEncoded().length;
  }

  /**
   * Get private key length
   * @return private key length (in bytes)
   */
  public int getPrivateKeyLength() {
    if (privateKey == null) {
      throw new IllegalStateException("PrivateKey not initialized.");
    }
    return privateKey.getEncoded().length;
  }

  /**
   * Get public key bytes with X.509 format
   * @return public key as bytes
   */
  public byte[] getPublicKeyBytes() {
    return getPublicKey().getEncoded(); // X.509 format
  }

  /**
   * Get private key bytes with PKCS#8 format
   * @return private key as hexadecimal string
   */
  public byte[] getPrivateKeyBytes() {
    return getPrivateKey().getEncoded(); // PKCS#8 format
  }
}
