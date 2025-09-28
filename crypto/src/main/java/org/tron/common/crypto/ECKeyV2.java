package org.tron.common.crypto;

import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.SECP256K1_EC_UNCOMPRESSED;

import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.SignatureException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1;

@Slf4j(topic = "crypto")
public class ECKeyV2 extends ECKey {

  private final LibSecp256k1.secp256k1_pubkey pubKey = new LibSecp256k1.secp256k1_pubkey();

  @Getter
  private static final boolean isECKeyV2Available;

  private static final String ECKeyV2_NOT_AVAILABLE = "ECKeyV2 is not available!";

  static {
    isECKeyV2Available = LibSecp256k1.CONTEXT != null;
    if (!isECKeyV2Available) {
      logger.warn(ECKeyV2_NOT_AVAILABLE);
    }
  }

  public ECKeyV2() throws SignatureException {
    super();
    checkECKeyV2Available();

    byte[] privateKeyBytes = getPrivateKey();
    if (!isValidPrivateKey(privateKeyBytes)) {
      throw new SignatureException("Invalid private key.");
    }

    if (LibSecp256k1.secp256k1_ec_pubkey_create(
        LibSecp256k1.CONTEXT, pubKey, privateKeyBytes)
        == 0) {
      throw new SignatureException("Could not create public key from private key.");
    }
  }

  public ECKeyV2(byte[] privateKey) throws SignatureException {
    super(privateKey, true);
    checkECKeyV2Available();

    if (LibSecp256k1.secp256k1_ec_pubkey_create(
        LibSecp256k1.CONTEXT, pubKey, getPrivateKey())
        == 0) {
      throw new SignatureException("Could not create public key from private key.");
    }
  }

  public ECKeyV2(SecureRandom secureRandom) throws SignatureException {
    super(secureRandom);
    checkECKeyV2Available();

    byte[] privateKeyBytes = getPrivateKey();
    if (!isValidPrivateKey(privateKeyBytes)) {
      throw new SignatureException("Invalid private key.");
    }

    if (LibSecp256k1.secp256k1_ec_pubkey_create(
        LibSecp256k1.CONTEXT, pubKey, getPrivateKey())
        == 0) {
      throw new SignatureException("Could not create public key from private key.");
    }
  }

  public static ECKeyV2 fromECKey(ECKey key) throws SignatureException {
    if (key == null) {
      return null;
    }

    checkECKeyV2Available();
    return new ECKeyV2(key.getPrivateKey());
  }

  public static ECKeyV2 fromPrivate(byte[] privateKey) {
    try {
      checkECKeyV2Available();
      return new ECKeyV2(privateKey);
    } catch (SignatureException e) {
      throw new RuntimeException("Failed to create ECKeyV2 from private key", e);
    }
  }

  public static ECKeyV2 fromPrivate(BigInteger privateKey) {
    if (!isValidPrivateKey(privateKey)) {
      throw new IllegalArgumentException("Invalid private key.");
    }

    try {
      checkECKeyV2Available();
      return new ECKeyV2(privateKey.toByteArray());
    } catch (SignatureException e) {
      throw new RuntimeException("Failed to create ECKeyV2 from private key", e);
    }
  }

  public static void checkECKeyV2Available() throws SignatureException {
    if (!isECKeyV2Available) {
      throw new SignatureException(ECKeyV2_NOT_AVAILABLE);
    }
  }

  @Override
  public byte[] getPubKey() {
    ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    LongByReference keySize = new LongByReference(recoveredKey.limit());
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        recoveredKey,
        keySize,
        pubKey,
        SECP256K1_EC_UNCOMPRESSED
    ) == 0) {
      throw new RuntimeException("Could not serialize public key.");
    }
    return recoveredKey.array();
  }

  @Override
  public String signHash(byte[] hash) {
    if (hash == null || hash.length != 32) {
      throw new IllegalArgumentException("Hash must be 32 bytes array.");
    }

    final LibSecp256k1.secp256k1_ecdsa_recoverable_signature signature =
        new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();
    if (LibSecp256k1.secp256k1_ecdsa_sign_recoverable(
        LibSecp256k1.CONTEXT,
        signature,
        hash,
        getPrivateKey(),
        null,
        null)
        == 0) {
      throw new RuntimeException(
          "Could not natively sign. Private Key is invalid or default nonce generation failed.");
    }

    return transformSignature(signature).toBase64();
  }

  private ECDSASignature transformSignature(
      LibSecp256k1.secp256k1_ecdsa_recoverable_signature signature) {
    final ByteBuffer compactSig = ByteBuffer.allocate(64);
    final IntByReference recId = new IntByReference(0);
    LibSecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        LibSecp256k1.CONTEXT, compactSig, recId, signature);
    compactSig.flip();
    final byte[] sigData = compactSig.array();

    byte[] r = new byte[32];
    byte[] s = new byte[32];
    byte v;
    System.arraycopy(sigData, 0, r, 0, 32);
    System.arraycopy(sigData, 32, s, 0, 32);
    v = (byte) recId.getValue();
    if (v >= 0 && v <= 3) {
      v += 27;
    } else {
      throw new RuntimeException(String.format("Invalid signature recId: %d", v));
    }

    return ECDSASignature.fromComponents(r, s, v);
  }

  /**
   * Compute the address of the key that signed the given signature.
   *
   * @param messageHash     32-byte hash of message
   * @param signatureBase64 Base-64 encoded signature
   * @return 20-byte address
   */
  public static byte[] signatureToAddress(byte[] messageHash, String
      signatureBase64) throws SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash,
        signatureBase64));
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash, String
      signatureBase64) throws SignatureException {
    byte[] sigData = ECDSASignature.parseBase64Signature(signatureBase64).toByteArray();
    return signatureToKeyBytes(messageHash, sigData);
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash, byte[] signBytes)
      throws SignatureException {
    checkECKeyV2Available();

    if (messageHash == null || messageHash.length != 32) {
      throw new IllegalArgumentException("Hash must be 32 bytes array.");
    }

    if (signBytes == null || signBytes.length != 65) {
      throw new IllegalArgumentException("Signature must be 65 bytes array.");
    }

    byte[] input = new byte[64];
    System.arraycopy(signBytes, 0, input, 0, 64);
    byte recId = signBytes[64];
    // recId = recId >= 27 ? (byte) (recId - 27) : recId;

    final LibSecp256k1.secp256k1_ecdsa_recoverable_signature signature =
        new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();

    if (LibSecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
        LibSecp256k1.CONTEXT, signature, input, recId) == 0) {
      throw new SignatureException("Could not parse signature");
    }

    final LibSecp256k1.secp256k1_pubkey newPubKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ecdsa_recover(
        LibSecp256k1.CONTEXT, newPubKey, signature, messageHash)
        == 0) {
      throw new SignatureException("Could not parse pub key");
    }

    ByteBuffer recoveredKey = ByteBuffer.allocate(65);
    LongByReference keySize = new LongByReference(recoveredKey.limit());
    LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT, recoveredKey, keySize, newPubKey, SECP256K1_EC_UNCOMPRESSED);
    return recoveredKey.array();
  }

  /**
   * Compute the address of the key that signed the given signature.
   *
   * @param messageHash 32-byte hash of message
   * @param signature         -
   * @return 20-byte address
   */
  public static byte[] signatureToAddress(byte[] messageHash,
      ECDSASignature signature) throws
      SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash, signature.toByteArray()));
  }
}
