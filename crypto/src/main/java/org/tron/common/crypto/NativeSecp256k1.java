package org.tron.common.crypto;

import static org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1.SECP256K1_EC_UNCOMPRESSED;

import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.LongByReference;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Base64;
import org.hyperledger.besu.nativelib.secp256k1.LibSecp256k1;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;

/**
 * JNA-backed secp256k1 key, signing and public-key recovery implementation.
 *
 * <p>The wire format, canonical S value and recovery-id handling intentionally match {@link
 * ECKey}. Enabling native verification does not automatically switch key generation or signing;
 * callers must invoke {@link #sign(byte[], byte[])} explicitly.
 */
@Slf4j(topic = "crypto")
public final class NativeSecp256k1 extends ECKey {

  private static final int HASH_LENGTH = 32;
  private static final int MAX_PRIVATE_KEY_LENGTH = 32;
  private static final int COMPACT_SIGNATURE_LENGTH = 64;
  private static final int BASE64_SIGNATURE_LENGTH = 65;
  private static final int UNCOMPRESSED_PUBLIC_KEY_LENGTH = 65;
  private static final boolean AVAILABLE = loadNativeLibrary();
  private final LibSecp256k1.secp256k1_pubkey publicKey =
      new LibSecp256k1.secp256k1_pubkey();

  /**
   * Generates a new secp256k1 key pair using the default source of randomness.
   */
  public NativeSecp256k1() throws SignatureException {
    super();
    initializePublicKey();
  }

  /**
   * Generates a new secp256k1 key pair using the supplied source of randomness.
   *
   * @param secureRandom source of randomness used to generate the private key
   */
  public NativeSecp256k1(SecureRandom secureRandom) throws SignatureException {
    super(requireSecureRandom(secureRandom));
    initializePublicKey();
  }

  /**
   * Creates a secp256k1 key pair from private-key bytes.
   *
   * @param privateKey unsigned private-key bytes in the range {@code [1, n - 1]}
   */
  public NativeSecp256k1(byte[] privateKey) throws SignatureException {
    super(validatePrivateKey(privateKey), true);
    initializePublicKey();
  }

  public static boolean isAvailable() {
    return AVAILABLE;
  }

  @Override
  public byte[] getPubKey() {
    ByteBuffer serialized = ByteBuffer.allocate(UNCOMPRESSED_PUBLIC_KEY_LENGTH);
    LongByReference serializedLength =
        new LongByReference(UNCOMPRESSED_PUBLIC_KEY_LENGTH);
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        serialized,
        serializedLength,
        publicKey,
        SECP256K1_EC_UNCOMPRESSED) == 0
        || serializedLength.getValue() != UNCOMPRESSED_PUBLIC_KEY_LENGTH) {
      throw new IllegalStateException("Could not serialize native secp256k1 public key");
    }
    return serialized.array();
  }

  @Override
  public ECDSASignature sign(byte[] messageHash) {
    byte[] privateKey = getPrivateKey();
    try {
      return sign(messageHash, privateKey);
    } catch (SignatureException e) {
      throw new IllegalStateException("Could not create native secp256k1 signature", e);
    } finally {
      if (privateKey != null) {
        Arrays.fill(privateKey, (byte) 0);
      }
    }
  }

  private static boolean loadNativeLibrary() {
    try {
      boolean available = LibSecp256k1.CONTEXT != null;
      if (!available) {
        logger.warn("Native secp256k1 context is unavailable");
      }
      return available;
    } catch (LinkageError | RuntimeException e) {
      logger.warn("Unable to load native secp256k1 library", e);
      return false;
    }
  }

  private void initializePublicKey() throws SignatureException {
    ensureAvailable();
    byte[] privateKey = getPrivateKey();
    try {
      if (privateKey == null || LibSecp256k1.secp256k1_ec_pubkey_create(
          LibSecp256k1.CONTEXT, publicKey, privateKey) == 0) {
        throw new SignatureException("Could not create native secp256k1 public key");
      }
    } finally {
      if (privateKey != null) {
        Arrays.fill(privateKey, (byte) 0);
      }
    }
  }

  /**
   * Creates a recoverable ECDSA signature for a 32-byte message hash.
   *
   * @param messageHash 32-byte message hash
   * @param privateKey 32-byte secp256k1 private key
   * @return canonical recoverable signature compatible with {@link ECKey}
   */
  public static ECDSASignature sign(byte[] messageHash, byte[] privateKey)
      throws SignatureException {
    ensureAvailable();
    validateMessageHash(messageHash);
    if (privateKey == null || privateKey.length != HASH_LENGTH) {
      throw new IllegalArgumentException("privateKey argument must be 32 bytes");
    }

    byte[] nativePrivateKey = Arrays.copyOf(privateKey, privateKey.length);
    try {
      LibSecp256k1.secp256k1_ecdsa_recoverable_signature nativeSignature =
          new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();
      if (LibSecp256k1.secp256k1_ecdsa_sign_recoverable(
          LibSecp256k1.CONTEXT,
          nativeSignature,
          messageHash,
          nativePrivateKey,
          null,
          null) == 0) {
        throw new SignatureException("Could not create native secp256k1 signature");
      }

      ByteBuffer compactSignature = ByteBuffer.allocate(COMPACT_SIGNATURE_LENGTH);
      IntByReference recoveryIdReference = new IntByReference();
      LibSecp256k1.secp256k1_ecdsa_recoverable_signature_serialize_compact(
          LibSecp256k1.CONTEXT,
          compactSignature,
          recoveryIdReference,
          nativeSignature);

      int recoveryId = recoveryIdReference.getValue();
      if (recoveryId < 0 || recoveryId > 3) {
        throw new SignatureException("Native signature recovery ID is out of range: "
            + recoveryId);
      }
      byte[] signatureBytes = compactSignature.array();
      ECDSASignature signature = ECDSASignature.fromComponents(
          Arrays.copyOfRange(signatureBytes, 0, HASH_LENGTH),
          Arrays.copyOfRange(signatureBytes, HASH_LENGTH, COMPACT_SIGNATURE_LENGTH),
          (byte) (recoveryId + 27));

      if (signature.s.compareTo(ECKey.HALF_CURVE_ORDER) > 0) {
        signature = ECDSASignature.fromComponents(
            ByteUtil.bigIntegerToBytes(signature.r, HASH_LENGTH),
            ByteUtil.bigIntegerToBytes(ECKey.CURVE.getN().subtract(signature.s), HASH_LENGTH),
            (byte) ((recoveryId ^ 1) + 27));
      }
      return signature;
    } finally {
      Arrays.fill(nativePrivateKey, (byte) 0);
    }
  }

  /**
   * Recovers the TRON address from a base64 signature encoded as {@code v || r || s}.
   */
  public static byte[] signatureToAddress(byte[] messageHash, String signatureBase64)
      throws SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash, signatureBase64));
  }

  /**
   * Recovers the TRON address from the supplied ECDSA signature components.
   */
  public static byte[] signatureToAddress(byte[] messageHash, ECDSASignature signature)
      throws SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash, signature));
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash, String signatureBase64)
      throws SignatureException {
    byte[] encoded;
    try {
      encoded = Base64.decode(signatureBase64);
    } catch (RuntimeException e) {
      throw new SignatureException("Could not decode base64", e);
    }
    // ECKey historically accepts trailing bytes, so preserve that consensus behaviour.
    if (encoded.length < BASE64_SIGNATURE_LENGTH) {
      throw new SignatureException("Signature truncated, expected 65 bytes and got "
          + encoded.length);
    }

    ECDSASignature signature = ECDSASignature.fromComponents(
        Arrays.copyOfRange(encoded, 1, 33),
        Arrays.copyOfRange(encoded, 33, 65),
        encoded[0]);
    return signatureToKeyBytes(messageHash, signature);
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash, ECDSASignature signature)
      throws SignatureException {
    ensureAvailable();
    validateMessageHash(messageHash);
    if (signature == null) {
      throw new SignatureException("Signature must not be null");
    }
    if (signature.r == null || signature.s == null
        || signature.r.signum() < 0 || signature.s.signum() < 0
        || signature.r.bitLength() > HASH_LENGTH * Byte.SIZE
        || signature.s.bitLength() > HASH_LENGTH * Byte.SIZE) {
      throw new SignatureException("Signature components must be unsigned 32-byte integers");
    }

    int header = signature.v;
    if (header < 27 || header > 34) {
      throw new SignatureException("Header byte out of range: " + header);
    }
    if (header >= 31) {
      header -= 4;
    }
    int recoveryId = header - 27;

    byte[] compactSignature = ByteUtil.merge(
        ByteUtil.bigIntegerToBytes(signature.r, HASH_LENGTH),
        ByteUtil.bigIntegerToBytes(signature.s, HASH_LENGTH));
    if (compactSignature.length != COMPACT_SIGNATURE_LENGTH) {
      throw new SignatureException("Compact signature must be 64 bytes");
    }

    LibSecp256k1.secp256k1_ecdsa_recoverable_signature nativeSignature =
        new LibSecp256k1.secp256k1_ecdsa_recoverable_signature();
    if (LibSecp256k1.secp256k1_ecdsa_recoverable_signature_parse_compact(
        LibSecp256k1.CONTEXT, nativeSignature, compactSignature, (byte) recoveryId) == 0) {
      throw new SignatureException("Could not parse signature");
    }

    LibSecp256k1.secp256k1_pubkey publicKey = new LibSecp256k1.secp256k1_pubkey();
    if (LibSecp256k1.secp256k1_ecdsa_recover(
        LibSecp256k1.CONTEXT, publicKey, nativeSignature, messageHash) == 0) {
      throw new SignatureException("Could not recover public key from signature");
    }

    ByteBuffer serialized = ByteBuffer.allocate(UNCOMPRESSED_PUBLIC_KEY_LENGTH);
    LongByReference serializedLength =
        new LongByReference(UNCOMPRESSED_PUBLIC_KEY_LENGTH);
    if (LibSecp256k1.secp256k1_ec_pubkey_serialize(
        LibSecp256k1.CONTEXT,
        serialized,
        serializedLength,
        publicKey,
        SECP256K1_EC_UNCOMPRESSED) == 0
        || serializedLength.getValue() != UNCOMPRESSED_PUBLIC_KEY_LENGTH) {
      throw new SignatureException("Could not serialize recovered public key");
    }
    return serialized.array();
  }

  private static void ensureAvailable() throws SignatureException {
    if (!AVAILABLE) {
      throw new SignatureException("Native secp256k1 library is unavailable");
    }
  }

  private static void validateMessageHash(byte[] messageHash) {
    if (messageHash == null || messageHash.length != HASH_LENGTH) {
      throw new IllegalArgumentException("messageHash argument must be 32 bytes");
    }
  }

  private static SecureRandom requireSecureRandom(SecureRandom secureRandom) {
    if (secureRandom == null) {
      throw new IllegalArgumentException("secureRandom argument must not be null");
    }
    return secureRandom;
  }

  /**
   * Validates and normalises a private-key byte array for native secp256k1 operations.
   * Accepts unsigned encodings up to 32 bytes and Java {@link BigInteger} encodings with
   * one leading zero sign byte ({@link BigInteger#toByteArray()} prepends {@code 0x00} when
   * the scalar's high bit is set). The leading byte is stripped before the range check.
   */
  private static byte[] validatePrivateKey(byte[] privateKey) {
    if (ByteArray.isEmpty(privateKey)) {
      throw new IllegalArgumentException("privateKey argument must contain 1 to 32 bytes");
    }
    // Strip BigInteger.toByteArray() sign-padding when present
    if (privateKey.length == MAX_PRIVATE_KEY_LENGTH + 1
        && privateKey[0] == 0
        && (privateKey[1] & 0x80) != 0) {
      privateKey = Arrays.copyOfRange(privateKey, 1, privateKey.length);
    } else if (privateKey.length > MAX_PRIVATE_KEY_LENGTH) {
      throw new IllegalArgumentException("privateKey argument must contain 1 to 32 bytes");
    }
    BigInteger privateKeyValue = new BigInteger(1, privateKey);
    if (privateKeyValue.signum() <= 0 || privateKeyValue.compareTo(ECKey.CURVE.getN()) >= 0) {
      throw new IllegalArgumentException("privateKey argument is outside the secp256k1 range");
    }
    return privateKey;
  }
}
