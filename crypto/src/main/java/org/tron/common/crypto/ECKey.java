package org.tron.common.crypto;
/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.tron.common.crypto.jce.ECKeyFactory;
import org.tron.common.crypto.jce.ECKeyPairGenerator;
import org.tron.common.crypto.jce.TronCastleProvider;
import org.tron.common.utils.BIUtil;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.ByteUtil;

/**
 * ECDSA key pair on the secp256k1 curve used by the TRON network.
 * <p>
 * ECDSA signatures are mutable: for a given (R, S) pair, both (R, S) and (R, N - S mod N) are
 * valid. Canonical signatures satisfy 1 &lt;= S &lt;= N/2, where N is the curve order
 * (SECP256K1N).
 * <p>
 * Reference: <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">
 * BIP-62: Low S values in signatures</a>
 * <p>
 * For the TRON network, since the transaction ID does not include the signature and can still
 * guarantee the transaction uniqueness, it is not necessary to strictly enforce signature
 * canonicalization. Signature verification accepts both low-S and high-S forms.
 * <p>
 * Note: While not enforced by the protocol, using low-S signatures is recommended to prevent
 * signature malleability.
 */
@Slf4j(topic = "crypto")
public class ECKey implements Serializable, SignInterface {

  /** The parameters of the secp256k1 curve. */
  public static final ECDomainParameters CURVE;
  /** The EC parameter spec derived from the secp256k1 curve parameters. */
  public static final ECParameterSpec CURVE_SPEC;

  public static final BigInteger HALF_CURVE_ORDER;
  private static final BigInteger SECP256K1N;
  private static final SecureRandom secureRandom;
  private static final long serialVersionUID = -728224901792295832L;

  static {
    // All clients must agree on the curve to use by agreement.
    X9ECParameters params = SECNamedCurves.getByName("secp256k1");
    CURVE = new ECDomainParameters(params.getCurve(), params.getG(),
        params.getN(), params.getH());
    CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(),
        params.getN(), params.getH());
    SECP256K1N = params.getN();
    HALF_CURVE_ORDER = params.getN().shiftRight(1);
    secureRandom = new SecureRandom();
  }

  protected final ECPoint pub;
  // The two parts of the key. If "priv" is set, "pub" can always be
  // calculated. If "pub" is set but not "priv", we
  // can only verify signatures not make them.
  // TODO: Redesign this class to use consistent internals and more
  // efficient serialization.
  private final PrivateKey privKey;
  // the Java Cryptographic Architecture provider to use for Signature
  // this is set along with the PrivateKey privKey and must be compatible
  // this provider will be used when selecting a Signature instance
  // https://docs.oracle.com/javase/8/docs/technotes/guides/security
  // /SunProviders.html
  private final Provider provider;

  // Computed lazily; volatile ensures visibility. Benign write race: both threads derive identical bytes.
  private transient volatile byte[] pubKeyHash;
  private transient volatile byte[] nodeId;

  /**
   * Generates an entirely new keypair using BouncyCastle as the security provider.
   */
  public ECKey() {
    this(secureRandom);
  }

  /**
   * Generates a new keypair using the given security provider and random source.
   */
  public ECKey(Provider provider, SecureRandom secureRandom) {
    this.provider = provider;

    final KeyPairGenerator keyPairGen = ECKeyPairGenerator.getInstance(provider, secureRandom);
    final KeyPair keyPair = keyPairGen.generateKeyPair();

    this.privKey = keyPair.getPrivate();

    final PublicKey pubKey = keyPair.getPublic();
    if (pubKey instanceof BCECPublicKey) {
      pub = ((BCECPublicKey) pubKey).getQ();
    } else if (pubKey instanceof ECPublicKey) {
      pub = extractPublicKey((ECPublicKey) pubKey);
    } else {
      throw new AssertionError(
          "Expected Provider " + provider.getName()
              + " to produce a subtype of ECPublicKey, found "
              + pubKey.getClass());
    }
  }

  /**
   * Generates a new keypair with the given {@link SecureRandom}, using BouncyCastle.
   */
  public ECKey(SecureRandom secureRandom) {
    this(TronCastleProvider.getInstance(), secureRandom);
  }

  /**
   * Creates an ECKey from raw bytes, interpreted as a private or public key.
   */
  public ECKey(byte[] key, boolean isPrivateKey) {
    if (isPrivateKey) {
      if (!isValidPrivateKey(key)) {
        throw new IllegalArgumentException("Invalid private key.");
      }
      BigInteger pk = new BigInteger(1, key);
      this.privKey = privateKeyFromBigInteger(pk);
      this.pub = CURVE.getG().multiply(pk);
    } else {
      ECPoint point;
      try {
        point = CURVE.getCurve().decodePoint(key);
      } catch (RuntimeException e) {
        throw new IllegalArgumentException("Invalid public key.", e);
      }
      if (point.isInfinity() || !point.isValid()) {
        throw new IllegalArgumentException("Invalid public key.");
      }
      this.privKey = null;
      this.pub = point;
    }
    this.provider = TronCastleProvider.getInstance();
  }

  public ECKey(Provider provider, @Nullable PrivateKey privKey, ECPoint pub) {
    this.provider = provider;

    if (privKey == null || isECPrivateKey(privKey)) {
      this.privKey = privKey;
    } else {
      throw new IllegalArgumentException(
          "Expected EC private key, given a private key object with" +
              " class "
              + privKey.getClass() +
              " and algorithm "
              + privKey.getAlgorithm());
    }

    if (pub == null || pub.isInfinity() || !pub.isValid()) {
      throw new IllegalArgumentException(
          "Public key is not a valid point on secp256k1 curve.");
    }
    this.pub = pub;
  }

  /**
   * Pairs a private key integer with a public EC point, using BouncyCastle.
   */
  public ECKey(@Nullable BigInteger priv, ECPoint pub) {
    this(
        TronCastleProvider.getInstance(),
        priv == null ? null : privateKeyFromBigInteger(priv),
        pub);
  }

  /**
   * Converts a JCE ECPublicKey into a BouncyCastle ECPoint.
   */
  private static ECPoint extractPublicKey(final ECPublicKey ecPublicKey) {
    final java.security.spec.ECPoint publicPointW = ecPublicKey.getW();
    final BigInteger xCoord = publicPointW.getAffineX();
    final BigInteger yCoord = publicPointW.getAffineY();

    return CURVE.getCurve().createPoint(xCoord, yCoord);
  }

  /**
   * Tests if a generic private key is an EC private key (checks both type and algorithm
   * to handle SunPKCS11 providers that return a generic PrivateKey).
   */
  private static boolean isECPrivateKey(PrivateKey privKey) {
    return privKey instanceof ECPrivateKey || privKey.getAlgorithm()
        .equals("EC");
  }

  /**
   * Converts a BigInteger into a PrivateKey object.
   */
  private static PrivateKey privateKeyFromBigInteger(BigInteger priv) {
    if (!isValidPrivateKey(priv)) {
      throw new IllegalArgumentException("Invalid private key.");
    }

    try {
      return ECKeyFactory
          .getInstance(TronCastleProvider.getInstance())
          .generatePrivate(new ECPrivateKeySpec(priv,
              CURVE_SPEC));
    } catch (InvalidKeySpecException ex) {
      throw new AssertionError("Assumed correct key spec statically");
    }
  }

  public static boolean isValidPrivateKey(byte[] keyBytes) {
    if (ByteArray.isEmpty(keyBytes)) {
      return false;
    }
    // Accept a 33-byte array only when the leading byte is 0x00 (BigInteger sign-byte padding);
    // reject anything longer or any non-canonical 33-byte encoding.
    if (keyBytes.length > 33 || (keyBytes.length == 33 && keyBytes[0] != 0x00)) {
      return false;
    }

    BigInteger key = new BigInteger(1, keyBytes);
    return key.compareTo(BigInteger.ONE) >= 0 && key.compareTo(CURVE.getN()) < 0;
  }

  public static boolean isValidPrivateKey(BigInteger privateKey) {
    if (privateKey == null) {
      return false;
    }
    return privateKey.compareTo(BigInteger.ONE) >= 0 && privateKey.compareTo(CURVE.getN()) < 0;
  }

  public static boolean isValidPublicKey(byte[] keyBytes) {
    if (ByteArray.isEmpty(keyBytes)) {
      return false;
    }

    try {
      ECPoint point = CURVE.getCurve().decodePoint(keyBytes);
      return !point.isInfinity() && point.isValid();
    } catch (RuntimeException e) {
      return false;
    }
  }

  /**
   * Compresses an elliptic curve point.
   *
   * @deprecated per-point compression property will be removed in Bouncy Castle
   */
  public static ECPoint compressPoint(ECPoint uncompressed) {
    return CURVE.getCurve().decodePoint(uncompressed.getEncoded(true));
  }

  /**
   * Decompresses an elliptic curve point.
   *
   * @deprecated per-point compression property will be removed in Bouncy Castle
   */
  public static ECPoint decompressPoint(ECPoint compressed) {
    return CURVE.getCurve().decodePoint(compressed.getEncoded(false));
  }

  /**
   * Creates an ECKey given the private key only.
   */
  public static ECKey fromPrivate(BigInteger privKey) {
    if (!isValidPrivateKey(privKey)) {
      throw new IllegalArgumentException("Invalid private key.");
    }

    return new ECKey(privKey, CURVE.getG().multiply(privKey));
  }

  /**
   * Creates an ECKey given the private key bytes.
   */
  public static ECKey fromPrivate(byte[] privKeyBytes) {
    if (!isValidPrivateKey(privKeyBytes)) {
      throw new IllegalArgumentException("Invalid private key.");
    }
    return fromPrivate(new BigInteger(1, privKeyBytes));
  }

  /**
   * Creates a verify-only ECKey from the given encoded public key bytes.
   */
  public static ECKey fromPublicOnly(byte[] pub) {
    if (ByteArray.isEmpty(pub)) {
      throw new IllegalArgumentException("Public key bytes cannot be null or empty");
    }
    ECPoint point = CURVE.getCurve().decodePoint(pub);
    return new ECKey(null, point);
  }

  /**
   * Returns the encoded public key bytes derived from the given private key.
   */
  public static byte[] publicKeyFromPrivate(BigInteger privKey, boolean compressed) {
    if (!isValidPrivateKey(privKey)) {
      throw new IllegalArgumentException("Invalid private key.");
    }
    ECPoint point = CURVE.getG().multiply(privKey);
    return point.getEncoded(compressed);
  }

  /**
   * Returns the 64-byte X,Y coordinates of a public point (without the 0x04 prefix).
   */
  public static byte[] pubBytesWithoutFormat(ECPoint pubPoint) {
    final byte[] pubBytes = pubPoint.getEncoded(/* uncompressed */ false);
    return Arrays.copyOfRange(pubBytes, 1, pubBytes.length);
  }

  /**
   * Recover the public key from an encoded node id.
   *
   * @param nodeId a 64-byte X,Y point pair
   */
  public static ECKey fromNodeId(byte[] nodeId) {
    check(nodeId.length == 64, "Expected a 64 byte node id");
    byte[] pubBytes = new byte[65];
    System.arraycopy(nodeId, 0, pubBytes, 1, nodeId.length);
    pubBytes[0] = 0x04; // uncompressed
    return ECKey.fromPublicOnly(pubBytes);
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash, String signatureBase64)
      throws SignatureException {
    byte[] signatureEncoded;
    try {
      signatureEncoded = Base64.decode(signatureBase64);
    } catch (RuntimeException e) {
      // This is what you getData back from Bouncy Castle if base64 doesn't decode
      throw new SignatureException("Could not decode base64", e);
    }
    // Parse the signature bytes into r/s and the selector value.
    if (signatureEncoded.length < 65) {
      throw new SignatureException("Signature truncated, expected 65 " +
          "bytes and got " + signatureEncoded.length);
    }

    return signatureToKeyBytes(
        messageHash,
        ECDSASignature.fromComponents(
            Arrays.copyOfRange(signatureEncoded, 1, 33),
            Arrays.copyOfRange(signatureEncoded, 33, 65),
            (byte) (signatureEncoded[0] & 0xFF)));
  }

  public static byte[] signatureToKeyBytes(byte[] messageHash,
      ECDSASignature sig) throws SignatureException {
    if (messageHash == null || sig == null) {
      throw new IllegalArgumentException("messageHash and sig cannot be null");
    }
    check(messageHash.length == 32, "messageHash argument has length " +
        messageHash.length);
    int header = sig.v;
    // The header byte: 0x1B = first key with even y, 0x1C = first key
    // with odd y,
    // 0x1D = second key with even y, 0x1E = second key
    // with odd y
    if (header < 27 || header > 34) {
      throw new SignatureException("Header byte out of range: " + header);
    }
    if (header >= 31) {
      header -= 4;
    }
    int recId = header - 27;
    byte[] key = ECKey.recoverPubBytesFromSignature(recId, sig,
        messageHash);
    if (key == null) {
      throw new SignatureException("Could not recover public key from " +
          "signature");
    }
    return key;
  }

  /**
   * Compute the address of the key that signed the given signature.
   *
   * @param messageHash     32-byte hash of message
   * @param signatureBase64 Base-64 encoded signature
   * @return 20-byte address
   */
  public static byte[] signatureToAddress(byte[] messageHash, String signatureBase64)
      throws SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash,
        signatureBase64));
  }

  /**
   * Compute the address of the key that signed the given signature.
   *
   * @param messageHash 32-byte hash of message
   * @param sig         -
   * @return 20-byte address
   */
  public static byte[] signatureToAddress(byte[] messageHash,
      ECDSASignature sig) throws SignatureException {
    return Hash.computeAddress(signatureToKeyBytes(messageHash, sig));
  }

  /**
   * Compute the key that signed the given signature.
   *
   * @param messageHash     32-byte hash of message
   * @param signatureBase64 Base-64 encoded signature
   * @return ECKey
   */
  public static ECKey signatureToKey(byte[] messageHash, String signatureBase64)
      throws SignatureException {
    final byte[] keyBytes = signatureToKeyBytes(messageHash,
        signatureBase64);
    return ECKey.fromPublicOnly(keyBytes);
  }

  /**
   * Returns true if the given pubkey is canonical, i.e. the correct length taking into account
   * compression.
   */
  public static boolean isPubKeyCanonical(byte[] pubkey) {
    if (pubkey[0] == 0x04) {
      // Uncompressed pubkey
      return pubkey.length == 65;
    } else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
      // Compressed pubkey
      return pubkey.length == 33;
    } else {
      return false;
    }
  }

  /**
   * Recover the public key from a signature, per SEC1v2 section 4.1.6.
   *
   * <p>recId (0–3) selects which of the candidate keys to return. Iterate recId in a loop and
   * retry if the result is null or not the expected key.
   *
   * @param recId       which possible key to recover
   * @param sig         the R and S components of the signature, wrapped
   * @param messageHash hash of the signed data
   * @return 65-byte encoded public key
   */
  @Nullable
  public static byte[] recoverPubBytesFromSignature(int recId,
      ECDSASignature sig, byte[] messageHash) {
    check(recId >= 0, "recId must be positive");
    check(sig.r.signum() >= 0, "r must be positive");
    check(sig.s.signum() >= 0, "s must be positive");
    check(messageHash != null, "messageHash must not be null");
    // 1.0 For j from 0 to h (h == recId here and the loop is outside
    // this function)
    // 1.1 Let x = r + jn
    BigInteger n = CURVE.getN(); // Curve order.
    BigInteger i = BigInteger.valueOf((long) recId / 2);
    BigInteger x = sig.r.add(i.multiply(n));
    // 1.2. Convert the integer x to an octet string X of length mlen
    // using the conversion routine
    // specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or
    // mlen = ⌈m/8⌉.
    // 1.3. Convert the octet string (16 set binary digits)||X to an
    // elliptic curve point R using the
    // conversion routine specified in Section 2.3.4. If this
    // conversion routine outputs “invalid”, then
    // do another iteration of Step 1.
    //
    // More concisely, what these points mean is to use X as a compressed
    // public key.
    ECCurve.Fp curve = (ECCurve.Fp) CURVE.getCurve();
    BigInteger prime = curve.getQ(); // Bouncy Castle is not consistent
    // about the letter it uses for the prime.
    if (x.compareTo(prime) >= 0) {
      // Cannot have point co-ordinates larger than this as everything
      // takes place modulo Q.
      return null;
    }
    // Compressed allKeys require you to know an extra bit of data about the
    // y-coord as there are two possibilities.
    // So it's encoded in the recId.
    ECPoint R = decompressKey(x, (recId & 1) == 1);
    // 1.4. If nR != point at infinity, then do another iteration of
    // Step 1 (callers responsibility).
    if (!R.multiply(n).isInfinity()) {
      return null;
    }
    // 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature
    // verification.
    BigInteger e = new BigInteger(1, messageHash);
    // 1.6. For k from 1 to 2 do the following. (loop is outside this
    // function via iterating recId)
    // 1.6.1. Compute a candidate public key as:
    // Q = mi(r) * (sR - eG)
    //
    // Where mi(x) is the modular multiplicative inverse. We transform
    // this into the following:
    // Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
    // Where -e is the modular additive inverse of e, that is z such that
    // z + e = 0 (mod n). In the above equation
    // ** is point multiplication and + is point addition (the EC group
    // operator).
    //
    // We can find the additive inverse by subtracting e from zero then
    // taking the mod. For example the additive
    // inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod
    // 11 = 8.
    BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
    BigInteger rInv = sig.r.modInverse(n);
    BigInteger srInv = rInv.multiply(sig.s).mod(n);
    BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
    ECPoint.Fp q = (ECPoint.Fp) ECAlgorithms.sumOfTwoMultiplies(CURVE
        .getG(), eInvrInv, R, srInv);
    return q.getEncoded(/* compressed */ false);
  }

  /**
   * @param recId       Which possible key to recover.
   * @param sig         the R and S components of the signature, wrapped.
   * @param messageHash Hash of the data that was signed.
   * @return 20-byte address
   */
  @Nullable
  public static byte[] recoverAddressFromSignature(int recId,
      ECDSASignature sig, byte[] messageHash) {
    final byte[] pubBytes = recoverPubBytesFromSignature(recId, sig,
        messageHash);
    if (pubBytes == null) {
      return null;
    } else {
      return Hash.computeAddress(pubBytes);
    }
  }

  /**
   * @param recId       Which possible key to recover.
   * @param sig         the R and S components of the signature, wrapped.
   * @param messageHash Hash of the data that was signed.
   * @return ECKey
   */
  @Nullable
  public static ECKey recoverFromSignature(int recId, ECDSASignature sig,
      byte[] messageHash) {
    final byte[] pubBytes = recoverPubBytesFromSignature(recId, sig,
        messageHash);
    if (pubBytes == null) {
      return null;
    } else {
      return ECKey.fromPublicOnly(pubBytes);
    }
  }

  /**
   * Decompresses a public key from x-coordinate and y-parity bit.
   */
  private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
    X9IntegerConverter x9 = new X9IntegerConverter();
    byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE
        .getCurve()));
    compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
    return CURVE.getCurve().decodePoint(compEnc);
  }

  private static void check(boolean test, String message) {
    if (!test) {
      throw new IllegalArgumentException(message);
    }
  }

  /**
   * Returns true if this is a public-key-only (watching) key with no private key access.
   */
  public boolean isPubKeyOnly() {
    return privKey == null;
  }

  /**
   * Returns true if this key has access to private key bytes.
   */
  public boolean hasPrivKey() {
    return privKey != null;
  }

  /**
   * Gets the address form of the public key.
   *
   * @return 21-byte address
   */
  public byte[] getAddress() {
    if (pubKeyHash == null) {
      pubKeyHash = Hash.computeAddress(this.pub);
    }
    return Arrays.copyOf(pubKeyHash, pubKeyHash.length);
  }

  @Override
  public String signHash(byte[] hash) {
    return sign(hash).toBase64();
  }

  public byte[] Base64toBytes(String signature) {
    byte[] signData = Base64.decode(signature);
    byte first = (byte) (signData[0] - 27);
    byte[] temp = Arrays.copyOfRange(signData, 1, 65);
    return ByteUtil.appendByte(temp, first);
  }

  /**
   * Generates the NodeID based on this key, that is the public key without first format byte
   */
  public byte[] getNodeId() {
    if (nodeId == null) {
      nodeId = pubBytesWithoutFormat(this.pub);
    }
    return Arrays.copyOf(nodeId, nodeId.length);
  }

  @Override
  public byte[] getPrivateKey() {
    return getPrivKeyBytes();
  }

  /**
   * Gets the encoded public key value.
   *
   * @return 65-byte encoded public key
   */
  public byte[] getPubKey() {
    return pub.getEncoded(/* compressed */ false);
  }

  /**
   * Gets the public key in the form of an elliptic curve point object from Bouncy Castle.
   */
  public ECPoint getPubKeyPoint() {
    return pub;
  }

  /**
   * Returns the private key as a BigInteger.
   */
  public BigInteger getPrivKey() {
    if (privKey == null) {
      throw new MissingPrivateKeyException();
    } else if (privKey instanceof BCECPrivateKey) {
      return ((BCECPrivateKey) privKey).getD();
    } else {
      throw new MissingPrivateKeyException();
    }
  }

  public String toString() {
    return "pub:" + Hex.toHexString(pub.getEncoded(false));
  }

  /**
   * Signs the given 32-byte hash and returns the R and S components as an ECDSASignature.
   */
  public ECDSASignature doSign(byte[] input) {
    if (input.length != 32) {
      throw new IllegalArgumentException("Expected 32 byte input to " +
          "ECDSA signature, not " + input.length);
    }
    // No decryption of private key required.
    if (privKey == null) {
      throw new MissingPrivateKeyException();
    }
    if (privKey instanceof BCECPrivateKey) {
      ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
      ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
          ((BCECPrivateKey) privKey).getD(), CURVE);
      signer.init(true, privKeyParams);
      BigInteger[] components = signer.generateSignature(input);
      return new ECDSASignature(components[0], components[1])
          .toCanonicalised();
    } else {
      throw new RuntimeException("ECKey signing error");
    }
  }

  /**
   * Signs the given 32-byte message hash with recovery ID.
   */
  public ECDSASignature sign(byte[] messageHash) {
    ECDSASignature sig = doSign(messageHash);
    // Now we have to work backwards to figure out the recId needed to
    // recover the signature.
    int recId = -1;
    byte[] thisKey = this.pub.getEncoded(/* compressed */ false);
    for (int i = 0; i < 4; i++) {
      byte[] k = ECKey.recoverPubBytesFromSignature(i, sig, messageHash);
      if (k != null && Arrays.equals(k, thisKey)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new RuntimeException("Could not construct a recoverable key" +
          ". This should never happen.");
    }
    sig.v = (byte) (recId + 27);
    return sig;
  }

  /**
   * Returns true if this key's public encoding has canonical length.
   */
  public boolean isPubKeyCanonical() {
    return isPubKeyCanonical(pub.getEncoded(/* uncompressed */ false));
  }

  /**
   * Returns 32-byte private key array, or null if unavailable.
   */
  @Nullable
  public byte[] getPrivKeyBytes() {
    if (privKey == null) {
      return null;
    } else if (privKey instanceof BCECPrivateKey) {
      return ByteUtil.bigIntegerToBytes(((BCECPrivateKey) privKey).getD(), 32);
    } else if (privKey instanceof ECPrivateKey) {
      return ByteUtil.bigIntegerToBytes(((ECPrivateKey) privKey).getS(), 32);
    } else {
      return null;
    }
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    ECKey ecKey = (ECKey) o;

    if (privKey != null && !privKey.equals(ecKey.privKey)) {
      return false;
    }
    return pub == null || pub.equals(ecKey.pub);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getPubKey());
  }

  public static class ECDSASignature implements SignatureInterface {

    /**
     * The two components of the signature.
     */
    public final BigInteger r, s;
    public byte v;

    /**
     * Constructs a signature with the given components. Does NOT automatically canonicalise.
     */
    public ECDSASignature(BigInteger r, BigInteger s) {
      this.r = r;
      this.s = s;
    }

    public ECDSASignature(byte[] r, byte[] s, byte v) {
      this.r = new BigInteger(1, r);
      this.s = new BigInteger(1, s);
      this.v = v;
    }

    private static ECDSASignature fromComponents(byte[] r, byte[] s) {
      return new ECDSASignature(new BigInteger(1, r), new BigInteger(1,
          s));
    }

    public static ECDSASignature fromComponents(byte[] r, byte[] s, byte v) {
      ECDSASignature signature = fromComponents(r, s);
      signature.v = v;
      return signature;
    }

    public static boolean validateComponents(BigInteger r, BigInteger s,
        byte v) {

      if (v != 27 && v != 28) {
        return false;
      }

      if (BIUtil.isLessThan(r, BigInteger.ONE)) {
        return false;
      }
      if (BIUtil.isLessThan(s, BigInteger.ONE)) {
        return false;
      }

      if (!BIUtil.isLessThan(r, SECP256K1N)) {
        return false;
      }
      return BIUtil.isLessThan(s, SECP256K1N);
    }

    public boolean validateComponents() {
      return validateComponents(r, s, v);
    }

    public ECDSASignature toCanonicalised() {
      if (s.compareTo(HALF_CURVE_ORDER) > 0) {
        // The order of the curve is the number of valid points that
        // exist on that curve. If S is in the upper
        // half of the number of valid points, then bring it back to
        // the lower half. Otherwise, imagine that
        // N = 10
        // s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2)
        // are valid solutions.
        // 10 - 8 == 2, giving us always the latter solution,
        // which is canonical.
        return new ECDSASignature(r, CURVE.getN().subtract(s));
      } else {
        return this;
      }
    }

    /**
     * Encodes this signature as a 65-byte Base64 string (v ‖ r ‖ s).
     */
    public String toBase64() {
      byte[] sigData = new byte[65]; // 1 header + 32 bytes for R + 32
      // bytes for S
      sigData[0] = v;
      System.arraycopy(ByteUtil.bigIntegerToBytes(this.r, 32), 0, sigData, 1, 32);
      System.arraycopy(ByteUtil.bigIntegerToBytes(this.s, 32), 0, sigData, 33, 32);
      return new String(Base64.encode(sigData), Charset.forName("UTF-8"));
    }

    public byte[] toByteArray() {
      final byte fixedV = this.v >= 27
          ? (byte) (this.v - 27)
          : this.v;

      return ByteUtil.merge(
          ByteUtil.bigIntegerToBytes(this.r, 32),
          ByteUtil.bigIntegerToBytes(this.s, 32),
          new byte[]{fixedV});
    }

    public String toHex() {
      return Hex.toHexString(toByteArray());
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }

      ECDSASignature signature = (ECDSASignature) o;

      if (!r.equals(signature.r)) {
        return false;
      }
      return s.equals(signature.s);
    }

    @Override
    public int hashCode() {
      int result = r.hashCode();
      result = 31 * result + s.hashCode();
      return result;
    }
  }

  @SuppressWarnings("serial")
  public static class MissingPrivateKeyException extends RuntimeException {

  }

}
