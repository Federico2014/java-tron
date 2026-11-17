package org.tron.keystore;

import static java.nio.charset.StandardCharsets.UTF_8;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.SCrypt;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.Hash;
import org.tron.common.crypto.SignInterface;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.StringUtil;
import org.tron.core.exception.CipherException;

public class WalletCreateValidationTest {

  private static final String PASSWORD = "123456";

  private static void assertRejected(String password, SignInterface sign, int n, int p) {
    try (MockedStatic<SCrypt> scrypt = mockStatic(SCrypt.class)) {
      assertThrows(CipherException.class, () -> Wallet.create(password, sign, n, p));
      scrypt.verifyNoInteractions();
    }
  }

  @Test
  public void testInvalidPasswordsAreRejectedBeforeKdf() {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    for (String password : new String[] {null, "", "12345"}) {
      assertRejected(password, key, 4096, 1);
      try (MockedStatic<SCrypt> scrypt = mockStatic(SCrypt.class)) {
        assertThrows(CipherException.class, () -> Wallet.createLight(password, key));
        assertThrows(CipherException.class, () -> Wallet.createStandard(password, key));
        scrypt.verifyNoInteractions();
      }
    }
  }

  @Test
  public void testMissingAndPublicOnlyKeysAreRejectedBeforeKdf() {
    assertRejected(PASSWORD, null, 4096, 1);
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    assertRejected(PASSWORD, ECKey.fromPublicOnly(key.getPubKey()), 4096, 1);
  }

  @Test
  public void testInvalidPrivateKeysAreRejectedBeforeKdf() {
    byte[] order = ByteArray.fromHexString(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    byte[] aboveOrder = order.clone();
    aboveOrder[31]++;
    for (byte[] bytes : new byte[][] {null, new byte[0], new byte[] {0}, new byte[31],
        new byte[33], new byte[34], new byte[32], order, aboveOrder}) {
      SignInterface sign = mock(SignInterface.class);
      when(sign.getPrivateKey()).thenReturn(bytes);
      assertRejected(PASSWORD, sign, 4096, 1);
    }
  }

  @Test
  public void testInvalidCostsAreRejectedBeforeKdf() {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    for (int n : new int[] {0, 2, 4095, 4097, 1 << 21}) {
      assertRejected(PASSWORD, key, n, 1);
    }
    for (int p : new int[] {-1, 0, 9}) {
      assertRejected(PASSWORD, key, 4096, p);
    }
  }

  @Test
  public void testCreateAcceptsConsistentSigningKey() throws Exception {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    byte[] privateKey = key.getPrivateKey();
    SignInterface sign = mock(SignInterface.class);
    when(sign.getPrivateKey()).thenReturn(privateKey);
    when(sign.getAddress()).thenReturn(key.getAddress());

    WalletFile wallet = Wallet.create(PASSWORD, sign, 4096, 1);

    assertEquals(StringUtil.encode58Check(key.getAddress()), wallet.getAddress());
    assertArrayEquals(privateKey, Wallet.decrypt(PASSWORD, wallet).getPrivateKey());
    assertArrayEquals(key.getPrivateKey(), privateKey);
    verify(sign).getPrivateKey();
    verify(sign).getAddress();
  }

  @Test
  public void testValidPrivateKeyEncodingsRoundTrip() throws Exception {
    byte[] shortKey = new byte[31];
    shortKey[30] = 1;
    byte[] signedKey = BigInteger.ONE.shiftLeft(255).toByteArray();
    for (byte[] bytes : new byte[][] {new byte[] {1}, shortKey,
        ECKey.fromPrivate(BigInteger.ONE).getPrivateKey(), signedKey}) {
      ECKey key = ECKey.fromPrivate(bytes);
      SignInterface sign = mock(SignInterface.class);
      when(sign.getPrivateKey()).thenReturn(bytes);
      when(sign.getAddress()).thenReturn(key.getAddress());

      WalletFile wallet = Wallet.create(PASSWORD, sign, 4096, 1);

      assertEquals(bytes.length,
          ByteArray.fromHexString(wallet.getCrypto().getCiphertext()).length);
      assertArrayEquals(key.getPrivateKey(), Wallet.decrypt(PASSWORD, wallet).getPrivateKey());
    }
  }

  @Test
  public void testInvalidDecryptedKeysStillThrowCipherException() throws Exception {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    byte[] invalidSignByte = new byte[33];
    invalidSignByte[0] = 1;
    byte[] unnecessarySignByte = new byte[33];
    unnecessarySignByte[32] = 1;
    byte[] order = ByteArray.fromHexString(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    for (byte[] bytes : new byte[][] {new byte[1], new byte[31], new byte[32],
        invalidSignByte, unnecessarySignByte, order}) {
      WalletFile wallet = Wallet.create(PASSWORD, key, 4096, 1);
      encryptPrivateKey(wallet, PASSWORD, bytes);

      CipherException error = assertThrows(CipherException.class,
          () -> Wallet.decrypt(PASSWORD, wallet));
      assertEquals("Invalid private key in keystore", error.getMessage());
    }
  }

  @Test
  public void testKdfFailureIsWrapped() {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    IllegalArgumentException cause = new IllegalArgumentException("KDF failure");
    try (MockedStatic<SCrypt> scrypt = mockStatic(SCrypt.class)) {
      scrypt.when(() -> SCrypt.generate(any(byte[].class), any(byte[].class),
          anyInt(), anyInt(), anyInt(), anyInt())).thenThrow(cause);
      CipherException error = assertThrows(CipherException.class,
          () -> Wallet.create(PASSWORD, key, 4096, 1));
      assertEquals("Scrypt key derivation failed", error.getMessage());
      assertSame(cause, error.getCause());
    }
  }

  @Test
  public void testLegacyShortPasswordsStillDecrypt() throws Exception {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    for (String password : new String[] {"", "short"}) {
      WalletFile wallet = Wallet.create(PASSWORD, key, 4096, 1);
      encryptPrivateKey(wallet, password, key.getPrivateKey());

      assertArrayEquals(key.getPrivateKey(), Wallet.decrypt(password, wallet).getPrivateKey());
    }
  }

  private static void encryptPrivateKey(WalletFile wallet, String password, byte[] privateKey)
      throws Exception {
    WalletFile.Crypto crypto = wallet.getCrypto();
    WalletFile.ScryptKdfParams params = (WalletFile.ScryptKdfParams) crypto.getKdfparams();
    byte[] derived = SCrypt.generate(password.getBytes(UTF_8),
        ByteArray.fromHexString(params.getSalt()), params.getN(), params.getR(), params.getP(),
        params.getDklen());
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOf(derived, 16), "AES"),
        new IvParameterSpec(ByteArray.fromHexString(crypto.getCipherparams().getIv())));
    byte[] ciphertext = cipher.doFinal(privateKey);
    byte[] macInput = new byte[16 + ciphertext.length];
    System.arraycopy(derived, 16, macInput, 0, 16);
    System.arraycopy(ciphertext, 0, macInput, 16, ciphertext.length);
    crypto.setCiphertext(ByteArray.toHexString(ciphertext));
    crypto.setMac(ByteArray.toHexString(Hash.sha3(macInput)));
  }
}
