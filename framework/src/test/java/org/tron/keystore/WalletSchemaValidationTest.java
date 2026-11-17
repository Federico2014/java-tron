package org.tron.keystore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.tron.common.utils.ByteArray;
import org.tron.common.utils.StringUtil;
import org.tron.core.exception.CipherException;

public class WalletSchemaValidationTest {

  private static String hex(int bytes) {
    return ByteArray.toHexString(new byte[bytes]);
  }

  private static WalletFile validWallet(boolean pbkdf2) {
    WalletFile wallet = new WalletFile();
    wallet.setVersion(3);
    wallet.setAddress("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb");
    WalletFile.Crypto crypto = new WalletFile.Crypto();
    crypto.setCipher("aes-128-ctr");
    crypto.setCiphertext(hex(32));
    crypto.setMac(hex(32));
    WalletFile.CipherParams cipher = new WalletFile.CipherParams();
    cipher.setIv(hex(16));
    crypto.setCipherparams(cipher);
    if (pbkdf2) {
      crypto.setKdf("pbkdf2");
      WalletFile.Aes128CtrKdfParams params = new WalletFile.Aes128CtrKdfParams();
      params.setDklen(32);
      params.setC(1);
      params.setPrf("hmac-sha256");
      params.setSalt("00");
      crypto.setKdfparams(params);
    } else {
      crypto.setKdf("scrypt");
      WalletFile.ScryptKdfParams params = new WalletFile.ScryptKdfParams();
      params.setDklen(32);
      params.setN(4096);
      params.setR(8);
      params.setP(1);
      params.setSalt("00");
      crypto.setKdfparams(params);
    }
    wallet.setCrypto(crypto);
    return wallet;
  }

  private static void assertRejected(WalletFile wallet) {
    try (MockedStatic<SCrypt> scrypt = mockStatic(SCrypt.class);
        MockedConstruction<PKCS5S2ParametersGenerator> pbkdf2 =
            mockConstruction(PKCS5S2ParametersGenerator.class)) {
      assertFalse(Wallet.isValidKeystoreFile(wallet));
      assertThrows(CipherException.class, () -> Wallet.validate(wallet));
      assertThrows(CipherException.class, () -> Wallet.decrypt("password", wallet));
      scrypt.verifyNoInteractions();
      assertTrue("Malformed input must be rejected before PBKDF2", pbkdf2.constructed().isEmpty());
    }
  }

  @Test
  public void testMissingRequiredSectionsAreRejectedBeforeKdf() {
    assertRejected(null);
    List<Consumer<WalletFile>> mutations = Arrays.asList(
        w -> w.setCrypto(null),
        w -> w.getCrypto().setCipher(null),
        w -> w.getCrypto().setCipherparams(null),
        w -> w.getCrypto().setKdf(null),
        w -> w.getCrypto().setKdfparams(null));
    for (boolean pbkdf2 : new boolean[] {false, true}) {
      for (Consumer<WalletFile> mutation : mutations) {
        WalletFile wallet = validWallet(pbkdf2);
        mutation.accept(wallet);
        assertRejected(wallet);
      }
    }
  }

  @Test
  public void testMalformedHexFieldsAreRejectedBeforeKdf() {
    List<BiConsumer<WalletFile, String>> fields = Arrays.asList(
        (w, s) -> w.getCrypto().setCiphertext(s),
        (w, s) -> w.getCrypto().setMac(s),
        (w, s) -> w.getCrypto().getCipherparams().setIv(s),
        (w, s) -> {
          WalletFile.KdfParams params = w.getCrypto().getKdfparams();
          if (params instanceof WalletFile.ScryptKdfParams) {
            ((WalletFile.ScryptKdfParams) params).setSalt(s);
          } else {
            ((WalletFile.Aes128CtrKdfParams) params).setSalt(s);
          }
        });
    for (boolean pbkdf2 : new boolean[] {false, true}) {
      for (BiConsumer<WalletFile, String> field : fields) {
        for (String value : new String[] {null, "", "0x", "0", "zz", "00 00", "００"}) {
          WalletFile wallet = validWallet(pbkdf2);
          field.accept(wallet, value);
          assertRejected(wallet);
        }
      }
    }
  }

  @Test
  public void testInvalidFixedLengthsAreRejectedBeforeKdf() {
    for (int length : new int[] {0, 1, 15, 17, 31, 33}) {
      WalletFile wallet = validWallet(false);
      wallet.getCrypto().getCipherparams().setIv(hex(length));
      assertRejected(wallet);
      wallet = validWallet(false);
      wallet.getCrypto().setMac(hex(length));
      assertRejected(wallet);
    }
  }

  @Test
  public void testCiphertextLengthBounds() throws Exception {
    for (boolean pbkdf2 : new boolean[] {false, true}) {
      for (String prefix : new String[] {"", "0x"}) {
        for (int length : new int[] {0, 34, 35, 64}) {
          WalletFile wallet = validWallet(pbkdf2);
          wallet.getCrypto().setCiphertext(prefix + hex(length));
          assertRejected(wallet);
        }
        for (int length : new int[] {1, 31, 32, 33}) {
          WalletFile wallet = validWallet(pbkdf2);
          wallet.getCrypto().setCiphertext(prefix + hex(length));
          Wallet.validate(wallet);
        }
      }
    }
  }

  @Test
  public void testInvalidAddressesAreRejectedBeforeKdf() {
    for (String address : new String[] {"T0", "../wallet", hex(64),
        "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwa", StringUtil.encode58Check(new byte[21])}) {
      WalletFile wallet = validWallet(false);
      wallet.setAddress(address);
      assertRejected(wallet);
    }
  }

  @Test
  public void testAbsentAddressIsValidForDecryptButNotDiscovery() throws Exception {
    for (String address : new String[] {null, ""}) {
      WalletFile wallet = validWallet(false);
      wallet.setAddress(address);
      Wallet.validate(wallet);
      assertFalse(Wallet.isValidKeystoreFile(wallet));
    }
  }

  @Test
  public void testKdfTypeMismatchIsRejectedBeforeDerivation() {
    for (boolean pbkdf2 : new boolean[] {false, true}) {
      WalletFile wallet = validWallet(pbkdf2);
      wallet.getCrypto().setKdf(pbkdf2 ? "scrypt" : "pbkdf2");
      assertRejected(wallet);
    }
  }

  @Test
  public void testPbkdf2ParametersAreRejectedBeforeDerivation() {
    for (int dklen : new int[] {-1, 0, 1, 31, 129, Integer.MAX_VALUE}) {
      WalletFile wallet = validWallet(true);
      ((WalletFile.Aes128CtrKdfParams) wallet.getCrypto().getKdfparams()).setDklen(dklen);
      assertRejected(wallet);
    }
    for (int c : new int[] {-1, 0, (1 << 20) + 1}) {
      WalletFile wallet = validWallet(true);
      ((WalletFile.Aes128CtrKdfParams) wallet.getCrypto().getKdfparams()).setC(c);
      assertRejected(wallet);
    }
    for (String prf : new String[] {null, "", "hmac-sha1"}) {
      WalletFile wallet = validWallet(true);
      ((WalletFile.Aes128CtrKdfParams) wallet.getCrypto().getKdfparams()).setPrf(prf);
      assertRejected(wallet);
    }
  }

  @Test
  public void testScryptR1Boundary() throws Exception {
    WalletFile wallet = validWallet(false);
    WalletFile.ScryptKdfParams params =
        (WalletFile.ScryptKdfParams) wallet.getCrypto().getKdfparams();
    params.setR(1);
    params.setN(1 << 15);
    Wallet.validate(wallet);
    params.setN(1 << 16);
    assertRejected(wallet);
  }

  @Test
  public void testPbkdf2UsesDeclaredKeyLength() throws Exception {
    WalletFile wallet = validWallet(true);
    ((WalletFile.Aes128CtrKdfParams) wallet.getCrypto().getKdfparams()).setDklen(64);
    try (MockedConstruction<PKCS5S2ParametersGenerator> generators = mockConstruction(
        PKCS5S2ParametersGenerator.class, (generator, context) ->
            when(generator.generateDerivedParameters(512)).thenReturn(
                new KeyParameter(new byte[64])))) {
      CipherException error = assertThrows(CipherException.class,
          () -> Wallet.decrypt("password", wallet));
      assertEquals("Invalid password provided", error.getMessage());
      assertEquals(1, generators.constructed().size());
      verify(generators.constructed().get(0)).generateDerivedParameters(512);
    }
  }

  @Test
  public void testPrefixedAndUppercaseHexRemainAccepted() throws Exception {
    WalletFile wallet = validWallet(false);
    wallet.getCrypto().getCipherparams().setIv("0xAABBCCDDEEFF00112233445566778899");
    wallet.getCrypto().setMac("0x" + hex(32));
    wallet.getCrypto().setCiphertext("0x" + hex(32));
    ((WalletFile.ScryptKdfParams) wallet.getCrypto().getKdfparams()).setSalt("0xAABB");
    Wallet.validate(wallet);
    assertTrue(Wallet.isValidKeystoreFile(wallet));
  }
}
