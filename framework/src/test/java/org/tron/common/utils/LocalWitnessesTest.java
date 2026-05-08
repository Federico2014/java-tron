package org.tron.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

public class LocalWitnessesTest {

  // Real Falcon-512 keypair generated once per test class. We exercise the
  // (priv, pub) keypair config path with bytes that satisfy the BC ops, so the
  // tests below never hit cross-platform FFT determinism concerns.
  private static String priv;
  private static String pub;
  private static String priv2;
  private static String pub2;

  @BeforeClass
  public static void generateKeypairs() {
    FNDSA k1 = new FNDSA();
    FNDSA k2 = new FNDSA();
    priv = Hex.toHexString(k1.getPrivateKey());
    pub = Hex.toHexString(k1.getPublicKey());
    priv2 = Hex.toHexString(k2.getPrivateKey());
    pub2 = Hex.toHexString(k2.getPublicKey());
  }

  @Test
  public void fnDsa512AcceptsValidKeypair() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Collections.singletonList(priv), Collections.singletonList(pub));
    assertEquals(PQScheme.FN_DSA_512, lw.getPqScheme());
    assertEquals(1, lw.getPqPrivateKeys().size());
    assertEquals(1, lw.getPqPublicKeys().size());
  }

  @Test
  public void fnDsa512AcceptsMultipleKeypairs() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Arrays.asList(priv, priv2), Arrays.asList(pub, pub2));
    assertEquals(2, lw.getPqPrivateKeys().size());
    assertEquals(2, lw.getPqPublicKeys().size());
  }

  @Test
  public void mismatchedListSizesRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Arrays.asList(priv, priv2), Collections.singletonList(pub)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("size mismatch"));
  }

  @Test
  public void wrongLengthPrivateKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String shortPriv = priv.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(shortPriv),
            Collections.singletonList(pub)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
    // FN-DSA-512 private key is 1280 bytes = 2560 hex chars.
    assertTrue(err.getMessage().contains("2560"));
  }

  @Test
  public void wrongLengthPublicKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String shortPub = pub.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(priv),
            Collections.singletonList(shortPub)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ public key"));
    // FN-DSA-512 public key is 896 bytes = 1792 hex chars.
    assertTrue(err.getMessage().contains("1792"));
  }

  @Test
  public void nonHexPrivateKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String badPriv = "zz" + priv.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(badPriv),
            Collections.singletonList(pub)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("hex"));
  }

  @Test
  public void unsupportedSchemeRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqScheme(PQScheme.UNRECOGNIZED));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("unsupported PQ signature scheme"));
  }

  @Test
  public void nullSchemeRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class, () -> lw.setPqScheme(null));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("unsupported PQ signature scheme"));
  }

  @Test
  public void supportedSchemeAccepted() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqScheme(PQScheme.FN_DSA_512);
    assertEquals(PQScheme.FN_DSA_512, lw.getPqScheme());
  }

  @Test
  public void emptyKeypairsAreNoop() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(Collections.emptyList(), Collections.emptyList());
    lw.setPqKeypairs(null, null);
    assertEquals(0, lw.getPqPrivateKeys().size());
    assertEquals(0, lw.getPqPublicKeys().size());
  }

  @Test
  public void zeroXPrefixedHexAccepted() {
    // validatePqKey strips a leading "0x" before measuring the length, so
    // hex strings with the prefix must be accepted.
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqKeypairs(
        Collections.singletonList("0x" + priv),
        Collections.singletonList("0x" + pub));
    assertEquals(1, lw.getPqPrivateKeys().size());
  }

  @Test
  public void blankKeyRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqKeypairs(Collections.singletonList(""),
            Collections.singletonList(pub)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ private key"));
  }
}
