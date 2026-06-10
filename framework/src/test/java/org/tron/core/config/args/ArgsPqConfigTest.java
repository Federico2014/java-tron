package org.tron.core.config.args;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.tron.common.TestConstants;
import org.tron.common.crypto.pqc.FNDSA512;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.crypto.pqc.PQSchemeRegistry;
import org.tron.common.crypto.pqc.PQSignature;
import org.tron.common.crypto.pqc.PqKeypair;
import org.tron.common.utils.LocalWitnesses;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

/**
 * Covers the {@code localwitness_pq.keys} HOCON parsing in
 * {@link Args#setParam} — specifically the {@code key} vs {@code seed} entry
 * shape and the per-scheme guard that rejects {@code seed} for schemes whose
 * keygen is not reproducible across platforms (Falcon-512).
 */
public class ArgsPqConfigTest {

  @Rule
  public TemporaryFolder tmp = new TemporaryFolder();

  @After
  public void tearDown() {
    Args.clearParam();
  }

  @Test
  public void mlDsa44SeedEntryDerivesKeypair() throws IOException {
    byte[] seed = filled(MLDSA44.SEED_LENGTH, (byte) 0x07);
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", seed = \"" + Hex.toHexString(seed) + "\" }");

    Args.setParam(new String[]{"--witness"}, conf.toString());

    LocalWitnesses lw = Args.getLocalWitnesses();
    assertEquals(1, lw.getPqKeypairs().size());
    PqKeypair kp = lw.getPqKeypairs().get(0);
    assertEquals(PQScheme.ML_DSA_44, kp.getScheme());

    PQSignature expected = PQSchemeRegistry.fromSeed(PQScheme.ML_DSA_44, seed);
    assertEquals(Hex.toHexString(expected.getPrivateKey()), kp.getPrivateKey());
    assertEquals(Hex.toHexString(expected.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void mlDsa44SeedAcceptsZeroXPrefix() throws IOException {
    byte[] seed = filled(MLDSA44.SEED_LENGTH, (byte) 0x09);
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", seed = \"0x" + Hex.toHexString(seed) + "\" }");
    Args.setParam(new String[]{"--witness"}, conf.toString());
    assertEquals(1, Args.getLocalWitnesses().getPqKeypairs().size());
  }

  @Test
  public void fnDsa512SeedRejected() throws IOException {
    byte[] seed = filled(FNDSA512.SEED_LENGTH, (byte) 0x03);
    Path conf = writeConfWithEntry(
        "{ scheme = \"FN_DSA_512\", seed = \"" + Hex.toHexString(seed) + "\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("seed is not supported for FN_DSA_512"));
  }

  @Test
  public void keyAndSeedBothSetRejected() throws IOException {
    byte[] seed = filled(MLDSA44.SEED_LENGTH, (byte) 0x05);
    MLDSA44 ml = new MLDSA44(seed);
    byte[] priv = ml.getPrivateKey();
    byte[] pub = ml.getPublicKey();
    byte[] ext = concat(priv, pub);

    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\","
            + " key = \"" + Hex.toHexString(ext) + "\","
            + " seed = \"" + Hex.toHexString(seed) + "\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("exactly one of `key` or `seed`"));
  }

  @Test
  public void neitherKeyNorSeedRejected() throws IOException {
    Path conf = writeConfWithEntry("{ scheme = \"ML_DSA_44\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("exactly one of `key` or `seed`"));
  }

  @Test
  public void mlDsa44SeedWrongLengthRejected() throws IOException {
    String shortSeed = Hex.toHexString(filled(MLDSA44.SEED_LENGTH - 1, (byte) 0x02));
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", seed = \"" + shortSeed + "\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("seed must be"));
  }

  @Test
  public void mlDsa44PrivOnlyKeyDerivesPublicKey() throws IOException {
    MLDSA44 ml = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0C));
    byte[] priv = ml.getPrivateKey();
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", key = \"" + Hex.toHexString(priv) + "\" }");

    Args.setParam(new String[]{"--witness"}, conf.toString());

    LocalWitnesses lw = Args.getLocalWitnesses();
    assertEquals(1, lw.getPqKeypairs().size());
    PqKeypair kp = lw.getPqKeypairs().get(0);
    assertEquals(Hex.toHexString(priv), kp.getPrivateKey());
    assertEquals(Hex.toHexString(ml.getPublicKey()), kp.getPublicKey());
  }

  @Test
  public void mlDsa44KeyWrongLengthRejected() throws IOException {
    String shortKey = Hex.toHexString(filled(MLDSA44.PRIVATE_KEY_LENGTH - 1, (byte) 0x0D));
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", key = \"" + shortKey + "\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("priv-only"));
  }

  @Test
  public void fnDsa512PrivOnlyKeyRejected() throws IOException {
    String privOnly = Hex.toHexString(filled(FNDSA512.PRIVATE_KEY_LENGTH, (byte) 0x0E));
    Path conf = writeConfWithEntry(
        "{ scheme = \"FN_DSA_512\", key = \"" + privOnly + "\" }");

    TronError err = assertThrows(TronError.class,
        () -> Args.setParam(new String[]{"--witness"}, conf.toString()));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("extended priv‖pub"));
    assertTrue(err.getMessage(), !err.getMessage().contains("priv-only"));
  }

  @Test
  public void mlDsa44KeyEntryStillAccepted() throws IOException {
    // Regression: adding the `seed` path must not break the existing `key`
    // path for the same scheme.
    MLDSA44 ml = new MLDSA44(filled(MLDSA44.SEED_LENGTH, (byte) 0x0B));
    byte[] ext = concat(ml.getPrivateKey(), ml.getPublicKey());
    Path conf = writeConfWithEntry(
        "{ scheme = \"ML_DSA_44\", key = \"" + Hex.toHexString(ext) + "\" }");

    Args.setParam(new String[]{"--witness"}, conf.toString());
    LocalWitnesses lw = Args.getLocalWitnesses();
    assertNotNull(lw);
    assertEquals(1, lw.getPqKeypairs().size());
    assertEquals(PQScheme.ML_DSA_44, lw.getPqKeypairs().get(0).getScheme());
  }

  private Path writeConfWithEntry(String entry) throws IOException {
    Path conf = tmp.newFile("pqc-args-test.conf").toPath();
    String body = "include classpath(\"" + TestConstants.TEST_CONF + "\")\n"
        + "localwitness = []\n"
        + "localwitness_pq = {\n"
        + "  keys = [\n"
        + "    " + entry + "\n"
        + "  ]\n"
        + "}\n";
    Files.write(conf, body.getBytes(StandardCharsets.UTF_8));
    return conf;
  }

  private static byte[] filled(int len, byte value) {
    byte[] out = new byte[len];
    Arrays.fill(out, value);
    return out;
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }
}
