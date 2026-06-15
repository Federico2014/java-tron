package org.tron.core.config.args;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import org.junit.Test;
import org.tron.core.config.args.LocalWitnessPqConfig.PqEntryConfig;
import org.tron.core.exception.TronError;

public class LocalWitnessConfigTest {

  private static Config withRef(String hocon) {
    return ConfigFactory.parseString(hocon).withFallback(ConfigFactory.defaultReference());
  }

  private static Config withRef() {
    return ConfigFactory.defaultReference();
  }

  @Test
  public void testDefaults() {
    Config empty = withRef();
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(empty);
    assertTrue(lw.getPrivateKeys().isEmpty());
    assertNull(lw.getAccountAddress());
    assertNull(lw.getPqAccountAddress());
    assertTrue(lw.getKeystores().isEmpty());
    assertTrue(lw.getPqEntries().isEmpty());
  }

  @Test
  public void testWithPqAccountAddress() {
    Config config = withRef("localwitness_pq.accountAddress = \"TPqAddr\"");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertNull(lw.getAccountAddress());
    assertEquals("TPqAddr", lw.getPqAccountAddress());
  }

  @Test
  public void testEcdsaAndPqAccountAddressBothSetRejected() {
    Config config = withRef(
        "localWitnessAccountAddress = \"TEcdsaAddr\"\n"
            + "localwitness_pq.accountAddress = \"TPqAddr\"");
    TronError err = assertThrows(TronError.class,
        () -> LocalWitnessConfig.fromConfig(config));
    assertEquals(TronError.ErrCode.PARAMETER_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("should not exist at the same time"));
  }

  @Test
  public void testWithPrivateKeys() {
    Config config = withRef(
        "localwitness = [\"key1\", \"key2\"]\n"
            + "localWitnessAccountAddress = \"TAddr123\"");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(2, lw.getPrivateKeys().size());
    assertEquals("key1", lw.getPrivateKeys().get(0));
    assertEquals("TAddr123", lw.getAccountAddress());
  }

  @Test
  public void testWithKeystores() {
    Config config = withRef(
        "localwitnesskeystore = [\"/path/to/keystore1\"]");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(1, lw.getKeystores().size());
  }

  @Test
  public void testWithPqEntries() {
    Config config = withRef(
        "localwitness_pq.keys = [\n"
            + "  { scheme = \"FN_DSA_512\", key = \"deadbeef\" },\n"
            + "  { scheme = \"ML_DSA_44\", seed = \"cafebabe\" }\n"
            + "]");
    LocalWitnessConfig lw = LocalWitnessConfig.fromConfig(config);
    assertEquals(2, lw.getPqEntries().size());

    PqEntryConfig first = lw.getPqEntries().get(0);
    assertEquals("FN_DSA_512", first.getScheme());
    assertEquals("deadbeef", first.getKey());
    assertNull(first.getSeed());
    assertTrue(first.hasKey());
    assertFalse(first.hasSeed());

    PqEntryConfig second = lw.getPqEntries().get(1);
    assertEquals("ML_DSA_44", second.getScheme());
    assertNull(second.getKey());
    assertEquals("cafebabe", second.getSeed());
    // Scheme validity and key material (hex length, public-key recovery) are
    // still left to WitnessInitializer; fromConfig only checks entry shape.
  }

  @Test
  public void testPqEntryMissingSchemeRejected() {
    Config config = withRef("localwitness_pq.keys = [ { key = \"deadbeef\" } ]");
    TronError err = assertThrows(TronError.class,
        () -> LocalWitnessConfig.fromConfig(config));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(), err.getMessage().contains("must define `scheme`"));
  }

  @Test
  public void testPqEntryMissingKeyAndSeedRejected() {
    Config config = withRef("localwitness_pq.keys = [ { scheme = \"FN_DSA_512\" } ]");
    TronError err = assertThrows(TronError.class,
        () -> LocalWitnessConfig.fromConfig(config));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("exactly one of `key` or `seed`, but neither is set"));
  }

  @Test
  public void testPqEntryBothKeyAndSeedRejected() {
    Config config = withRef(
        "localwitness_pq.keys = [ { scheme = \"FN_DSA_512\", key = \"de\", seed = \"ad\" } ]");
    TronError err = assertThrows(TronError.class,
        () -> LocalWitnessConfig.fromConfig(config));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage(),
        err.getMessage().contains("exactly one of `key` or `seed`, but both are set"));
  }
}
