package org.tron.core.config.args;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import org.junit.Test;
import org.tron.core.Constant;

public class MiscConfigTest {

  private static Config withRef(String hocon) {
    return ConfigFactory.parseString(hocon).withFallback(ConfigFactory.defaultReference());
  }

  private static Config withRef() {
    return ConfigFactory.defaultReference();
  }

  @Test
  public void testDefaults() {
    Config empty = withRef();
    MiscConfig mc = MiscConfig.fromConfig(empty);
    assertTrue(mc.isNeedToUpdateAsset());
    assertFalse(mc.isHistoryBalanceLookup());
    assertEquals("solid", mc.getTrxReferenceBlock());
    assertEquals(Constant.TRANSACTION_DEFAULT_EXPIRATION_TIME,
        mc.getTrxExpirationTimeInMilliseconds());
    // reference.conf has seed.node.ip.list with actual IPs
    assertFalse(mc.getSeedNodeIpList().isEmpty());
  }

  @Test
  public void testFromConfig() {
    Config config = withRef(
        "storage { needToUpdateAsset = false,"
            + " balance { history { lookup = true } } }\n"
            + "trx { reference { block = head } }\n"
            + "seed.node { ip.list = [\"1.2.3.4:18888\"] }");
    MiscConfig mc = MiscConfig.fromConfig(config);
    assertFalse(mc.isNeedToUpdateAsset());
    assertTrue(mc.isHistoryBalanceLookup());
    assertEquals("head", mc.getTrxReferenceBlock());
    assertEquals(1, mc.getSeedNodeIpList().size());
  }

  @Test
  public void shouldAcceptLegacyEckeyCryptoEngine() {
    Config config = withRef("crypto.engine = ECKey");

    MiscConfig.fromConfig(config);
  }

  @Test
  public void shouldRejectLegacySm2CryptoEngine() {
    Config config = withRef("crypto.engine = sm2");

    IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
        () -> MiscConfig.fromConfig(config));

    assertEquals(
        "crypto.engine no longer supports non-ECKey values; remove the setting or use eckey",
        exception.getMessage());
  }
}
