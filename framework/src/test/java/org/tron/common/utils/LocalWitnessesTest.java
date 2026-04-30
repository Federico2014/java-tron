package org.tron.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import org.junit.Test;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.PQScheme;

public class LocalWitnessesTest {

  // 48-byte hex seed (FN-DSA-512 / Falcon-512).
  private static final String SEED_48 =
      "010101010101010101010101010101010101010101010101"
          + "020202020202020202020202020202020202020202020202";

  // 32-byte hex seed (wrong size for FN-DSA-512).
  private static final String SEED_32 =
      "0101010101010101010101010101010101010101010101010101010101010101";

  @Test
  public void fnDsa512DefaultAccepts48ByteSeed() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqSeeds(Collections.singletonList(SEED_48));
    assertEquals(PQScheme.FN_DSA_512, lw.getPqScheme());
    assertEquals(1, lw.getPqSeeds().size());
  }

  @Test
  public void fnDsa512Rejects32ByteSeed() {
    LocalWitnesses lw = new LocalWitnesses();
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqSeeds(Collections.singletonList(SEED_32)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ seed"));
    // FN-DSA-512 expects 48 bytes = 96 hex chars.
    assertTrue(err.getMessage().contains("96"));
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
  public void nonHexSeedRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String badSeed = "zz" + SEED_48.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqSeeds(Collections.singletonList(badSeed)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("hex"));
  }
}
