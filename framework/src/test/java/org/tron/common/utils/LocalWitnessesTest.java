package org.tron.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import java.util.Collections;
import org.junit.Test;
import org.tron.core.exception.TronError;
import org.tron.protos.Protocol.SignatureScheme;

public class LocalWitnessesTest {

  // 32-byte hex seed (ML-DSA-44 / ML-DSA-65).
  private static final String SEED_32 =
      "0101010101010101010101010101010101010101010101010101010101010101";
  // 48-byte hex seed (FN-DSA / Falcon-512).
  private static final String SEED_48 = SEED_32 + "02020202020202020202020202020202";

  @Test
  public void mlDsa65DefaultAccepts32ByteSeed() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqSeeds(Collections.singletonList(SEED_32));
    assertEquals(SignatureScheme.ML_DSA_65, lw.getPqScheme());
    assertEquals(1, lw.getPqSeeds().size());
  }

  @Test
  public void fnDsaAccepts48ByteSeedWhenSchemeSetFirst() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqScheme(SignatureScheme.FN_DSA);
    lw.setPqSeeds(Collections.singletonList(SEED_48));
    assertEquals(SignatureScheme.FN_DSA, lw.getPqScheme());
    assertEquals(1, lw.getPqSeeds().size());
  }

  @Test
  public void fnDsaRejects32ByteSeed() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqScheme(SignatureScheme.FN_DSA);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqSeeds(Collections.singletonList(SEED_32)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ seed"));
    assertTrue(err.getMessage().contains("96"));
  }

  @Test
  public void mlDsa44Rejects48ByteSeed() {
    LocalWitnesses lw = new LocalWitnesses();
    lw.setPqScheme(SignatureScheme.ML_DSA_44);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqSeeds(Collections.singletonList(SEED_48)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("PQ seed"));
    assertTrue(err.getMessage().contains("64"));
  }

  @Test
  public void nonHexSeedRejected() {
    LocalWitnesses lw = new LocalWitnesses();
    String badSeed = "zz" + SEED_32.substring(2);
    TronError err = assertThrows(TronError.class,
        () -> lw.setPqSeeds(Collections.singletonList(badSeed)));
    assertEquals(TronError.ErrCode.WITNESS_INIT, err.getErrCode());
    assertTrue(err.getMessage().contains("hex"));
  }
}
