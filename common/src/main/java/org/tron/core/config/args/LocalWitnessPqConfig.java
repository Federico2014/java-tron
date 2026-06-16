package org.tron.core.config.args;

import com.typesafe.config.Optional;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.tron.core.exception.TronError;

/**
 * Auto-bound shape of the {@code localPqWitness} section. Bound via
 * {@link com.typesafe.config.ConfigBeanFactory}, which recurses into the
 * {@link PqEntryConfig} list members. All fields are {@link Optional} so the
 * section may appear with no {@code accountAddress} and/or no entries
 * (reference.conf ships an empty key list).
 */
@Getter
@Setter
public class LocalWitnessPqConfig {

  /**
   * Counterpart to {@code localWitnessAccountAddress} for the PQ witness path:
   * overrides the on-chain witness account address for the single-PQ-witness
   * case. Independent of the ECDSA address.
   * Validated in {@link Args} / WitnessInitializer.
   */
  @Optional
  private String accountAddress;

  @Optional
  private List<PqEntryConfig> keys = new ArrayList<>();

  /**
   * Validate the structural shape of the bound entries: every entry must name a
   * {@code scheme} and define exactly one of {@code key} or {@code seed}. Scheme
   * validity and key material (hex length, public-key recovery) are checked later
   * in WitnessInitializer, which has access to the crypto module.
   */
  public void postProcess() {
    for (int i = 0; i < keys.size(); i++) {
      PqEntryConfig entry = keys.get(i);
      if (entry.getScheme() == null) {
        throw witnessError("%s[%d] must define `scheme`", LocalWitnessConfig.PQ_KEYS_PATH, i);
      }
      if (!entry.hasKey() && !entry.hasSeed()) {
        throw witnessError("%s[%d] must define exactly one of `key` or `seed`, but neither is set",
            LocalWitnessConfig.PQ_KEYS_PATH, i);
      }
      if (entry.hasKey() && entry.hasSeed()) {
        throw witnessError("%s[%d] must define exactly one of `key` or `seed`, but both are set",
            LocalWitnessConfig.PQ_KEYS_PATH, i);
      }
    }
  }

  private static TronError witnessError(String format, Object... args) {
    return new TronError(String.format(format, args), TronError.ErrCode.WITNESS_INIT);
  }

  @Getter
  @Setter
  public static class PqEntryConfig {

    @Optional
    private String scheme;
    @Optional
    private String key;
    @Optional
    private String seed;

    public boolean hasKey() {
      return key != null;
    }

    public boolean hasSeed() {
      return seed != null;
    }
  }
}
