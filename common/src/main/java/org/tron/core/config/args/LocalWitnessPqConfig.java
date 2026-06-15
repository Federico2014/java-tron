package org.tron.core.config.args;

import com.typesafe.config.Optional;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;

/**
 * Auto-bound shape of the {@code localwitness_pq} section. Bound via
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
   * case. Independent of the ECDSA address so mixed-mode nodes can set either,
   * both, or neither. Validated in {@link Args} / WitnessInitializer.
   */
  @Optional
  private String accountAddress;

  @Optional
  private List<PqEntryConfig> keys = new ArrayList<>();

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
