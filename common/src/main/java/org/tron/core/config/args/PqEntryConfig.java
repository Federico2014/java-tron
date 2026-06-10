package org.tron.core.config.args;

import lombok.Getter;

/**
 * Raw HOCON shape of a single {@code localwitness_pq.keys[i]} entry.
 * Carries the unparsed string fields so module {@code common} stays free
 * of any crypto-module dependency; scheme-registry lookups and key/seed
 * decoding live in {@link Args#buildPqWitnesses}.
 */
@Getter
public class PqEntryConfig {

  private final int index;
  private final String scheme;
  private final String key;
  private final String seed;

  public PqEntryConfig(int index, String scheme, String key, String seed) {
    this.index = index;
    this.scheme = scheme;
    this.key = key;
    this.seed = seed;
  }

  public boolean hasKey() {
    return key != null;
  }

  public boolean hasSeed() {
    return seed != null;
  }
}
