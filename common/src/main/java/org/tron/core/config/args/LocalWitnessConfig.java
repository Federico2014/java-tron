package org.tron.core.config.args;

import static org.tron.core.exception.TronError.ErrCode.PARAMETER_INIT;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigBeanFactory;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.tron.core.config.args.LocalWitnessPqConfig.PqEntryConfig;
import org.tron.core.exception.TronError;

/**
 * Local witness configuration bean.
 * Reads top-level config keys: localwitness, localWitnessAccountAddress,
 * localwitnesskeystore, and the localwitness_pq section. These top-level keys
 * are not under a sub-section — they are at the root of config.conf. The
 * localwitness_pq section is auto-bound through
 * {@link com.typesafe.config.ConfigBeanFactory} into {@link LocalWitnessPqConfig}
 * (which carries the PQ witness account address plus the {@link PqEntryConfig}
 * list) instead of being read field-by-field. ECDSA and PQ witness accounts use
 * independent account-address keys (localWitnessAccountAddress vs
 * localwitness_pq.accountAddress) so the two consensus paths do not interfere.
 */
@Slf4j
@Getter
public class LocalWitnessConfig {

  /**
   * Root path of the PQ witness section within config.conf.
   */
  public static final String PQ_SECTION_PATH = "localwitness_pq";

  /**
   * Path of the PQ witness key list; used for entry-level error messages.
   */
  public static final String PQ_KEYS_PATH = "localwitness_pq.keys";

  private List<String> privateKeys = new ArrayList<>();
  private String accountAddress = null;
  private String pqAccountAddress = null;
  private List<String> keystores = new ArrayList<>();
  private List<PqEntryConfig> pqEntries = Collections.emptyList();

  public static LocalWitnessConfig fromConfig(Config config) {
    LocalWitnessConfig lw = new LocalWitnessConfig();
    if (config.hasPath("localwitness")) {
      lw.privateKeys = config.getStringList("localwitness");
    }
    if (config.hasPath("localWitnessAccountAddress")) {
      lw.accountAddress = config.getString("localWitnessAccountAddress");
    }
    if (config.hasPath("localwitnesskeystore")) {
      lw.keystores = config.getStringList("localwitnesskeystore");
    }
    if (config.hasPath(PQ_SECTION_PATH)) {
      LocalWitnessPqConfig pq = ConfigBeanFactory.create(
          config.getConfig(PQ_SECTION_PATH), LocalWitnessPqConfig.class);
      pq.postProcess();
      lw.pqEntries = pq.getKeys();
      lw.pqAccountAddress = pq.getAccountAddress();

      if (StringUtils.isNotEmpty(lw.accountAddress) && StringUtils.isNotEmpty(
          lw.pqAccountAddress)) {
        throw new TronError("localWitnessAccountAddress and localwitness_pq.accountAddress "
            + "should not exist at the same time", PARAMETER_INIT);
      }
    }
    return lw;
  }
}
