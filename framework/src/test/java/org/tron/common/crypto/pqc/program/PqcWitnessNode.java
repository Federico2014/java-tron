package org.tron.common.crypto.pqc.program;

import com.google.protobuf.ByteString;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.crypto.pqc.MLDSA44;
import org.tron.common.utils.ByteArray;
import org.tron.core.ChainBaseManager;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.consensus.ConsensusService;
import org.tron.core.db.Manager;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.AccountType;
import org.tron.protos.Protocol.Key;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.Permission.PermissionType;
import org.tron.protos.Protocol.SignatureScheme;

/**
 * Demo witness node with ML-DSA-44 block production.
 *
 * Starts an in-process TRON node configured with a PQC witness keypair and
 * a user account that holds an ML-DSA-44 owner permission — ready to receive
 * transactions from {@link PqcClient}.
 *
 * Keypairs are derived from fixed seeds so PqcClient can derive matching keys
 * without any out-of-band coordination.
 *
 * Usage:
 *   Terminal 1 — start this node:
 *     ./gradlew :framework:run -PmainClass=org.tron.common.crypto.pqc.program.PqcWitnessNode
 *   Terminal 2 — broadcast a PQC transaction:
 *     ./gradlew :framework:run -PmainClass=org.tron.common.crypto.pqc.program.PqcClient
 */
public class PqcWitnessNode {

  /** Fixed seed for the ML-DSA-44 witness keypair (shared with PqcClient for derivation). */
  static final byte[] WITNESS_SEED = filledSeed(0x01);
  /** Fixed seed for the ML-DSA-44 user keypair (shared with PqcClient for derivation). */
  static final byte[] USER_SEED = filledSeed(0x02);

  /** gRPC port the node listens on. */
  static final int GRPC_PORT = 50051;

  /** Full-node HTTP port. */
  static final int HTTP_PORT = 8090;

  /** P2P listen port (shared with PqFullNode so it can dial in as a seed peer). */
  static final int P2P_PORT = 18888;

  /** Fixed on-chain address for the demo user account. */
  static final byte[] USER_ADDR =
      ByteArray.fromHexString("41abd4b9367799eaa3197fecb144eb71de1e049abc");

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive deterministic keypairs ──────────────────────────────────
    MLDSA44 witnessKp = new MLDSA44(WITNESS_SEED);
    MLDSA44 userKp    = new MLDSA44(USER_SEED);

    byte[] witnessPub  = witnessKp.getPublicKey();
    byte[] witnessAddr = MLDSA44.computeAddress(witnessPub);
    byte[] userPub     = userKp.getPublicKey();
    byte[] signerAddr  = MLDSA44.computeAddress(userPub);

    System.out.println("=== PQC Witness Node ===");
    System.out.println("Witness address (ML-DSA-44): " + ByteArray.toHexString(witnessAddr));
    System.out.println("User address:                " + ByteArray.toHexString(USER_ADDR));
    System.out.println("User signer address:         " + ByteArray.toHexString(signerAddr));
    System.out.println("gRPC port:                   " + GRPC_PORT);
    System.out.println("HTTP port:                   " + HTTP_PORT);
    System.out.println("P2P port:                    " + P2P_PORT);

    // ── 2. Configure node ─────────────────────────────────────────────────
    File dbDir = Files.createTempDirectory("pqc-node-").toFile();
    dbDir.deleteOnExit();

    Args.setParam(new String[]{"--output-directory", dbDir.getAbsolutePath(), "-w"},
        "config-test.conf");
    Args.getInstance().setRpcEnable(true);
    Args.getInstance().setFullNodeHttpEnable(true);
    Args.getInstance().setFullNodeHttpPort(HTTP_PORT);
    Args.getInstance().setRpcPort(GRPC_PORT);
    Args.getInstance().setNodeListenPort(P2P_PORT);
    Args.getInstance().setNeedSyncCheck(false);
    Args.getInstance().setMinEffectiveConnection(0);
    Args.getInstance().genesisBlock.setWitnesses(new ArrayList<>());

    // ── 3. Start Spring context ───────────────────────────────────────────
    TronApplicationContext context = new TronApplicationContext(DefaultConfig.class);
    Application app = ApplicationFactory.create(context);
    Manager db = context.getBean(Manager.class);
    ChainBaseManager chain = context.getBean(ChainBaseManager.class);

    // ── 4. Install PQ genesis pre-state (shared with PqFullNode) ─────────
    installPqGenesisState(db, chain, witnessPub, userPub);

    // ── 5. Start consensus (DposTask auto-produces blocks) ───────────────
    context.getBean(ConsensusService.class).start();

    // ── 6. Start gRPC / P2P server ───────────────────────────────────────
    app.startup();

    System.out.println("\nNode is running. Send Ctrl-C to stop.");
    System.out.println("Run PqcClient or PqFullNode in another terminal.\n");

    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      System.out.println("Shutting down...");
      context.close();
      Args.clearParam();
    }));

    Thread.currentThread().join(); // block until Ctrl-C
  }

  /**
   * Apply the PQ-specific pre-state that must exist on every node participating
   * in the demo network. Both PqcWitnessNode and PqFullNode call this so their
   * genesis state matches before the first PQ block is produced / received.
   */
  static void installPqGenesisState(Manager db, ChainBaseManager chain,
      byte[] witnessPub, byte[] userPub) {
    byte[] witnessAddr = MLDSA44.computeAddress(witnessPub);
    ByteString witnessAddrBs = ByteString.copyFrom(witnessAddr);
    byte[] signerAddr = MLDSA44.computeAddress(userPub);
    ByteString signerAddrBs = ByteString.copyFrom(signerAddr);

    // Activate ML-DSA on the local chain params.
    db.getDynamicPropertiesStore().saveAllowMlDsa44(1L);
    db.getDynamicPropertiesStore().saveAllowMultiSign(1L);

    // Witness account with ML-DSA-44 witness permission.
    Permission witnessPerm = Permission.newBuilder()
        .setType(PermissionType.Witness)
        .setId(1).setPermissionName("witness").setThreshold(1)
        .addKeys(Key.newBuilder()
            .setAddress(witnessAddrBs).setWeight(1)
            .setScheme(SignatureScheme.ML_DSA_44)
            .setPublicKey(ByteString.copyFrom(witnessPub)))
        .build();
    db.getAccountStore().put(witnessAddr, new AccountCapsule(Account.newBuilder()
        .setAddress(witnessAddrBs).setType(AccountType.Normal)
        .setBalance(1_000_000_000L).setIsWitness(true)
        .setWitnessPermission(witnessPerm).build()));

    // The witness must be in the witness store BEFORE consensus starts so that
    // DposService.start() includes it in the active-witness schedule.
    chain.getWitnessStore().put(witnessAddr, new WitnessCapsule(witnessAddrBs));
    chain.getWitnessScheduleStore().saveActiveWitnesses(new ArrayList<>());
    chain.addWitness(witnessAddrBs);

    // User account with ML-DSA-44 owner permission.
    Permission userOwnerPerm = Permission.newBuilder()
        .setType(PermissionType.Owner).setPermissionName("owner").setThreshold(1)
        .addKeys(Key.newBuilder()
            .setAddress(signerAddrBs).setWeight(1)
            .setScheme(SignatureScheme.ML_DSA_44)
            .setPublicKey(ByteString.copyFrom(userPub)))
        .build();
    AccountCapsule userCapsule = new AccountCapsule(
        ByteString.copyFrom(USER_ADDR), ByteString.copyFromUtf8("pquser"), AccountType.Normal);
    userCapsule.setBalance(100_000_000L); // 100 TRX
    userCapsule.updatePermissions(userOwnerPerm, null, Collections.emptyList());
    db.getAccountStore().put(USER_ADDR, userCapsule);
  }

  private static byte[] filledSeed(int value) {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) value);
    return seed;
  }
}
