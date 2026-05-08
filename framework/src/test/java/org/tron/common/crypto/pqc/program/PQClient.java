package org.tron.common.crypto.pqc.program;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import org.tron.api.GrpcAPI.EmptyMessage;
import org.tron.api.GrpcAPI.Return;
import org.tron.api.WalletGrpc;
import org.tron.api.WalletGrpc.WalletBlockingStub;
import org.tron.common.crypto.pqc.FNDSA;
import org.tron.common.utils.ByteArray;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.PQAuthSig;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;

/**
 * Demo client that connects to {@link PQWitnessNode} and broadcasts an FN-DSA-512
 * signed transfer transaction.
 *
 * The keypair is derived from the same fixed seed used by PQWitnessNode, so no
 * out-of-band key exchange is needed.
 *
 * Usage:
 *   Terminal 1 — start the witness node first:
 *     ./gradlew :framework:run -PmainClass=org.tron.common.crypto.pqc.program.PQWitnessNode
 *   Terminal 2 — broadcast a PQC transaction:
 *     ./gradlew :framework:run -PmainClass=org.tron.common.crypto.pqc.program.PQClient
 *
 * Optional JVM args:
 *   -Dpqc.host=localhost  (default: localhost)
 *   -Dpqc.port=50051      (default: 50051)
 */
public class PQClient {

  private static final String HOST =
      System.getProperty("pqc.host", "localhost");
  private static final int PORT =
      Integer.parseInt(System.getProperty("pqc.port", "50051"));

  /** Recipient of the demo transfer. */
  private static final byte[] TO_ADDR =
      ByteArray.fromHexString("41f522cc20ca18b636bdd93b4fb15ea84cc2b4e001");

  public static void main(String[] args) throws Exception {
    // Force INFO level: logback-test.xml (on the test classpath) sets root=DEBUG
    // which is far too noisy for a demo run.
    ((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
        .getLogger(ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME))
        .setLevel(ch.qos.logback.classic.Level.INFO);

    // ── 1. Derive user keypair from same fixed seed as PQWitnessNode ─────
    byte[] userSeed = new byte[FNDSA.SEED_LENGTH];
    Arrays.fill(userSeed, (byte) 0x02);
    FNDSA userKp = new FNDSA(userSeed);

    byte[] userPub    = userKp.getPublicKey();
    byte[] userPriv   = userKp.getPrivateKey();
    byte[] signerAddr = FNDSA.computeAddress(userPub);
    byte[] ownerAddr  = PQWitnessNode.USER_ADDR;

    System.out.println("=== PQC Client ===");
    System.out.println("Connecting to " + HOST + ":" + PORT);
    System.out.println("Owner address:  " + ByteArray.toHexString(ownerAddr));
    System.out.println("Signer address: " + ByteArray.toHexString(signerAddr));

    // ── 2. Connect via gRPC ───────────────────────────────────────────────
    ManagedChannel channel = ManagedChannelBuilder
        .forAddress(HOST, PORT)
        .usePlaintext()
        .build();
    WalletBlockingStub stub = WalletGrpc.newBlockingStub(channel)
        .withDeadlineAfter(10, TimeUnit.SECONDS);

    try {
      // ── 3. Fetch reference block for TaPoS ───────────────────────────
      Block head = stub.getNowBlock(EmptyMessage.getDefaultInstance());
      byte[] headerRaw = head.getBlockHeader().getRawData().toByteArray();
      long   refNum    = head.getBlockHeader().getRawData().getNumber();
      byte[] blockHash = sha256(headerRaw);

      System.out.println("Reference block: #" + refNum
          + " hash=" + ByteArray.toHexString(Arrays.copyOfRange(blockHash, 0, 8)) + "...");

      // ── 4. Build the transfer transaction ─────────────────────────────
      Transaction.raw rawData = Transaction.raw.newBuilder()
          .addContract(Transaction.Contract.newBuilder()
              .setType(ContractType.TransferContract)
              .setParameter(Any.pack(TransferContract.newBuilder()
                  .setOwnerAddress(ByteString.copyFrom(ownerAddr))
                  .setToAddress(ByteString.copyFrom(TO_ADDR))
                  .setAmount(1_000_000L)  // 1 TRX
                  .build()))
              .setPermissionId(0))
          // TaPoS fields
          .setRefBlockHash(ByteString.copyFrom(Arrays.copyOfRange(blockHash, 8, 16)))
          .setRefBlockBytes(ByteString.copyFrom(longToBytes(refNum), 6, 2))
          .setExpiration(System.currentTimeMillis() + 60_000L)
          .build();

      Transaction tx = Transaction.newBuilder().setRawData(rawData).build();

      // ── 5. Sign with FN-DSA-512 pq_auth_sig ─────────────────────────────
      byte[] txId   = sha256(rawData.toByteArray());
      byte[] sig    = FNDSA.sign(userPriv, txId);

      // FN_DSA_512 is the launch scheme → leave scheme at proto3 default and
      // let PQSchemeRegistry.resolve() normalize it on the verifier side.
      Transaction signedTx = tx.toBuilder()
          .addPqAuthSig(PQAuthSig.newBuilder()
              .setPublicKey(ByteString.copyFrom(userPub))
              .setSignature(ByteString.copyFrom(sig)))
          .build();

      System.out.println("TX id: " + ByteArray.toHexString(txId));

      // ── 6. Broadcast ──────────────────────────────────────────────────
      Return result = stub.broadcastTransaction(signedTx);
      System.out.println("Broadcast result: " + result.getCode()
          + " — " + result.getMessage().toStringUtf8());

      if (result.getResult()) {
        System.out.println("SUCCESS: PQC-signed transaction accepted by the node.");
      } else {
        System.out.println("REJECTED: " + result.getCode());
      }

    } finally {
      channel.shutdown();
      channel.awaitTermination(5, TimeUnit.SECONDS);
    }
  }

  private static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  private static byte[] longToBytes(long value) {
    return ByteBuffer.allocate(8).putLong(value).array();
  }
}
