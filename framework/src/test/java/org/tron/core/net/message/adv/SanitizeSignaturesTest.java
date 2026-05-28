package org.tron.core.net.message.adv;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.util.Arrays;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import org.tron.common.overlay.message.Message;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.BlockHeader;
import org.tron.protos.Protocol.Transaction;

/**
 * Verifies that {@link TransactionCapsule#sanitizeSignatures()},
 * {@link TransactionsMessage#sanitizeSignature()} and
 * {@link BlockCapsule#sanitizeSignatures()} truncate any signature longer than 68
 * bytes to exactly 68 bytes while leaving in-range signatures (and the
 * transaction / block id) untouched.
 */
public class SanitizeSignaturesTest {

  @BeforeClass
  public static void setUp() {
    // BlockMessage(byte[]) calls Message.isFilter() which dereferences the
    // static DynamicPropertiesStore. The mock's primitive-long getter returns
    // 0L by default, so isFilter() returns false.
    Message.setDynamicPropertiesStore(Mockito.mock(DynamicPropertiesStore.class));
  }

  private static BlockHeader.raw sampleRawHeader() {
    return BlockHeader.raw.newBuilder()
        .setNumber(100)
        .setTimestamp(123456789L)
        .build();
  }

  private static Block sampleBlock(ByteString witnessSignature) {
    return Block.newBuilder()
        .setBlockHeader(BlockHeader.newBuilder()
            .setRawData(sampleRawHeader())
            .setWitnessSignature(witnessSignature)
            .build())
        .build();
  }

  private static Transaction sampleTransaction() {
    return Transaction.newBuilder()
        .setRawData(Transaction.raw.newBuilder().setTimestamp(123456789L).build())
        .build();
  }

  // ---- TransactionCapsule.sanitizeSignatures ----

  @Test
  public void truncatesOversizedSignatureTo68Bytes() {
    byte[] sigBytes = new byte[200];
    Arrays.fill(sigBytes, (byte) 0x7f);
    Transaction padded = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(sigBytes))
        .build();
    TransactionCapsule capsule = new TransactionCapsule(padded);

    assertTrue("sanitizeSignatures() should report it mutated the capsule",
        capsule.sanitizeSignatures());
    assertEquals(68, capsule.getInstance().getSignature(0).size());
    assertArrayEquals("First 68 bytes must be preserved",
        Arrays.copyOf(sigBytes, 68),
        capsule.getInstance().getSignature(0).toByteArray());
  }

  @Test
  public void leavesSixtyFiveByteSignatureUnchanged() {
    Transaction trx = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .build();
    TransactionCapsule capsule = new TransactionCapsule(trx);
    Transaction before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
  }

  @Test
  public void leavesSixtyEightByteSignatureUnchanged() {
    Transaction trx = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[68]))
        .build();
    TransactionCapsule capsule = new TransactionCapsule(trx);
    Transaction before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
  }

  @Test
  public void leavesUndersizedSignatureUnchanged() {
    Transaction trx = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[64]))
        .build();
    TransactionCapsule capsule = new TransactionCapsule(trx);
    Transaction before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
    assertEquals(64, capsule.getInstance().getSignature(0).size());
  }

  @Test
  public void truncatesOnlyOversizedSignaturesInMixedList() {
    Transaction trx = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .addSignature(ByteString.copyFrom(new byte[100]))
        .addSignature(ByteString.copyFrom(new byte[68]))
        .build();
    TransactionCapsule capsule = new TransactionCapsule(trx);

    assertTrue(capsule.sanitizeSignatures());
    assertEquals(65, capsule.getInstance().getSignature(0).size());
    assertEquals(68, capsule.getInstance().getSignature(1).size());
    assertEquals(68, capsule.getInstance().getSignature(2).size());
  }

  @Test
  public void preservesTransactionId() {
    Transaction clean = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .build();
    Transaction padded = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[200]))
        .build();
    TransactionCapsule cleanCapsule = new TransactionCapsule(clean);
    TransactionCapsule paddedCapsule = new TransactionCapsule(padded);

    paddedCapsule.sanitizeSignatures();

    assertEquals("Truncating signatures must not change the transaction id",
        cleanCapsule.getTransactionId(), paddedCapsule.getTransactionId());
  }

  // ---- TransactionsMessage.sanitizeSignature ----

  @Test
  public void messageSanitizeRewritesAffectedTransactionAndWireBytes() {
    Transaction oversized = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[200]))
        .build();
    TransactionsMessage msg = new TransactionsMessage(Arrays.asList(oversized));
    byte[] before = msg.getData();

    assertTrue(msg.sanitizeSignature());
    assertEquals(68, msg.getTransactions().getTransactions(0).getSignature(0).size());
    assertTrue("Wire data should shrink after truncating",
        msg.getData().length < before.length);
    assertArrayEquals(msg.getTransactions().toByteArray(), msg.getData());
  }

  @Test
  public void messageSanitizeIsNoOpWhenAllSignaturesInRange() {
    Transaction inRange = sampleTransaction().toBuilder()
        .addSignature(ByteString.copyFrom(new byte[65]))
        .build();
    TransactionsMessage msg = new TransactionsMessage(Arrays.asList(inRange));
    byte[] before = msg.getData();

    assertFalse(msg.sanitizeSignature());
    assertSame(before, msg.getData());
  }

  // ---- BlockCapsule.sanitizeSignatures ----

  @Test
  public void blockCapsuleTruncatesOversizedWitnessSignatureTo68Bytes() {
    byte[] sigBytes = new byte[200];
    Arrays.fill(sigBytes, (byte) 0x7f);
    Block padded = sampleBlock(ByteString.copyFrom(sigBytes));
    BlockCapsule capsule = new BlockCapsule(padded);

    assertTrue("sanitizeSignatures() should report it mutated the capsule",
        capsule.sanitizeSignatures());
    assertEquals(68,
        capsule.getInstance().getBlockHeader().getWitnessSignature().size());
    assertArrayEquals("First 68 bytes must be preserved",
        Arrays.copyOf(sigBytes, 68),
        capsule.getInstance().getBlockHeader().getWitnessSignature().toByteArray());
  }

  @Test
  public void blockCapsuleLeavesSixtyFiveByteWitnessSignatureUnchanged() {
    Block clean = sampleBlock(ByteString.copyFrom(new byte[65]));
    BlockCapsule capsule = new BlockCapsule(clean);
    Block before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
  }

  @Test
  public void blockCapsuleLeavesSixtyEightByteWitnessSignatureUnchanged() {
    Block clean = sampleBlock(ByteString.copyFrom(new byte[68]));
    BlockCapsule capsule = new BlockCapsule(clean);
    Block before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
  }

  @Test
  public void blockCapsuleLeavesUndersizedWitnessSignatureUnchanged() {
    Block clean = sampleBlock(ByteString.copyFrom(new byte[64]));
    BlockCapsule capsule = new BlockCapsule(clean);
    Block before = capsule.getInstance();

    assertFalse(capsule.sanitizeSignatures());
    assertSame(before, capsule.getInstance());
    assertEquals(64,
        capsule.getInstance().getBlockHeader().getWitnessSignature().size());
  }

  @Test
  public void blockCapsulePreservesBlockId() {
    Block clean = sampleBlock(ByteString.copyFrom(new byte[65]));
    Block padded = sampleBlock(ByteString.copyFrom(new byte[200]));
    BlockCapsule cleanCapsule = new BlockCapsule(clean);
    BlockCapsule paddedCapsule = new BlockCapsule(padded);

    paddedCapsule.sanitizeSignatures();

    assertEquals("Truncating witness signature must not change the block id",
        cleanCapsule.getBlockId(), paddedCapsule.getBlockId());
  }

  // ---- BlockMessage.sanitize for oversized witness signature ----

  @Test
  public void blockMessageSanitizeRewritesOversizedWitnessSignatureAndWireBytes()
      throws Exception {
    Block padded = sampleBlock(ByteString.copyFrom(new byte[200]));
    byte[] paddedBytes = padded.toByteArray();
    BlockMessage msg = new BlockMessage(paddedBytes);

    msg.sanitize();

    assertEquals(68,
        msg.getBlockCapsule().getInstance().getBlockHeader().getWitnessSignature().size());
    assertTrue("Wire data should shrink after truncating",
        msg.getData().length < paddedBytes.length);
    assertArrayEquals("msg.data should equal capsule.getData() after sanitize",
        msg.getBlockCapsule().getData(), msg.getData());
  }

  @Test
  public void blockMessageSanitizeIsNoOpWhenWitnessSignatureInRange() throws Exception {
    byte[] cleanBytes = sampleBlock(ByteString.copyFrom(new byte[65])).toByteArray();
    BlockMessage msg = new BlockMessage(cleanBytes);
    byte[] before = msg.getData();

    msg.sanitize();

    assertSame("msg.data should not be rewritten on the no-op path",
        before, msg.getData());
  }
}
