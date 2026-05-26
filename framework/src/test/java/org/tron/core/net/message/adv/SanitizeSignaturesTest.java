package org.tron.core.net.message.adv;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.google.protobuf.ByteString;
import java.util.Arrays;
import org.junit.Test;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.protos.Protocol.Transaction;

/**
 * Verifies that {@link TransactionCapsule#sanitizeSignatures()} and
 * {@link TransactionsMessage#sanitizeSignature()} truncate any signature longer than 68
 * bytes to exactly 68 bytes while leaving in-range signatures (and the
 * transaction id) untouched.
 */
public class SanitizeSignaturesTest {

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
}
