package org.tron.core.net.messagehandler;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collections;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.tron.common.crypto.ECKey;
import org.tron.common.overlay.message.Message;
import org.tron.common.utils.ReflectUtils;
import org.tron.common.utils.Sha256Hash;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.BlockCapsule.BlockId;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.exception.P2pException;
import org.tron.core.exception.P2pException.TypeEnum;
import org.tron.core.net.TronNetDelegate;
import org.tron.core.net.message.MessageTypes;
import org.tron.core.net.message.TronMessageFactory;
import org.tron.core.net.message.adv.BlockMessage;
import org.tron.core.net.peer.Item;
import org.tron.core.net.peer.PeerConnection;
import org.tron.core.net.service.adv.AdvService;
import org.tron.core.net.service.fetchblock.FetchBlockService;
import org.tron.core.net.service.relay.RelayService;
import org.tron.core.net.service.sync.SyncService;
import org.tron.core.services.WitnessProductBlockService;
import org.tron.core.store.AccountStore;
import org.tron.core.store.DynamicPropertiesStore;
import org.tron.p2p.connection.Channel;
import org.tron.protos.Protocol.Inventory.InventoryType;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.ShieldContract.ReceiveDescription;
import org.tron.protos.contract.ShieldContract.ShieldedTransferContract;

public class BlockMerkleMutationTest {

  @Test
  public void testSameIdMutationAndGenuineBlockRetry() throws Exception {
    Transaction left = transaction("merkle-85411");
    Assert.assertEquals(0x12, new TransactionCapsule(left).getMerkleHash().getBytes()[0]);
    Assert.assertEquals(0x3e, new TransactionCapsule(left).getMerkleHash().getBytes()[1]);
    Transaction right = transaction("right");
    ByteString foldedBytes = new TransactionCapsule(left).getMerkleHash().getByteString()
        .concat(new TransactionCapsule(right).getMerkleHash().getByteString());
    Transaction folded = Transaction.parseFrom(foldedBytes);
    Assert.assertEquals(foldedBytes, folded.toByteString());

    BlockCapsule genuine = block(transaction("first"), transaction("second"), left, right);
    BlockCapsule mutated = new BlockCapsule(genuine.getInstance().toBuilder()
        .clearTransactions().addTransactions(transaction("first"))
        .addTransactions(transaction("second")).addTransactions(folded).build());
    genuine.validateMerkleRoot();
    mutated.validateMerkleRoot();
    Assert.assertEquals(genuine.getBlockId(), mutated.getBlockId());
    Assert.assertEquals(genuine.getMerkleRoot(), mutated.calcMerkleRoot());
    Assert.assertEquals(genuine.getInstance().getBlockHeader(),
        mutated.getInstance().getBlockHeader());
    Assert.assertTrue(mutated.validateSignature(Mockito.mock(DynamicPropertiesStore.class),
        Mockito.mock(AccountStore.class)));

    TronNetDelegate delegate = delegate();
    AdvService adv = new AdvService();
    ReflectUtils.setFieldValue(adv, "tronNetDelegate", delegate);
    SyncService sync = Mockito.mock(SyncService.class);
    FetchBlockService fetch = Mockito.mock(FetchBlockService.class);
    RelayService relay = Mockito.mock(RelayService.class);
    BlockMsgHandler handler = handler(delegate, adv, sync, fetch, relay, false);
    Item item = new Item(genuine.getBlockId(), InventoryType.BLOCK);
    PeerConnection attacker = peer();
    attacker.getAdvInvRequest().put(item, 0L);
    try {
      Assert.assertTrue(adv.addInv(item));
      reject(handler, attacker, new BlockMessage(mutated));
      Assert.assertTrue(attacker.getAdvInvRequest().containsKey(item));
      Assert.assertNull(adv.getMessage(item));
      Mockito.verify(delegate, Mockito.never()).validBlock(any(BlockCapsule.class));
      Mockito.verify(delegate, Mockito.never())
          .processBlock(any(BlockCapsule.class), anyBoolean());
      Mockito.verifyNoInteractions(sync, fetch, relay);

      // Model the existing disconnect callback: the same ID must remain fetchable.
      adv.onDisconnect(attacker);
      Assert.assertTrue(adv.addInv(item));
      PeerConnection honest = peer();
      honest.getAdvInvRequest().put(item, 0L);
      handler.processMessage(honest, new BlockMessage(genuine));
      Mockito.verify(delegate).processBlock(genuine, false);
      Mockito.verify(fetch).blockFetchSuccess(genuine.getBlockId());
      Assert.assertTrue(honest.getAdvInvRequest().isEmpty());
      Assert.assertArrayEquals(genuine.getData(), adv.getMessage(item).getData());
    } finally {
      adv.close();
    }
  }

  @Test
  public void testRejectsMutationOnAllIngressModes() throws Exception {
    Transaction folded = Transaction.newBuilder().addSignature(ByteString.copyFrom(new byte[62]))
        .build();
    BlockMessage message = new BlockMessage(block(folded));
    for (boolean syncRequest : new boolean[]{false, true}) {
      for (boolean fastForward : new boolean[]{false, true}) {
        for (boolean relayPeer : new boolean[]{false, true}) {
          TronNetDelegate delegate = delegate();
          AdvService adv = Mockito.mock(AdvService.class);
          SyncService sync = Mockito.mock(SyncService.class);
          FetchBlockService fetch = Mockito.mock(FetchBlockService.class);
          RelayService relay = Mockito.mock(RelayService.class);
          BlockMsgHandler handler = handler(delegate, adv, sync, fetch, relay, fastForward);
          PeerConnection sender = peer();
          sender.setRelayPeer(relayPeer);
          Item item = new Item(message.getBlockId(), InventoryType.BLOCK);
          if (syncRequest) {
            sender.getSyncBlockRequested().put(message.getBlockId(), 0L);
          } else {
            sender.getAdvInvRequest().put(item, 0L);
          }

          reject(handler, sender, message);

          Assert.assertEquals(syncRequest,
              sender.getSyncBlockRequested().containsKey(message.getBlockId()));
          Assert.assertEquals(!syncRequest, sender.getAdvInvRequest().containsKey(item));
          Assert.assertTrue(sender.getSyncBlockInProcess().isEmpty());
          Assert.assertNull(sender.getAdvInvSpread().getIfPresent(item));
          Mockito.verifyNoInteractions(delegate, adv, sync, fetch, relay);
        }
      }
    }
  }

  @Test
  public void testRejects64BytesWithContractOrUnknownFields() throws Exception {
    Transaction withContract = Transaction.newBuilder().setRawData(Transaction.raw.newBuilder()
        .setData(ByteString.copyFrom(new byte[56]))
        .addContract(Contract.newBuilder().setType(ContractType.TransferContract))).build();
    Transaction withUnknownFields = Transaction.newBuilder().setUnknownFields(
        UnknownFieldSet.newBuilder().addField(100, UnknownFieldSet.Field.newBuilder()
            .addLengthDelimited(ByteString.copyFrom(new byte[61])).build()).build()).build();
    for (Transaction transaction : Arrays.asList(withContract, withUnknownFields)) {
      Assert.assertEquals(64, transaction.getSerializedSize());
      assertRejected(transaction);
    }
  }

  @Test
  public void testRejectsNonCanonicalEncodingOf64ByteTransaction() throws Exception {
    Transaction folded = Transaction.newBuilder().addSignature(ByteString.copyFrom(new byte[62]))
        .build();
    // Encode the signature length using a non-minimal varint: 0xbe 0x00 instead of 0x3e.
    // Merkle hashing uses the parsed transaction's canonical serialization, not its wire length.
    byte[] encoded = folded.toByteArray();
    encoded[1] = (byte) 0xbe;
    byte[] padded = new byte[encoded.length + 1];
    padded[0] = encoded[0];
    padded[1] = encoded[1];
    padded[2] = 0;
    System.arraycopy(encoded, 2, padded, 3, encoded.length - 2);
    Transaction parsed = Transaction.parseFrom(padded);
    Assert.assertEquals(65, padded.length);
    Assert.assertEquals(folded, parsed);
    Assert.assertEquals(64, parsed.getSerializedSize());

    ByteArrayOutputStream wire = new ByteArrayOutputStream();
    wire.write(MessageTypes.BLOCK.asByte());
    wire.write(0x0a); // Block.transactions, length-delimited.
    wire.write(padded.length);
    wire.write(padded);
    wire.write(block().getData()); // Preserve a well-formed block header.
    try (MockedStatic<Message> filter = Mockito.mockStatic(Message.class,
        Mockito.CALLS_REAL_METHODS)) {
      filter.when(Message::isFilter).thenReturn(false);
      BlockMessage message = (BlockMessage) TronMessageFactory.create(wire.toByteArray());
      Assert.assertEquals(64, message.getBlockCapsule().getInstance()
          .getTransactions(0).getSerializedSize());
      TronNetDelegate delegate = delegate();
      AdvService adv = Mockito.mock(AdvService.class);
      SyncService sync = Mockito.mock(SyncService.class);
      FetchBlockService fetch = Mockito.mock(FetchBlockService.class);
      RelayService relay = Mockito.mock(RelayService.class);
      BlockMsgHandler handler = handler(delegate, adv, sync, fetch, relay, false);
      PeerConnection sender = peer();
      sender.getAdvInvRequest().put(new Item(message.getBlockId(), InventoryType.BLOCK), 0L);
      reject(handler, sender, message);
      Mockito.verifyNoInteractions(delegate, adv, sync, fetch, relay);
    }
  }

  @Test
  public void testPreservesEmptySignedAndShieldedBlocks() throws Exception {
    ECKey key = ECKey.fromPrivate(BigInteger.ONE);
    TransferContract transfer = TransferContract.newBuilder()
        .setOwnerAddress(ByteString.copyFrom(key.getAddress()))
        .setToAddress(ByteString.copyFrom(ECKey.fromPrivate(BigInteger.TEN).getAddress()))
        .setAmount(1).build();
    TransactionCapsule signed = new TransactionCapsule(transfer, ContractType.TransferContract);
    signed.sign(key.getPrivKeyBytes());
    ShieldedTransferContract shielded = ShieldedTransferContract.newBuilder()
        .addReceiveDescription(ReceiveDescription.newBuilder()
            .setCEnc(ByteString.copyFrom(new byte[580]))
            .setCOut(ByteString.copyFrom(new byte[80]))).build();
    Transaction unsignedShielded = Transaction.newBuilder().setRawData(Transaction.raw.newBuilder()
        .addContract(Contract.newBuilder().setType(ContractType.ShieldedTransferContract)
            .setParameter(Any.pack(shielded)))).build();
    Assert.assertEquals(0, unsignedShielded.getSignatureCount());
    Assert.assertTrue(unsignedShielded.getSerializedSize() > 64);
    for (BlockCapsule block : Arrays.asList(block(), block(signed.getInstance()),
        block(unsignedShielded))) {
      for (boolean syncRequest : new boolean[]{false, true}) {
        TronNetDelegate delegate = delegate();
        AdvService adv = Mockito.mock(AdvService.class);
        SyncService sync = Mockito.mock(SyncService.class);
        BlockMsgHandler handler = handler(delegate, adv, sync,
            Mockito.mock(FetchBlockService.class), Mockito.mock(RelayService.class), false);
        PeerConnection sender = peer();
        if (syncRequest) {
          sender.getSyncBlockRequested().put(block.getBlockId(), 0L);
        } else {
          sender.getAdvInvRequest().put(new Item(block.getBlockId(), InventoryType.BLOCK), 0L);
        }
        handler.processMessage(sender, new BlockMessage(block));
        if (syncRequest) {
          Mockito.verify(sync).processBlock(Mockito.eq(sender), any(BlockMessage.class));
        } else {
          Mockito.verify(delegate).processBlock(block, false);
          Mockito.verify(adv).broadcast(any(BlockMessage.class));
        }
      }
    }
  }

  private void assertRejected(Transaction transaction) throws Exception {
    TronNetDelegate delegate = delegate();
    AdvService adv = Mockito.mock(AdvService.class);
    SyncService sync = Mockito.mock(SyncService.class);
    FetchBlockService fetch = Mockito.mock(FetchBlockService.class);
    RelayService relay = Mockito.mock(RelayService.class);
    BlockMsgHandler handler = handler(delegate, adv, sync, fetch, relay, false);
    BlockMessage message = new BlockMessage(block(transaction));
    PeerConnection sender = peer();
    sender.getAdvInvRequest().put(new Item(message.getBlockId(), InventoryType.BLOCK), 0L);
    reject(handler, sender, message);
    Mockito.verifyNoInteractions(delegate, adv, sync, fetch, relay);
  }

  private void reject(BlockMsgHandler handler, PeerConnection sender, BlockMessage message)
      throws Exception {
    try {
      handler.processMessage(sender, message);
      Assert.fail("Expected rejection of an ambiguous Merkle leaf");
    } catch (P2pException e) {
      Assert.assertEquals(TypeEnum.BAD_BLOCK, e.getType());
      Assert.assertEquals("64-byte transaction in block", e.getMessage());
    }
  }

  private Transaction transaction(String data) {
    return Transaction.newBuilder().setRawData(Transaction.raw.newBuilder()
        .setData(ByteString.copyFromUtf8(data))
        .addContract(Contract.newBuilder().setType(ContractType.TransferContract)))
        .addSignature(ByteString.copyFrom(new byte[65])).build();
  }

  private BlockCapsule block(Transaction... transactions) {
    ECKey key = ECKey.fromPrivate(BigInteger.TEN);
    BlockCapsule block = new BlockCapsule(1, Sha256Hash.ZERO_HASH, 1234,
        ByteString.copyFrom(key.getAddress()));
    for (Transaction transaction : transactions) {
      block.addTransaction(new TransactionCapsule(transaction));
    }
    block.setMerkleRoot();
    block.sign(key.getPrivKeyBytes());
    return block;
  }

  private TronNetDelegate delegate() throws Exception {
    TronNetDelegate delegate = Mockito.mock(TronNetDelegate.class);
    Mockito.when(delegate.validBlock(any(BlockCapsule.class))).thenReturn(true);
    Mockito.when(delegate.containBlock(any(BlockId.class))).thenReturn(true);
    Mockito.when(delegate.getHeadBlockId()).thenReturn(new BlockId(Sha256Hash.ZERO_HASH, 0));
    Mockito.when(delegate.getActivePeer()).thenReturn(Collections.emptyList());
    return delegate;
  }

  private BlockMsgHandler handler(TronNetDelegate delegate, AdvService adv, SyncService sync,
      FetchBlockService fetch, RelayService relay, boolean fastForward) {
    BlockMsgHandler handler = new BlockMsgHandler();
    ReflectUtils.setFieldValue(handler, "tronNetDelegate", delegate);
    ReflectUtils.setFieldValue(handler, "advService", adv);
    ReflectUtils.setFieldValue(handler, "syncService", sync);
    ReflectUtils.setFieldValue(handler, "fetchBlockService", fetch);
    ReflectUtils.setFieldValue(handler, "relayService", relay);
    ReflectUtils.setFieldValue(handler, "witnessProductBlockService",
        Mockito.mock(WitnessProductBlockService.class));
    ReflectUtils.setFieldValue(handler, "fastForward", fastForward);
    return handler;
  }

  private PeerConnection peer() {
    InetSocketAddress address = new InetSocketAddress("127.0.0.254", 10001);
    Channel channel = Mockito.mock(Channel.class);
    Mockito.when(channel.getInetAddress()).thenReturn(address.getAddress());
    Mockito.when(channel.getInetSocketAddress()).thenReturn(address);
    PeerConnection peer = new PeerConnection();
    ReflectUtils.setFieldValue(peer, "channel", channel);
    return peer;
  }
}
