package org.tron.core.db;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.tron.common.BaseMethodTest;
import org.tron.common.crypto.ECKey;
import org.tron.common.crypto.ECKey.ECDSASignature;
import org.tron.common.es.ExecutorServiceManager;
import org.tron.common.utils.ReflectUtils;
import org.tron.common.utils.Sha256Hash;
import org.tron.consensus.base.Param;
import org.tron.consensus.dpos.DposSlot;
import org.tron.core.capsule.AccountCapsule;
import org.tron.core.capsule.BlockCapsule;
import org.tron.core.capsule.BlockCapsule.BlockId;
import org.tron.core.capsule.ProposalCapsule;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.consensus.ConsensusService;
import org.tron.core.exception.P2pException;
import org.tron.core.net.TronNetDelegate;
import org.tron.core.net.message.adv.BlockMessage;
import org.tron.core.net.messagehandler.BlockMsgHandler;
import org.tron.core.net.messagehandler.PbftDataSyncHandler;
import org.tron.core.net.peer.Item;
import org.tron.core.net.peer.PeerConnection;
import org.tron.core.net.service.adv.AdvService;
import org.tron.core.net.service.sync.SyncService;
import org.tron.core.services.WitnessProductBlockService;
import org.tron.p2p.connection.Channel;
import org.tron.protos.Protocol.Account;
import org.tron.protos.Protocol.Inventory.InventoryType;
import org.tron.protos.Protocol.Permission;
import org.tron.protos.Protocol.ReasonCode;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.AccountContract.AccountPermissionUpdateContract;

/** Real ingress, revoking stores and DPoS execution; only forwarding and peer I/O are mocked. */
public class BlockWitnessParentStateTest extends BaseMethodTest {

  private final ECKey oldKey = ECKey.fromPrivate(BigInteger.TEN);
  private final ECKey newKey = ECKey.fromPrivate(BigInteger.valueOf(11));
  private final List<ByteString> witnesses = new ArrayList<>();
  private TronNetDelegate delegate;
  private BlockMsgHandler handler;
  private SyncService sync;
  private PeerConnection peer;
  private AdvService adv;
  private DposSlot slots;
  private BlockCapsule commonParent;
  private long time;

  @Override
  protected String[] extraArgs() {
    return new String[]{"--debug"};
  }

  @Override
  protected void afterInit() {
    context.getBean(ConsensusService.class).start();
    slots = context.getBean(DposSlot.class);
    time = System.currentTimeMillis() / 3000 * 3000 - 120_000;
    dbManager.getDynamicPropertiesStore().saveAllowMultiSign(1);
    dbManager.getDynamicPropertiesStore().saveAllowStrictEcdsaValidation(0);
    dbManager.getDynamicPropertiesStore().saveTotalSignNum(5);
    dbManager.getDynamicPropertiesStore().saveNextMaintenanceTime(time + 86_400_000);
    chainBaseManager.getWitnesses().clear();
    for (WitnessCapsule witness : chainBaseManager.getWitnessStore().getAllWitnesses()) {
      chainBaseManager.getWitnessStore().delete(witness.getAddress().toByteArray());
    }
    for (int i = 2; i < 5; i++) {
      ByteString address = ByteString.copyFrom(
          ECKey.fromPrivate(BigInteger.valueOf(i)).getAddress());
      witnesses.add(address);
      AccountCapsule account = new AccountCapsule(Account.newBuilder().setAddress(address)
          .setBalance(1_000_000_000_000L).setIsWitness(true).build());
      account.updatePermissions(AccountCapsule.createDefaultOwnerPermission(keyAddress(oldKey)),
          AccountCapsule.createDefaultWitnessPermission(keyAddress(oldKey)),
          Collections.singletonList(AccountCapsule.createDefaultActivePermission(keyAddress(oldKey),
              dbManager.getDynamicPropertiesStore())));
      dbManager.getAccountStore().put(address.toByteArray(), account);
      WitnessCapsule witness = new WitnessCapsule(address);
      witness.setVoteCount(100 + i);
      witness.setIsJobs(true);
      chainBaseManager.getWitnessStore().put(address.toByteArray(), witness);
      chainBaseManager.addWitness(address);
    }
    Collections.reverse(witnesses); // Match the vote order used by real maintenance.
    chainBaseManager.getWitnessScheduleStore().saveActiveWitnesses(witnesses);
    try {
      commonParent = emptyBlock(chainBaseManager.getGenesisBlockId(), 1, time, oldKey);
      assertEquals(BlockPushResult.Status.APPLIED, dbManager.pushBlock(commonParent).getStatus());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }

    peer = spy(new PeerConnection());
    Channel channel = mock(Channel.class);
    InetSocketAddress socket = new InetSocketAddress("127.0.0.8", 18888);
    when(channel.getInetAddress()).thenReturn(socket.getAddress());
    when(channel.getInetSocketAddress()).thenReturn(socket);
    peer.setChannel(channel);
    delegate = spy(context.getBean(TronNetDelegate.class));
    doReturn(Collections.singletonList(peer)).when(delegate).getActivePeer();
    ReflectUtils.setFieldValue(delegate, "backupServerStartFlag", true);
    handler = context.getBean(BlockMsgHandler.class);
    sync = context.getBean(SyncService.class);
    adv = mock(AdvService.class);
    ReflectUtils.setFieldValue(handler, "tronNetDelegate", delegate);
    ReflectUtils.setFieldValue(handler, "advService", adv);
    ReflectUtils.setFieldValue(handler, "fastForward", false);
    ReflectUtils.setFieldValue(handler, "witnessProductBlockService",
        mock(WitnessProductBlockService.class));
    ReflectUtils.setFieldValue(sync, "tronNetDelegate", delegate);
    ReflectUtils.setFieldValue(sync, "pbftDataSyncHandler", mock(PbftDataSyncHandler.class));
  }

  @Test
  public void broadcastRejectsOldKeyAndAcceptsNewKeyAfterParentExecutes() throws Exception {
    BlockCapsule parent = rotationParent(witnessAt(time + 6000));
    BlockCapsule staleChild = emptyBlock(parent.getBlockId(), 3, time + 6000, oldKey);
    assertTrue(staleChild.validateSignature(dbManager.getDynamicPropertiesStore(),
        dbManager.getAccountStore()));
    assertTrue(delegate.validBlock(staleChild));
    broadcast(parent);
    assertArrayEquals(newKey.getAddress(), dbManager.getAccountStore()
        .get(staleChild.getWitnessAddress().toByteArray()).getWitnessPermissionAddress());

    P2pException error = assertThrows(P2pException.class, () -> broadcast(staleChild));
    assertEquals(P2pException.TypeEnum.BLOCK_SIGN_INVALID, error.getType());
    assertEquals(parent.getBlockId(), delegate.getHeadBlockId());
    assertFalse(chainBaseManager.getBlockStore().has(staleChild.getBlockId().getBytes()));
    verify(adv, never()).broadcast(new BlockMessage(staleChild));

    // Same raw block id, different witness signature: a rejection must not poison the id cache.
    BlockCapsule validChild = emptyBlock(parent.getBlockId(), 3, time + 6000, newKey);
    assertEquals(staleChild.getBlockId(), validChild.getBlockId());
    broadcast(validChild);
    assertEquals(validChild.getBlockId(), delegate.getHeadBlockId());
  }

  @Test
  public void concurrentBroadcastCannotReusePermissionFromBeforeParentExecution() throws Exception {
    BlockCapsule parent = rotationParent(witnessAt(time + 6000));
    BlockCapsule child = emptyBlock(parent.getBlockId(), 3, time + 6000, oldKey);
    P2pException error = precheckThenApplyParent(parent, child);
    assertEquals(P2pException.TypeEnum.BLOCK_SIGN_INVALID, error.getType());
    assertEquals(parent.getBlockId(), delegate.getHeadBlockId());
    assertFalse(chainBaseManager.getBlockStore().has(child.getBlockId().getBytes()));
    verify(adv, never()).broadcast(any());
  }

  private P2pException precheckThenApplyParent(BlockCapsule parent, BlockCapsule child)
      throws Exception {
    assertTrue(child.validateSignature(dbManager.getDynamicPropertiesStore(),
        dbManager.getAccountStore()));
    CountDownLatch prechecked = new CountDownLatch(1);
    CountDownLatch parentApplied = new CountDownLatch(1);
    doAnswer(invocation -> {
      boolean result = (boolean) invocation.callRealMethod();
      prechecked.countDown();
      assertTrue(parentApplied.await(10, TimeUnit.SECONDS));
      return result;
    }).when(delegate).validBlock(any(BlockCapsule.class));
    ExecutorService executor = ExecutorServiceManager.newFixedThreadPool("witness-parent-race", 1);
    try {
      Future<P2pException> result;
      synchronized (dbManager) {
        result = executor.submit(() -> {
          try {
            broadcast(child);
            return null;
          } catch (P2pException e) {
            return e;
          }
        });
        try {
          assertTrue(prechecked.await(10, TimeUnit.SECONDS));
          dbManager.pushBlock(parent);
        } finally {
          parentApplied.countDown();
        }
      }
      return result.get(10, TimeUnit.SECONDS);
    } finally {
      ExecutorServiceManager.shutdownAndAwaitTermination(executor, "witness-parent-race");
    }
  }

  @Test
  public void knownIdRebroadcastUsesStoredSignatureInsteadOfIncomingVariant() throws Exception {
    BlockCapsule valid = emptyBlock(commonParent.getBlockId(), 2, time + 3000, oldKey);
    ByteString signature = valid.getInstance().getBlockHeader().getWitnessSignature();
    BlockCapsule historical = new BlockCapsule(valid.getInstance().toBuilder().setBlockHeader(
        valid.getInstance().getBlockHeader().toBuilder().setWitnessSignature(
            signature.concat(ByteString.copyFrom(new byte[3])))).build());
    dbManager.pushBlock(historical);
    BlockCapsule invalid = new BlockCapsule(valid.getInstance().toBuilder().setBlockHeader(
        valid.getInstance().getBlockHeader().toBuilder()
            .setWitnessSignature(ByteString.copyFrom(new byte[65]))).build());
    broadcast(invalid);
    ArgumentCaptor<BlockMessage> forwarded = ArgumentCaptor.forClass(BlockMessage.class);
    verify(adv).broadcast(forwarded.capture());
    for (BlockMessage message : forwarded.getAllValues()) {
      assertArrayEquals(valid.getData(), message.getData());
    }
  }

  @Test
  public void synchronizationUsesExecutedParentPermission() throws Exception {
    BlockCapsule parent = rotationParent(witnessAt(time + 6000));
    synchronize(parent);
    BlockCapsule child = emptyBlock(parent.getBlockId(), 3, time + 6000, newKey);
    synchronize(child);
    assertEquals(child.getBlockId(), delegate.getHeadBlockId());
    verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
    assertTrue(peer.getSyncBlockToFetch().isEmpty());
  }

  @Test
  public void broadcastDefersCompetingBranchAndValidatesAfterRollback() throws Exception {
    competingBranch(false, false);
  }

  @Test
  public void synchronizationDefersCompetingBranchAndValidatesAfterRollback() throws Exception {
    competingBranch(true, false);
  }

  @Test
  public void invalidForkRestoresHeadAndDoesNotBlameChildProvider() throws Exception {
    competingBranch(false, true);
  }

  private void competingBranch(boolean synchronization, boolean invalidAncestor) throws Exception {
    // A rotates its own producer's key. B1 has the same producer but no rotation transaction.
    BlockCapsule a = rotationParent(witnessAt(time + 3000));
    broadcast(a);
    BlockCapsule b1 = emptyBlock(commonParent.getBlockId(), 2, time + 3000,
        invalidAncestor ? newKey : oldKey);
    if (!invalidAncestor) {
      assertFalse(b1.validateSignature(dbManager.getDynamicPropertiesStore(),
          dbManager.getAccountStore()));
    }
    if (synchronization) {
      synchronize(b1);
    } else {
      broadcast(b1);
    }
    assertEquals(a.getBlockId(), delegate.getHeadBlockId());
    assertFalse(chainBaseManager.getBlockStore().has(b1.getBlockId().getBytes()));
    verify(adv, never()).broadcast(new BlockMessage(b1));
    verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);

    BlockCapsule b2 = emptyBlock(b1.getBlockId(), 3, time + 6000, oldKey);
    if (synchronization) {
      synchronize(b2);
    } else {
      broadcast(b2);
    }
    verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
    if (invalidAncestor) {
      assertEquals(a.getBlockId(), delegate.getHeadBlockId());
      assertFalse(chainBaseManager.getBlockStore().has(b1.getBlockId().getBytes()));
      assertFalse(chainBaseManager.getBlockStore().has(b2.getBlockId().getBytes()));
      assertArrayEquals(newKey.getAddress(), dbManager.getAccountStore()
          .get(a.getWitnessAddress().toByteArray()).getWitnessPermissionAddress());
      BlockCapsule repaired = emptyBlock(commonParent.getBlockId(), 2, time + 3000, oldKey);
      assertEquals(b1.getBlockId(), repaired.getBlockId());
      broadcast(repaired);
      broadcast(b2);
      assertEquals(b2.getBlockId(), delegate.getHeadBlockId());
      verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
    } else {
      assertEquals(b2.getBlockId(), delegate.getHeadBlockId());
      assertArrayEquals(oldKey.getAddress(), dbManager.getAccountStore()
          .get(a.getWitnessAddress().toByteArray()).getWitnessPermissionAddress());
      assertTrue(chainBaseManager.getBlockStore().has(b1.getBlockId().getBytes()));
    }
  }

  @Test
  public void maintenanceActivationRejectsLegacyOnlyChildOnBothIngressPaths() throws Exception {
    // s=e and R=G make Q=r^-1(sR-eG) the point at infinity, under exactly 65 bytes.
    for (ByteString witness : witnesses) {
      setWitnessKey(witness, infinityAddress());
    }
    long maintenanceTime = time + 3000;
    ProposalCapsule proposal = new ProposalCapsule(witnesses.get(0), 1);
    proposal.setParameters(Collections.singletonMap(100L, 1L));
    proposal.setExpirationTime(maintenanceTime);
    witnesses.forEach(proposal::addApproval);
    dbManager.getProposalStore().put(proposal.createDbKey(), proposal);
    dbManager.getDynamicPropertiesStore().saveLatestProposalNum(1);
    dbManager.getDynamicPropertiesStore().saveNextMaintenanceTime(maintenanceTime);
    BlockCapsule parent = infinityBlock(commonParent.getBlockId(), 2, maintenanceTime);
    assertTrue(parent.validateSignature(dbManager.getDynamicPropertiesStore(),
        dbManager.getAccountStore()));
    long childTime = maintenanceTime + 9000;
    BlockCapsule child = infinityBlock(parent.getBlockId(), 3, childTime, witnessAt(time + 6000));
    assertTrue(child.validateSignature(dbManager.getDynamicPropertiesStore(),
        dbManager.getAccountStore()));
    P2pException error = precheckThenApplyParent(parent, child);
    assertTrue(dbManager.getDynamicPropertiesStore().allowStrictEcdsaValidation());
    assertEquals(slots.getTime(1), childTime); // Real maintenance skip slots, not adjacent slots.
    assertEquals(P2pException.TypeEnum.BLOCK_SIGN_INVALID, error.getType());
    synchronize(child);
    verify(peer).disconnect(ReasonCode.BAD_BLOCK);
    assertEquals(parent.getBlockId(), delegate.getHeadBlockId());
    assertFalse(chainBaseManager.getBlockStore().has(child.getBlockId().getBytes()));
  }

  @Test
  public void strictLocalHeadDoesNotRejectLegacyCompetingBranchOnBroadcast() throws Exception {
    activationFork(false, false);
  }

  @Test
  public void strictLocalHeadDoesNotRejectLegacyCompetingBranchOnSync() throws Exception {
    activationFork(true, false);
  }

  @Test
  public void legacyLocalHeadDoesNotAcceptStrictInvalidCompetingChild() throws Exception {
    activationFork(false, true);
  }

  @Test
  public void syncRejectsStrictInvalidChildEvenWhenLocalHeadIsLegacy() throws Exception {
    activationFork(true, true);
  }

  private void activationFork(boolean synchronization, boolean invalidChild) throws Exception {
    for (ByteString witness : witnesses) {
      setWitnessKey(witness, infinityAddress());
    }
    long maintenanceTime = time + 6000;
    ProposalCapsule proposal = new ProposalCapsule(witnesses.get(0), 1);
    proposal.setParameters(Collections.singletonMap(100L, 1L));
    proposal.setExpirationTime(maintenanceTime);
    witnesses.forEach(proposal::addApproval);
    dbManager.getProposalStore().put(proposal.createDbKey(), proposal);
    dbManager.getDynamicPropertiesStore().saveLatestProposalNum(1);
    dbManager.getDynamicPropertiesStore().saveNextMaintenanceTime(maintenanceTime);
    BlockCapsule a = infinityBlock(commonParent.getBlockId(), 2,
        invalidChild ? time + 3000 : maintenanceTime);
    BlockCapsule b1 = infinityBlock(commonParent.getBlockId(), 2,
        invalidChild ? maintenanceTime : time + 3000);
    BlockCapsule b2 = invalidChild
        ? infinityBlock(b1.getBlockId(), 3, time + 15000, witnessAt(time + 9000))
        : infinityBlock(b1.getBlockId(), 3, maintenanceTime);
    broadcast(a);
    assertEquals(!invalidChild, dbManager.getDynamicPropertiesStore().allowStrictEcdsaValidation());
    if (synchronization) {
      synchronize(b1);
      synchronize(b2);
    } else {
      broadcast(b1);
      if (invalidChild) {
        P2pException error = assertThrows(P2pException.class, () -> broadcast(b2));
        assertEquals(P2pException.TypeEnum.BLOCK_SIGN_INVALID, error.getType());
      } else {
        broadcast(b2);
      }
    }
    assertEquals(invalidChild ? a.getBlockId() : b2.getBlockId(), delegate.getHeadBlockId());
    assertEquals(!invalidChild, dbManager.getDynamicPropertiesStore().allowStrictEcdsaValidation());
    if (invalidChild && synchronization) {
      verify(peer).disconnect(ReasonCode.BAD_BLOCK);
    } else {
      verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
    }
  }

  @Test
  public void pendingPermissionIsRemovedBeforeAuthoritativeValidation() throws Exception {
    ByteString witness = witnessAt(time + 3000);
    assertTrue(dbManager.pushTransaction(rotationTransaction(witness)));
    assertArrayEquals(newKey.getAddress(), dbManager.getAccountStore()
        .get(witness.toByteArray()).getWitnessPermissionAddress());
    BlockCapsule child = emptyBlock(commonParent.getBlockId(), 2, time + 3000, oldKey);
    broadcast(child);
    assertEquals(child.getBlockId(), delegate.getHeadBlockId());
    assertArrayEquals(oldKey.getAddress(), dbManager.getAccountStore()
        .get(witness.toByteArray()).getWitnessPermissionAddress());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void deferredBlocksExpireWithoutBecomingVerified() throws Exception {
    BlockCapsule a = rotationParent(witnessAt(time + 3000));
    broadcast(a);
    BlockCapsule b = emptyBlock(commonParent.getBlockId(), 2, time + 3000, oldKey);
    assertEquals(BlockPushResult.Status.DEFERRED, delegate.processBlock(b, false).getStatus());
    Map<BlockId, Long> pending = (Map<BlockId, Long>)
        ReflectUtils.getFieldObject(dbManager, "deferredBlocks");
    pending.put(b.getBlockId(), 0L);
    dbManager.pushBlock(a); // Even a duplicate arrival triggers expiry under the Manager lock.
    assertFalse(context.getBean(KhaosDatabase.class).containBlock(b.getBlockId()));
    assertTrue(pending.isEmpty());
  }

  @Test
  public void deferredCapacityRestartsSyncWithoutBlamingProvider() throws Exception {
    BlockCapsule a = rotationParent(witnessAt(time + 3000));
    broadcast(a);
    for (int i = 0; i < 128; i++) {
      BlockCapsule candidate = emptyBlock(commonParent.getBlockId(), 2, time + 3000 + i, oldKey);
      assertEquals(BlockPushResult.Status.DEFERRED,
          delegate.processBlock(candidate, false).getStatus());
    }
    BlockCapsule overCapacity = emptyBlock(commonParent.getBlockId(), 2, time + 4500, oldKey);
    broadcast(overCapacity);
    Map<?, ?> pending = (Map<?, ?>) ReflectUtils.getFieldObject(dbManager, "deferredBlocks");
    assertTrue(pending.isEmpty());
    assertEquals(a.getBlockId(), delegate.getHeadBlockId());
    verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
  }

  @Test
  public void replacingDeferredSignaturePreservesExistingChildLinks() throws Exception {
    BlockCapsule a = rotationParent(witnessAt(time + 3000));
    BlockCapsule invalid = emptyBlock(commonParent.getBlockId(), 2, time + 3000, newKey);
    BlockCapsule b1 = emptyBlock(commonParent.getBlockId(), 2, time + 3000, oldKey);
    broadcast(a);
    BlockCapsule a2 = emptyBlock(a.getBlockId(), 3, time + 6000, oldKey);
    BlockCapsule b2 = emptyBlock(b1.getBlockId(), 3, time + 6000, oldKey);
    broadcast(a2);
    broadcast(invalid);
    broadcast(b2);
    broadcast(b1);
    assertEquals(a2.getBlockId(), delegate.getHeadBlockId());
    BlockCapsule b3 = emptyBlock(b2.getBlockId(), 4, time + 9000, oldKey);
    broadcast(b3);
    assertEquals(b3.getBlockId(), delegate.getHeadBlockId());
    verify(peer, never()).disconnect(ReasonCode.BAD_BLOCK);
  }

  private BlockCapsule rotationParent(ByteString target) throws Exception {
    assertTrue(dbManager.pushTransaction(rotationTransaction(target)));
    ByteString producer = witnessAt(time + 3000);
    Param.Miner miner = Param.getInstance().new Miner(oldKey.getPrivKeyBytes(),
        keyAddress(oldKey), producer);
    BlockCapsule generated = dbManager.generateBlock(miner, time + 3000,
        System.currentTimeMillis() + 10_000);
    assertEquals(1, generated.getTransactions().size());
    return new BlockCapsule(generated.getInstance()); // External blocks cannot inherit local trust.
  }

  private TransactionCapsule rotationTransaction(ByteString target) throws Exception {
    AccountPermissionUpdateContract contract = AccountPermissionUpdateContract.newBuilder()
        .setOwnerAddress(target)
        .setOwner(AccountCapsule.createDefaultOwnerPermission(keyAddress(oldKey)))
        .setWitness(AccountCapsule.createDefaultWitnessPermission(keyAddress(newKey)))
        .addActives(AccountCapsule.createDefaultActivePermission(keyAddress(oldKey),
            dbManager.getDynamicPropertiesStore())).build();
    TransactionCapsule transaction = new TransactionCapsule(contract,
        ContractType.AccountPermissionUpdateContract);
    transaction.setReference(commonParent.getNum(), commonParent.getBlockId().getBytes());
    transaction.setTimestamp(time);
    transaction.setExpiration(time + 600_000);
    transaction.sign(oldKey.getPrivKeyBytes());
    return transaction;
  }

  private void broadcast(BlockCapsule block) throws Exception {
    BlockMessage message = new BlockMessage(block.getInstance().toByteArray());
    peer.getAdvInvRequest().put(new Item(message.getBlockId(), InventoryType.BLOCK), 0L);
    handler.processMessage(peer, message);
  }

  private void synchronize(BlockCapsule block) throws Exception {
    BlockMessage message = new BlockMessage(block.getInstance().toByteArray());
    peer.getSyncBlockToFetch().add(message.getBlockId());
    peer.getSyncBlockRequested().put(message.getBlockId(), 0L);
    handler.processMessage(peer, message);
    Method handle = SyncService.class.getDeclaredMethod("handleSyncBlock");
    handle.setAccessible(true);
    handle.invoke(sync);
  }

  private ByteString witnessAt(long timestamp) {
    return slots.getScheduledWitness(slots.getSlot(timestamp));
  }

  private BlockCapsule emptyBlock(BlockId parent, long number, long timestamp, ECKey key) {
    BlockCapsule block = new BlockCapsule(number, parent, timestamp, witnessAt(timestamp));
    block.setMerkleRoot();
    block.sign(key.getPrivKeyBytes());
    return block;
  }

  private BlockCapsule infinityBlock(BlockId parent, long number, long timestamp) {
    return infinityBlock(parent, number, timestamp, witnessAt(timestamp));
  }

  private BlockCapsule infinityBlock(BlockId parent, long number, long timestamp,
      ByteString witness) {
    BlockCapsule block = new BlockCapsule(number, parent, timestamp, witness);
    block.setMerkleRoot();
    byte[] hash = Sha256Hash.of(block.getInstance().getBlockHeader().getRawData()
        .toByteArray()).getBytes();
    ECDSASignature signature = new ECDSASignature(
        ECKey.CURVE.getG().getAffineXCoord().toBigInteger(), new BigInteger(1, hash));
    signature.v = 27;
    return new BlockCapsule(block.getInstance().toBuilder().setBlockHeader(
        block.getInstance().getBlockHeader().toBuilder()
            .setWitnessSignature(ByteString.copyFrom(signature.toByteArray()))).build());
  }

  private ByteString infinityAddress() {
    byte[] hash = new byte[32];
    hash[31] = 1;
    ECDSASignature signature = new ECDSASignature(
        ECKey.CURVE.getG().getAffineXCoord().toBigInteger(), BigInteger.ONE);
    return ByteString.copyFrom(ECKey.recoverAddressFromSignature(0, signature, hash));
  }

  private void setWitnessKey(ByteString address, ByteString key) {
    AccountCapsule account = dbManager.getAccountStore().get(address.toByteArray());
    Permission permission = AccountCapsule.createDefaultWitnessPermission(key);
    account.updatePermissions(account.getInstance().getOwnerPermission(), permission,
        account.getInstance().getActivePermissionList());
    dbManager.getAccountStore().put(address.toByteArray(), account);
  }

  private ByteString keyAddress(ECKey key) {
    return ByteString.copyFrom(key.getAddress());
  }
}
