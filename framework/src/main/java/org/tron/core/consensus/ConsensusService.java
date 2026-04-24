package org.tron.core.consensus;

import static org.tron.common.utils.ByteArray.fromHexString;

import com.google.protobuf.ByteString;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.common.crypto.SignUtils;
import org.tron.common.crypto.pqc.MLDSA65;
import org.tron.common.parameter.CommonParameter;
import org.tron.consensus.Consensus;
import org.tron.consensus.base.Param;
import org.tron.consensus.base.Param.Miner;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.config.args.Args;
import org.tron.core.store.WitnessStore;

@Slf4j(topic = "consensus")
@Component
public class ConsensusService {

  @Autowired
  private Consensus consensus;

  @Autowired
  private WitnessStore witnessStore;

  @Autowired
  private BlockHandleImpl blockHandle;

  @Autowired
  private PbftBaseImpl pbftBaseImpl;

  private CommonParameter parameter = Args.getInstance();

  public void start() {
    Param param = Param.getInstance();
    param.setEnable(parameter.isWitness());
    param.setGenesisBlock(parameter.getGenesisBlock());
    param.setMinParticipationRate(parameter.getMinParticipationRate());
    param.setBlockProduceTimeoutPercent(Args.getInstance().getBlockProducedTimeOut());
    param.setNeedSyncCheck(parameter.isNeedSyncCheck());
    param.setAgreeNodeCount(parameter.getAgreeNodeCount());
    List<Miner> miners = new ArrayList<>();
    List<String> privateKeys = Args.getLocalWitnesses().getPrivateKeys();
    List<String> pqSeeds = Args.getLocalWitnesses().getPqSeeds();
    if (privateKeys.size() > 1) {
      for (String key : privateKeys) {
        byte[] privateKey = fromHexString(key);
        byte[] privateKeyAddress = SignUtils
            .fromPrivate(privateKey, Args.getInstance().isECKeyCryptoEngine()).getAddress();
        WitnessCapsule witnessCapsule = witnessStore.get(privateKeyAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(privateKeyAddress));
        }
        Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
            ByteString.copyFrom(privateKeyAddress));
        miners.add(miner);
        logger.info("Add witness: {}, size: {}",
            Hex.toHexString(privateKeyAddress), miners.size());
      }
    } else if (privateKeys.size() == 1) {
      byte[] privateKey =
          fromHexString(Args.getLocalWitnesses().getPrivateKey());
      byte[] privateKeyAddress = SignUtils.fromPrivate(privateKey,
          Args.getInstance().isECKeyCryptoEngine()).getAddress();
      byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
      WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
      if (null == witnessCapsule) {
        logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
      }
      // In multi-signature mode, the address derived from the private key may differ from
      // witnessAddress.
      Miner miner = param.new Miner(privateKey, ByteString.copyFrom(privateKeyAddress),
          ByteString.copyFrom(witnessAddress));
      miners.add(miner);
    } else if (pqSeeds.size() > 1) {
      for (String seed : pqSeeds) {
        byte[] seedBytes = fromHexString(seed);
        MLDSA65 keypair = new MLDSA65(seedBytes);
        byte[] sk = keypair.getPrivateKey();
        byte[] pk = keypair.getPublicKey();
        byte[] pqAddress = MLDSA65.computeAddress(pk);
        WitnessCapsule witnessCapsule = witnessStore.get(pqAddress);
        if (null == witnessCapsule) {
          logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(pqAddress));
        }
        ByteString pqAddressBs = ByteString.copyFrom(pqAddress);
        Miner miner = param.new Miner(null, pqAddressBs, pqAddressBs);
        miner.setPqPrivateKey(sk);
        miner.setPqPublicKey(pk);
        miners.add(miner);
        logger.info("Add ML-DSA witness (from seed): {}, size: {}",
            Hex.toHexString(pqAddress), miners.size());
      }
    } else if (pqSeeds.size() == 1) {
      miners.add(buildPqOnlyMinerFromSeed(param, pqSeeds.get(0)));
    }

    param.setMiners(miners);
    param.setBlockHandle(blockHandle);
    param.setPbftInterface(pbftBaseImpl);
    consensus.start(param);
    logger.info("consensus service start success");
  }

  private Miner buildPqOnlyMinerFromSeed(Param param, String pqSeed) {
    byte[] seedBytes = fromHexString(pqSeed);
    MLDSA65 keypair = new MLDSA65(seedBytes);
    byte[] sk = keypair.getPrivateKey();
    byte[] pk = keypair.getPublicKey();
    byte[] pqAddress = MLDSA65.computeAddress(pk);
    byte[] witnessAddress = Args.getLocalWitnesses().getWitnessAccountAddress();
    if (witnessAddress == null || witnessAddress.length == 0) {
      witnessAddress = pqAddress;
    }
    WitnessCapsule witnessCapsule = witnessStore.get(witnessAddress);
    if (null == witnessCapsule) {
      logger.warn("Witness {} is not in witnessStore.", Hex.toHexString(witnessAddress));
    }
    // In multi-signature mode, the address derived from the PQ key may differ from witnessAddress.
    Miner miner = param.new Miner(null, ByteString.copyFrom(pqAddress),
        ByteString.copyFrom(witnessAddress));
    miner.setPqPrivateKey(sk);
    miner.setPqPublicKey(pk);
    logger.info("Add ML-DSA witness (from seed): {}", Hex.toHexString(witnessAddress));
    return miner;
  }

  public void stop() {
    logger.info("consensus service closed start.");
    consensus.stop();
    logger.info("consensus service closed successfully.");
  }

}
