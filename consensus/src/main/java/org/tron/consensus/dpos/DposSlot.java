package org.tron.consensus.dpos;


import static org.tron.core.config.Parameter.ChainConstant.BLOCK_PRODUCED_INTERVAL;
import static org.tron.core.config.Parameter.ChainConstant.SINGLE_REPEAT;

import com.google.protobuf.ByteString;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.tron.consensus.ConsensusDelegate;

import java.util.Collections;
import java.util.List;
import java.util.Random;

@Slf4j(topic = "consensus")
@Component
public class DposSlot {

  @Autowired
  private ConsensusDelegate consensusDelegate;

  @Setter
  private DposService dposService;

  public long getAbSlot(long time) {
    return (time - dposService.getGenesisBlockTime()) / BLOCK_PRODUCED_INTERVAL;
  }

  public long getSlot(long time) {
    long firstSlotTime = getTime(1);
    if (time < firstSlotTime) {
      return 0;
    }
    return (time - firstSlotTime) / BLOCK_PRODUCED_INTERVAL + 1;
  }

  public long getTime(long slot) {
    if (slot == 0) {
      return System.currentTimeMillis();
    }
    long interval = BLOCK_PRODUCED_INTERVAL;
    if (consensusDelegate.getLatestBlockHeaderNumber() == 0) {
      return dposService.getGenesisBlockTime() + slot * interval;
    }
    if (consensusDelegate.lastHeadBlockIsMaintenance()) {
      slot += consensusDelegate.getMaintenanceSkipSlots();
    }
    long time = consensusDelegate.getLatestBlockHeaderTimestamp();
    time = time - ((time - dposService.getGenesisBlockTime()) % interval);
    return time + interval * slot;
  }
  //shuffle
  public List<ByteString> getShuffleActiveWitnesses() {
    List<ByteString> activeWitnesses = consensusDelegate.getActiveWitnesses();
    int activeWitnessesSize = activeWitnesses.size();
    long latestBlockNum = consensusDelegate.getLatestBlockHeaderNumber();
    long seed = MaintenanceManager.getMaintenanceBlockTimestamp();
    if(latestBlockNum >= MaintenanceManager.getMaintenanceBlockHeight() + activeWitnessesSize){
      MaintenanceManager.setMaintenanceBlockHeight(consensusDelegate.getLatestBlockHeaderTimestamp());
      MaintenanceManager.setMaintenanceBlockTimestamp(consensusDelegate.getLatestBlockHeaderTimestamp());
      seed = consensusDelegate.getLatestBlockHeaderTimestamp();
    }
    Collections.shuffle(activeWitnesses,new java.util.Random(seed));
    return activeWitnesses;
  }
  public ByteString getScheduledWitness(long slot) {
    final long currentSlot = getAbSlot(consensusDelegate.getLatestBlockHeaderTimestamp()) + slot;
    if (currentSlot < 0) {
      throw new RuntimeException("current slot should be positive.");
    }
    int size = consensusDelegate.getActiveWitnesses().size();
    if (size <= 0) {
      throw new RuntimeException("active witnesses is null.");
    }
    int witnessIndex = (int) currentSlot % (size * SINGLE_REPEAT);
    witnessIndex /= SINGLE_REPEAT;
    return getShuffleActiveWitnesses().get(witnessIndex);
  }
  /*public ByteString getScheduledWitness(long slot) {
    final long currentSlot = getAbSlot(consensusDelegate.getLatestBlockHeaderTimestamp()) + slot;
    if (currentSlot < 0) {
      throw new RuntimeException("current slot should be positive.");
    }
    int size = consensusDelegate.getActiveWitnesses().size();
    if (size <= 0) {
      throw new RuntimeException("active witnesses is null.");
    }
    int witnessIndex = (int) currentSlot % (size * SINGLE_REPEAT);
    witnessIndex /= SINGLE_REPEAT;
    return consensusDelegate.getActiveWitnesses().get(witnessIndex);
  }*/

}
