package org.tron.core.db;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import lombok.Getter;
import org.tron.core.capsule.BlockCapsule;

/** The distinction between applying a block and only retaining an unverified branch. */
@Getter
public class BlockPushResult {

  public enum Status {
    APPLIED, DEFERRED, ALREADY_KNOWN, IGNORED
  }

  private final Status status;
  private final List<BlockCapsule> validatedBlocks;

  private BlockPushResult(Status status, List<BlockCapsule> validatedBlocks) {
    this.status = status;
    this.validatedBlocks = Collections.unmodifiableList(new ArrayList<>(validatedBlocks));
  }

  public static BlockPushResult applied(List<BlockCapsule> blocks) {
    return new BlockPushResult(Status.APPLIED, blocks);
  }

  public static BlockPushResult alreadyKnown(BlockCapsule block) {
    return new BlockPushResult(Status.ALREADY_KNOWN, Collections.singletonList(block));
  }

  public static BlockPushResult of(Status status) {
    return new BlockPushResult(status, Collections.emptyList());
  }
}
