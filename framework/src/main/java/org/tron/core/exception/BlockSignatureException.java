package org.tron.core.exception;

import lombok.Getter;
import org.tron.core.capsule.BlockCapsule.BlockId;

/** Identifies the block whose witness failed authentication, including a fork ancestor. */
@Getter
public class BlockSignatureException extends ValidateSignatureException {

  private final BlockId blockId;

  public BlockSignatureException(BlockId blockId, String message) {
    super("Block " + blockId.getString() + " witness signature invalid: " + message);
    this.blockId = blockId;
  }

  @Override
  protected void report() {
    // Block authentication failures are reported by the network, not as transaction failures.
  }
}
