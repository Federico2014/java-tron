package org.tron.core.net.message.adv;

import java.util.ArrayList;
import java.util.List;
import org.tron.core.capsule.TransactionCapsule;
import org.tron.core.net.message.MessageTypes;
import org.tron.core.net.message.TronMessage;
import org.tron.protos.Protocol;
import org.tron.protos.Protocol.Transaction;

public class TransactionsMessage extends TronMessage {

  private Protocol.Transactions transactions;

  public TransactionsMessage(List<Transaction> trxs) {
    Protocol.Transactions.Builder builder = Protocol.Transactions.newBuilder();
    trxs.forEach(trx -> builder.addTransactions(trx));
    this.transactions = builder.build();
    this.type = MessageTypes.TRXS.asByte();
    this.data = this.transactions.toByteArray();
  }

  public TransactionsMessage(byte[] data) throws Exception {
    super(data);
    this.type = MessageTypes.TRXS.asByte();
    this.transactions = Protocol.Transactions.parseFrom(getCodedInputStream(data));
    if (isFilter()) {
      compareBytes(data, transactions.toByteArray());
      TransactionCapsule.validContractProto(transactions.getTransactionsList());
    }
  }

  public Protocol.Transactions getTransactions() {
    return transactions;
  }

  public boolean sanitizeSignature() {
    List<Transaction> list = transactions.getTransactionsList();
    boolean changed = false;
    List<Transaction> sanitized = new ArrayList<>(list.size());
    for (Transaction trx : list) {
      TransactionCapsule cap = new TransactionCapsule(trx);
      if (cap.sanitizeSignatures()) {
        changed = true;
        sanitized.add(cap.getInstance());
      } else {
        sanitized.add(trx);
      }
    }
    if (!changed) {
      return false;
    }
    Protocol.Transactions.Builder builder = Protocol.Transactions.newBuilder();
    sanitized.forEach(builder::addTransactions);
    this.transactions = builder.build();
    this.data = this.transactions.toByteArray();
    return true;
  }

  @Override
  public String toString() {
    return new StringBuilder().append(super.toString()).append("trx size: ")
        .append(this.transactions.getTransactionsList().size()).toString();
  }

  @Override
  public Class<?> getAnswerMessage() {
    return null;
  }

}
