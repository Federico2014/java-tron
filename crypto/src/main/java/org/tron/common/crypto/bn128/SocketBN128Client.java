package org.tron.common.crypto.bn128;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ArrayBlockingQueue;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Socket-based implementation of Bn128Service. Connects to a remote BN128 worker server via TCP
 * socket.
 */
public class SocketBN128Client implements BN128Service {

  private ArrayBlockingQueue<SocketChannel> pool;
  private final int port;
  private final int socketTimeout;

  public SocketBN128Client(String host, int port, int poolSize, int socketTimeout) throws Exception {
    this.port = port;
    this.socketTimeout = socketTimeout;
    pool = new ArrayBlockingQueue<>(poolSize);
    for (int i = 0; i < poolSize; i++) {
      SocketChannel ch = SocketChannel.open();
      ch.connect(new InetSocketAddress(host, port));
      pool.add(ch);
    }
  }

  public SocketBN128Client( int poolSize, int port, int socketTimeout) throws Exception {
    this("127.0.0.1", port, poolSize, socketTimeout);
  }

  public SocketBN128Client(int poolSize, int socketTimeout) throws Exception {
    this("127.0.0.1", 9001, poolSize, socketTimeout);
  }

  private Pair<Boolean, byte[]> call(byte opcode, byte[] input) throws Exception {
    SocketChannel ch = pool.take();
    try {
      // Set timeout for socket operations
      ch.socket().setSoTimeout(socketTimeout);

      ByteBuffer req = ByteBuffer.allocate(5 + input.length);
      req.put(opcode);
      req.putInt(input.length);
      req.put(input);
      req.flip();
      ch.write(req);

      ByteBuffer header = ByteBuffer.allocate(5);
      ch.read(header);
      header.flip();
      boolean success = header.get() == 0; // status byte: 0=success
      int len = header.getInt();

      ByteBuffer body = ByteBuffer.allocate(len);
      ch.read(body);
      body.flip();
      byte[] result = new byte[len];
      body.get(result);
      return Pair.of(success, result);
    } catch (java.net.SocketTimeoutException e) {
      throw new RuntimeException("BN128 operation timed out after " + socketTimeout + "ms", e);
    } finally {
      pool.put(ch);
    }
  }

  @Override
  public Pair<Boolean, byte[]> bn128Add(byte[] input) throws Exception {
    return call((byte) 1, input);
  }

  @Override
  public Pair<Boolean, byte[]> bn128Mul(byte[] input) throws Exception {
    return call((byte) 2, input);
  }

  @Override
  public Pair<Boolean, byte[]> bn128Pairing(byte[] input) throws Exception {
    return call((byte) 3, input);
  }

  @Override
  public void close() throws Exception {
    for (SocketChannel ch : pool) {
      try {
        ch.close();
      } catch (Exception e) {
        // Ignore
      }
    }
  }
}
