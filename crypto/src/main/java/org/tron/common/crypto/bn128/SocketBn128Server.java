package org.tron.common.crypto.bn128;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Socket-based BN128 worker server. Listens on TCP port and processes BN128 operations using a
 * thread pool.
 */
public class SocketBn128Server {

  private static final int DEFAULT_PORT = 9001;
  private static final int DEFAULT_QUEUE_SIZE = 1000;

  private final int port;
  private final BlockingQueue<SocketRequest> queue;
  private final ExecutorService workers;
  private volatile boolean running = false;
  private Selector selector;
  private ServerSocketChannel server;

  private static final int MAX_PAYLOAD = 100 * 196;
  private static final int BUFFER_SIZE = 5 + MAX_PAYLOAD;

  public SocketBn128Server() {
    this(DEFAULT_PORT);
  }

  public SocketBn128Server(int port) {
    this.port = port;
    this.queue = new ArrayBlockingQueue<>(DEFAULT_QUEUE_SIZE);
    this.workers = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
  }

  public void start() throws Exception {
    if (running) {
      return;
    }
    running = true;

    startWorkers();

    selector = Selector.open();
    server = ServerSocketChannel.open();
    server.socket().bind(new InetSocketAddress(port));
    server.configureBlocking(false);
    server.register(selector, SelectionKey.OP_ACCEPT);

    System.out.println("BN128 Socket Worker started on port " + port);

    while (running) {
      selector.select();
      Iterator<SelectionKey> it = selector.selectedKeys().iterator();

      while (it.hasNext()) {
        SelectionKey key = it.next();
        it.remove();

        if (key.isAcceptable()) {
          SocketChannel client = server.accept();
          client.configureBlocking(false);
          client.register(selector, SelectionKey.OP_READ,
              ByteBuffer.allocateDirect(BUFFER_SIZE));
        }

        if (key.isReadable()) {
          SocketChannel ch = (SocketChannel) key.channel();
          ByteBuffer buffer = (ByteBuffer) key.attachment();
          int read = ch.read(buffer);
          if (read == -1) {
            ch.close();
            continue;
          }

          if (buffer.position() >= 5) {
            buffer.flip();
            byte opcode = buffer.get();
            int len = buffer.getInt();
            if (buffer.remaining() >= len) {
              byte[] payload = new byte[len];
              buffer.get(payload);
              SocketRequest req = new SocketRequest(ch, opcode, payload);
              if (!queue.offer(req)) {
                ch.close();
              }
              buffer.clear();
            } else {
              buffer.compact();
            }
          }
        }
      }
    }
  }

  public void stop() throws IOException {
    running = false;
    if (server != null) {
      server.close();
    }
    if (selector != null) {
      selector.close();
    }
    workers.shutdown();
  }

  private void startWorkers() {
    for (int i = 0; i < Runtime.getRuntime().availableProcessors(); i++) {
      workers.submit(() -> {
        while (true) {
          try {
            SocketRequest req = queue.take();
            Pair<Boolean, byte[]> resultPair;
            byte[] result;
            byte status = 0;
            switch (req.opcode) {
              case 1:
                resultPair = bn128Add(req.payload);
                result = resultPair != null ? resultPair.getRight() : new byte[]{0};
                status = (resultPair != null && resultPair.getLeft()) ? (byte) 0 : (byte) 1;
                break;
              case 2:
                resultPair = bn128Mul(req.payload);
                result = resultPair != null ? resultPair.getRight() : new byte[]{0};
                status = (resultPair != null && resultPair.getLeft()) ? (byte) 0 : (byte) 1;
                break;
              case 3:
                resultPair = bn128Pairing(req.payload);
                result = resultPair != null ? resultPair.getRight() : new byte[]{0};
                status = (resultPair != null && resultPair.getLeft()) ? (byte) 0 : (byte) 1;
                break;
              default:
                result = new byte[]{0};
                status = 1;
            }
            sendResponse(req.channel, status, result);
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      });
    }
  }

  // BN128 operations using GNark library
  private Pair<Boolean, byte[]> bn128Add(byte[] input) {
    return BN128Executor.add(input);
  }

  private Pair<Boolean, byte[]> bn128Mul(byte[] input) {
    return BN128Executor.mul(input);
  }

  private Pair<Boolean, byte[]> bn128Pairing(byte[] input) {
    return BN128Executor.pairing(input);
  }

  private void sendResponse(SocketChannel ch, byte status, byte[] result) throws IOException {
    ByteBuffer resp = ByteBuffer.allocateDirect(5 + result.length);
    resp.put(status);
    resp.putInt(result.length);
    resp.put(result);
    resp.flip();
    ch.write(resp);
  }

  // Request holder class
  static class SocketRequest {

    SocketChannel channel;
    byte opcode;
    byte[] payload;

    SocketRequest(SocketChannel ch, byte op, byte[] data) {
      channel = ch;
      opcode = op;
      payload = data;
    }
  }

  public static void main(String[] args) throws Exception {
    SocketBn128Server server = new SocketBn128Server();
    server.start();
  }
}
