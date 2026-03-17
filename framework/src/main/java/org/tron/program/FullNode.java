package org.tron.program;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.tron.common.application.Application;
import org.tron.common.application.ApplicationFactory;
import org.tron.common.application.TronApplicationContext;
import org.tron.common.arch.Arch;
import org.tron.common.crypto.bn128.SocketBn128Server;
import org.tron.common.exit.ExitManager;
import org.tron.common.log.LogService;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.prometheus.Metrics;
import org.tron.core.config.DefaultConfig;
import org.tron.core.config.args.Args;
import org.tron.core.exception.TronError;

@Slf4j(topic = "app")
public class FullNode {

  /**
   * Start the FullNode.
   */
  public static void main(String[] args) {
    ExitManager.initExceptionHandler();
    checkJdkVersion();
    Args.setParam(args, "config.conf");
    CommonParameter parameter = Args.getInstance();

    LogService.load(parameter.getLogbackPath());

    if (parameter.isSolidityNode()) {
      SolidityNode.start();
      return;
    }
    if (parameter.isKeystoreFactory()) {
      KeystoreFactory.start();
      return;
    }
    if (parameter.launchBN128Server) {
      logger.info("Starting BN128 Server...");
      int bn128Port = Args.getInstance().getBn128ServerPort();
      logger.info("BN128 Server config: port={}", bn128Port);
      SocketBn128Server server = new SocketBn128Server(bn128Port);
      try {
        server.start();
        logger.info("BN128 Socket Server started successfully");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
          try {
            logger.info("Shutting down BN128 Socket Server...");
            server.stop();
            logger.info("BN128 Socket Server stopped successfully");
          } catch (Exception e) {
            logger.error("Error occurred while stopping BN128 Socket Server", e);
          }
        }));

        Thread.currentThread().join();
      } catch (Exception e) {
        logger.error("Failed to start BN128 Socket Server", e);
        System.exit(1);
      }
      return;
    }

    logger.info("Full node running.");
    if (Args.getInstance().isDebug()) {
      logger.info("in debug mode, it won't check energy time");
    } else {
      logger.info("not in debug mode, it will check energy time");
    }

    // init metrics first
    Metrics.init();

    DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
    beanFactory.setAllowCircularReferences(false);
    TronApplicationContext context =
        new TronApplicationContext(beanFactory);
    context.register(DefaultConfig.class);
    context.refresh();
    Application appT = ApplicationFactory.create(context);
    context.registerShutdownHook();
    appT.startup();
    appT.blockUntilShutdown();
  }

  private static void checkJdkVersion() {
    try {
      Arch.throwIfUnsupportedJavaVersion();
    } catch (UnsupportedOperationException e) {
      System.err.println(e.getMessage());
      throw new TronError(e, TronError.ErrCode.JDK_VERSION);
    }
  }
}
