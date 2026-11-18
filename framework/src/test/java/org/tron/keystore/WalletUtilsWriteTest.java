package org.tron.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Assume;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.MockedStatic;
import org.tron.common.crypto.SignInterface;
import org.tron.common.crypto.SignUtils;
import org.tron.common.utils.Utils;

/**
 * Verifies that {@link WalletUtils#generateWalletFile} and
 * {@link WalletUtils#writeWalletFile} produce keystore files with
 * owner-only permissions (0600) atomically, leaving no temp files behind.
 *
 * <p>Tests use light scrypt (useFullScrypt=false) where possible because
 * they validate filesystem behavior, not the KDF parameters.
 */
public class WalletUtilsWriteTest {

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  private static WalletFile lightWalletFile(String password) throws Exception {
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());
    return Wallet.createLight(password, keyPair);
  }

  @Test
  public void testGenerateWalletFileCreatesOwnerOnlyFile() throws Exception {
    Assume.assumeTrue("POSIX permissions test",
        !System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));

    File dir = tempFolder.newFolder("gen-perms");
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());

    String fileName = WalletUtils.generateWalletFile("password123", keyPair, dir, false);

    File created = new File(dir, fileName);
    assertTrue(created.exists());

    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(created.toPath());
    assertEquals("Keystore must have owner-only permissions (rw-------)",
        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        perms);
  }

  @Test
  public void testGenerateWalletFileLeavesNoTempFile() throws Exception {
    File dir = tempFolder.newFolder("gen-no-temp");
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());

    WalletUtils.generateWalletFile("password123", keyPair, dir, false);

    File[] tempFiles = dir.listFiles((d, name) -> name.startsWith("keystore-")
        && name.endsWith(".tmp"));
    assertNotNull(tempFiles);
    assertEquals("No temp files should remain after generation", 0, tempFiles.length);
  }

  @Test
  public void testGenerateWalletFileLightScrypt() throws Exception {
    File dir = tempFolder.newFolder("gen-light");
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());

    String fileName = WalletUtils.generateWalletFile("password123", keyPair, dir, false);
    assertNotNull(fileName);
    assertTrue(fileName.endsWith(".json"));
    assertTrue(new File(dir, fileName).exists());
  }

  @Test
  public void testWriteWalletFileOwnerOnly() throws Exception {
    Assume.assumeTrue("POSIX permissions test",
        !System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));

    File dir = tempFolder.newFolder("write-perms");
    WalletFile wf = lightWalletFile("password123");
    File destination = new File(dir, "out.json");

    WalletUtils.writeWalletFile(wf, destination);

    assertTrue(destination.exists());
    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(destination.toPath());
    assertEquals("Keystore must have owner-only permissions (rw-------)",
        EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        perms);
  }

  @Test
  public void testWriteWalletFileReplacesExisting() throws Exception {
    File dir = tempFolder.newFolder("write-replace");
    WalletFile wf1 = lightWalletFile("password123");
    WalletFile wf2 = lightWalletFile("password123");
    File destination = new File(dir, "out.json");

    WalletUtils.writeWalletFile(wf1, destination);
    WalletUtils.writeWalletFile(wf2, destination);

    assertTrue("Destination exists after replace", destination.exists());
    WalletFile reread = new com.fasterxml.jackson.databind.ObjectMapper()
        .readValue(destination, WalletFile.class);
    assertEquals("Replaced file should have wf2's address",
        wf2.getAddress(), reread.getAddress());
  }

  @Test
  public void testWriteWalletFileLeavesNoTempFile() throws Exception {
    File dir = tempFolder.newFolder("write-no-temp");
    WalletFile wf = lightWalletFile("password123");
    File destination = new File(dir, "final.json");

    WalletUtils.writeWalletFile(wf, destination);

    File[] tempFiles = dir.listFiles((d, name) -> name.startsWith("keystore-")
        && name.endsWith(".tmp"));
    assertNotNull(tempFiles);
    assertEquals("No temp files should remain", 0, tempFiles.length);
  }

  @Test
  public void testWriteWalletFileCreatesParentDirectories() throws Exception {
    File base = tempFolder.newFolder("write-nested");
    File destination = new File(base, "a/b/c/out.json");
    assertFalse("Parent dir does not exist yet", destination.getParentFile().exists());

    WalletFile wf = lightWalletFile("password123");
    WalletUtils.writeWalletFile(wf, destination);

    assertTrue("Destination written", destination.exists());
  }

  @Test
  public void testWriteWalletFileCleansUpTempOnFailure() throws Exception {
    // Force failure by making the destination a directory — Files.move will fail
    // because the source is a file. The temp file must be cleaned up.
    File dir = tempFolder.newFolder("write-fail");
    File destinationAsDir = new File(dir, "blocking-dir");
    assertTrue("Setup: blocking dir created", destinationAsDir.mkdir());
    // Put a file inside so Files.move with REPLACE_EXISTING fails (non-empty dir).
    assertTrue("Setup: block file", new File(destinationAsDir, "blocker").createNewFile());

    WalletFile wf = lightWalletFile("password123");

    try {
      WalletUtils.writeWalletFile(wf, destinationAsDir);
      fail("Expected IOException because destination is a non-empty directory");
    } catch (IOException expected) {
      // Expected
    }

    File[] tempFiles = dir.listFiles((d, name) -> name.startsWith("keystore-")
        && name.endsWith(".tmp"));
    assertNotNull(tempFiles);
    assertEquals("Temp file must be cleaned up on failure", 0, tempFiles.length);
  }

  @Test
  public void testFileSyncFailurePreservesExistingKeystore() throws Exception {
    File dir = tempFolder.newFolder("file-sync-fail");
    File destination = new File(dir, "wallet.json");
    WalletFile original = lightWalletFile("password123");
    WalletUtils.writeWalletFile(original, destination);
    byte[] before = Files.readAllBytes(destination.toPath());
    WalletFile replacement = lightWalletFile("newpassword");
    AtomicReference<FileChannel> walletOutput = new AtomicReference<>();

    try (MockedStatic<FileChannel> channels = mockStatic(FileChannel.class, invocation -> {
      FileChannel output = (FileChannel) invocation.callRealMethod();
      if (invocation.getArguments().length == 3
          && ((Set<?>) invocation.getArgument(1)).contains(StandardOpenOption.CREATE_NEW)) {
        output = spy(output);
        doThrow(new IOException("file sync failed")).when(output).force(true);
        walletOutput.set(output);
      }
      return output;
    })) {
      IOException error = assertThrows(IOException.class,
          () -> WalletUtils.writeWalletFile(replacement, destination));
      assertEquals("file sync failed", error.getMessage());
      assertNotNull(walletOutput.get());
      verify(walletOutput.get()).close();
    }
    assertArrayEquals(before, Files.readAllBytes(destination.toPath()));
    assertEquals("Only the original wallet should remain", 1, dir.list().length);
  }

  @Test
  public void testWriteWalletFileDoesNotOpenDirectories() throws Exception {
    File base = tempFolder.newFolder("write-without-directory-reads");
    File destination = new File(base, "a/b/wallet.json");
    WalletFile wallet = lightWalletFile("password123");

    try (MockedStatic<FileChannel> channels = mockStatic(FileChannel.class, invocation -> {
      Path path = invocation.getArgument(0);
      if (Files.isDirectory(path)) {
        throw new IOException("directory reads are unsupported");
      }
      return invocation.callRealMethod();
    })) {
      WalletUtils.writeWalletFile(wallet, destination);
    }
    assertEquals(wallet.getAddress(),
        WalletUtils.loadCredentials("password123", destination).getAddress());
  }

  @Test
  public void testReplacedTemporaryFileDoesNotReceiveWalletBytes() throws Exception {
    assertTemporaryPathReplacementDoesNotReceiveWalletBytes(false);
  }

  @Test
  public void testReplacedTemporarySymlinkDoesNotReceiveWalletBytes() throws Exception {
    assertTemporaryPathReplacementDoesNotReceiveWalletBytes(true);
  }

  private void assertTemporaryPathReplacementDoesNotReceiveWalletBytes(boolean symlink)
      throws Exception {
    File dir = tempFolder.newFolder("replace-temp");
    File destination = new File(dir, "wallet.json");
    Path original = dir.toPath().resolve("original.tmp");
    Path attacker = dir.toPath().resolve("attacker-file");
    byte[] marker = new byte[] {1, 2, 3};
    Files.write(attacker, marker);
    WalletFile wallet = lightWalletFile("password123");

    try (MockedStatic<FileChannel> channels = mockStatic(FileChannel.class, invocation -> {
      FileChannel channel = (FileChannel) invocation.callRealMethod();
      if (invocation.getArguments().length == 3
          && ((Set<?>) invocation.getArgument(1)).contains(StandardOpenOption.CREATE_NEW)) {
        // Replace the directory entry after creation, before serialization starts.
        Path tmp = invocation.getArgument(0);
        Files.move(tmp, original);
        if (symlink) {
          Files.createSymbolicLink(tmp, attacker);
        } else {
          Files.write(tmp, marker);
        }
      }
      return channel;
    })) {
      WalletUtils.writeWalletFile(wallet, destination);
    }
    assertArrayEquals(marker, Files.readAllBytes(attacker));
    assertArrayEquals(marker, Files.readAllBytes(destination.toPath()));
    assertEquals(wallet.getAddress(),
        WalletUtils.loadCredentials("password123", original.toFile()).getAddress());
    assertEquals(EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        Files.getPosixFilePermissions(original));
  }

  @Test
  public void testTemporaryNameCollisionLeavesExistingFileUntouched() throws Exception {
    File dir = tempFolder.newFolder("temp-collision");
    File destination = new File(dir, "wallet.json");
    AtomicReference<Path> existing = new AtomicReference<>();
    byte[] marker = new byte[] {1, 2, 3};
    WalletFile wallet = lightWalletFile("password123");
    try (MockedStatic<FileChannel> channels = mockStatic(FileChannel.class, invocation -> {
      if (invocation.getArguments().length == 3
          && ((Set<?>) invocation.getArgument(1)).contains(StandardOpenOption.CREATE_NEW)) {
        Path path = invocation.getArgument(0);
        Files.write(path, marker);
        existing.set(path);
      }
      return invocation.callRealMethod();
    })) {
      assertThrows(FileAlreadyExistsException.class,
          () -> WalletUtils.writeWalletFile(wallet, destination));
    }
    assertNotNull(existing.get());
    assertArrayEquals(marker, Files.readAllBytes(existing.get()));
    assertFalse(destination.exists());
  }

  @Test
  public void testUnsupportedAtomicPermissionsDoesNotFallBack() throws Exception {
    File dir = tempFolder.newFolder("unsupported-permissions");
    File destination = new File(dir, "wallet.json");
    WalletFile wallet = lightWalletFile("password123");
    try (MockedStatic<FileChannel> channels = mockStatic(FileChannel.class, invocation -> {
      if (invocation.getArguments().length == 3
          && ((Set<?>) invocation.getArgument(1)).contains(StandardOpenOption.CREATE_NEW)) {
        throw new UnsupportedOperationException("Atomic permissions unavailable");
      }
      return invocation.callRealMethod();
    })) {
      assertThrows(UnsupportedOperationException.class,
          () -> WalletUtils.writeWalletFile(wallet, destination));
    }
    assertEquals("No wallet or temporary file should be created", 0, dir.list().length);
  }

  // ---------- loadCredentials symlink behavior ----------

  @Test
  public void testLoadCredentialsFollowsSymlinkButWarns() throws Exception {
    Assume.assumeTrue("Symlinks only tested on POSIX",
        !System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));

    File realDir = tempFolder.newFolder("load-symlink-target");
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());
    String realName = WalletUtils.generateWalletFile("password123", keyPair, realDir, false);
    File realKeystore = new File(realDir, realName);

    File linkDir = tempFolder.newFolder("load-symlink-link");
    File symlink = new File(linkDir, "witness.json");
    Files.createSymbolicLink(symlink.toPath(), realKeystore.toPath());

    // Should NOT throw — Lighthouse-style: follow the symlink, log a warning
    // for the operator. Hard-rejecting would silently break legitimate SR
    // deployments that organize keystores via symlinks.
    Credentials creds =
        WalletUtils.loadCredentials("password123", symlink);
    assertNotNull(creds.getAddress());
  }

  @Test
  public void testLoadCredentialsAcceptsRegularFile() throws Exception {
    File dir = tempFolder.newFolder("load-ok");
    SignInterface keyPair = SignUtils.getGeneratedRandomSign(Utils.getRandom());
    String fileName = WalletUtils.generateWalletFile("password123", keyPair, dir, false);

    Credentials creds =
        WalletUtils.loadCredentials("password123", new File(dir, fileName));
    assertNotNull(creds.getAddress());
  }
}
