package org.tron.keystore;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.tron.common.crypto.SignInterface;
import org.tron.core.exception.CipherException;
import org.tron.core.exception.TronError;

/**
 * Utility functions for working with Wallet files.
 */
@Slf4j(topic = "keystore")
public class WalletUtils {

  private static final ObjectMapper objectMapper = new ObjectMapper();

  private static final Set<PosixFilePermission> OWNER_ONLY =
      Collections.unmodifiableSet(EnumSet.of(
          PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));

  static {
    objectMapper.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static String generateWalletFile(
      String password, SignInterface ecKeyPair, File destinationDirectory, boolean useFullScrypt)
      throws CipherException, IOException {

    WalletFile walletFile;
    if (useFullScrypt) {
      walletFile = Wallet.createStandard(password, ecKeyPair);
    } else {
      walletFile = Wallet.createLight(password, ecKeyPair);
    }

    String fileName = getWalletFileName(walletFile);
    File destination = new File(destinationDirectory, fileName);
    writeWalletFile(walletFile, destination);

    return fileName;
  }

  /**
   * Write a WalletFile to the given destination path with owner-only (0600)
   * permissions, using a temp file + atomic rename.
   *
   * <p>On POSIX filesystems, the temp file is created atomically with 0600
   * permissions via {@link Files#createTempFile(Path, String, String,
   * java.nio.file.attribute.FileAttribute[])}, avoiding any window where the
   * file is world-readable.
   *
   * <p>On non-POSIX filesystems (e.g. Windows) the fallback uses
   * {@link File#setReadable(boolean, boolean)} /
   * {@link File#setWritable(boolean, boolean)} which is best-effort — these
   * methods manipulate only DOS-style attributes on Windows and may not update
   * file ACLs. The sensitive keystore JSON is written only after the narrowing
   * calls, so no confidential data is exposed during the window, but callers
   * on Windows should not infer strict owner-only ACL enforcement from this.
   *
   * @param walletFile  the keystore to serialize
   * @param destination the final target file (existing file will be replaced)
   */
  public static void writeWalletFile(WalletFile walletFile, File destination)
      throws IOException {
    Path dir = destination.getAbsoluteFile().getParentFile().toPath();
    Files.createDirectories(dir);

    Path tmp;
    try {
      tmp = Files.createTempFile(dir, "keystore-", ".tmp",
          PosixFilePermissions.asFileAttribute(OWNER_ONLY));
    } catch (UnsupportedOperationException e) {
      // Windows / non-POSIX fallback — best-effort narrowing only (see JavaDoc)
      tmp = Files.createTempFile(dir, "keystore-", ".tmp");
      File tf = tmp.toFile();
      tf.setReadable(false, false);
      tf.setReadable(true, true);
      tf.setWritable(false, false);
      tf.setWritable(true, true);
    }

    try {
      objectMapper.writeValue(tmp.toFile(), walletFile);
      try {
        Files.move(tmp, destination.toPath(),
            StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE);
      } catch (AtomicMoveNotSupportedException e) {
        Files.move(tmp, destination.toPath(), StandardCopyOption.REPLACE_EXISTING);
      }
    } catch (Exception e) {
      try {
        Files.deleteIfExists(tmp);
      } catch (IOException suppress) {
        e.addSuppressed(suppress);
      }
      throw e;
    }
  }

  public static Credentials loadCredentials(String password, File source)
      throws IOException, CipherException {
    warnIfSymbolicLink(source);
    WalletFile walletFile = objectMapper.readValue(source, WalletFile.class);
    return Credentials.create(Wallet.decrypt(password, walletFile));
  }

  /**
   * Emit a warning if {@code source} is a symbolic link. The keystore is still
   * read (following the symlink), preserving compatibility with legitimate
   * deployments that use symlinks to organize keystore files (e.g.
   * {@code /opt/tron/keystore/witness.json} -> {@code /mnt/encrypted/...},
   * container volume-mount paths). The warning gives operators a chance to
   * notice if a path they did not expect to be a symlink has become one — for
   * example if an attacker with config-injection ability has redirected the
   * SR startup keystore. This mirrors how Ethereum consensus clients (e.g.
   * Lighthouse) handle a configured {@code voting_keystore_path}.
   */
  private static void warnIfSymbolicLink(File source) {
    try {
      BasicFileAttributes attrs = Files.readAttributes(source.toPath(),
          BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (attrs.isSymbolicLink()) {
        logger.warn("Keystore file is a symbolic link: {} — proceeding, "
            + "but verify the symlink target points where you expect.",
            source.getPath());
      }
    } catch (IOException ignored) {
      // If we can't stat, let the subsequent readValue surface the real error.
    }
  }

  public static String getWalletFileName(WalletFile walletFile) {
    DateTimeFormatter format = DateTimeFormatter.ofPattern(
        "'UTC--'yyyy-MM-dd'T'HH-mm-ss.nVV'--'");
    ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);

    return now.format(format) + walletFile.getAddress() + ".json";
  }

  /**
   * Strip trailing line terminators ({@code \n}/{@code \r}) and a leading
   * UTF-8 BOM ({@code \uFEFF}) from a line of input. Unlike
   * {@link String#trim()} this preserves internal whitespace, so passwords
   * containing spaces (e.g. passphrases) survive intact.
   *
   * <p>Intended as the canonical helper for normalizing raw user-provided
   * password/line input across both CLI console and file-driven paths.
   * Returns {@code null} if the input is {@code null}.
   */
  public static String stripPasswordLine(String s) {
    if (s == null) {
      return null;
    }
    if (s.length() > 0 && s.charAt(0) == '\uFEFF') {
      s = s.substring(1);
    }
    int end = s.length();
    while (end > 0) {
      char c = s.charAt(end - 1);
      if (c == '\n' || c == '\r') {
        end--;
      } else {
        break;
      }
    }
    return s.substring(0, end);
  }

  public static boolean passwordValid(String password) {
    if (StringUtils.isEmpty(password)) {
      return false;
    }
    if (password.length() < 6) {
      return false;
    }
    //Other rule;
    return true;
  }

  /**
   * Lazily-initialized Scanner shared across successive
   * {@link #inputPassword()} calls on the non-TTY path. Each call to
   * {@code new Scanner(System.in)} buffers ahead from stdin; constructing
   * a second Scanner after the first has been discarded drops any bytes
   * the first pulled, causing {@code NoSuchElementException}.
   */
  private static Scanner sharedStdinScanner;

  /**
   * Visible for testing: reset the cached Scanner so subsequent calls
   * see a freshly rebound {@link System#in}.
   */
  static synchronized void resetSharedStdinScanner() {
    sharedStdinScanner = null;
  }

  private static synchronized Scanner getSharedStdinScanner() {
    if (sharedStdinScanner == null) {
      // CharsetDecoder defaults to REPORT: never replace malformed password bytes.
      sharedStdinScanner = new Scanner(new InputStreamReader(System.in,
          StandardCharsets.UTF_8.newDecoder()));
    }
    return sharedStdinScanner;
  }

  /**
   * Decode a UTF-8 password file without silently replacing malformed bytes.
   */
  public static String decodePassword(byte[] bytes) throws IOException {
    try {
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
    } catch (CharacterCodingException e) {
      throw new IOException("Password input must be valid UTF-8", e);
    }
  }

  /**
   * Read with echo disabled, rejecting potentially corrupted console input.
   * The caller must clear the returned array; EOF is returned as {@code null}.
   */
  public static char[] readConsolePassword(Console console, String prompt) throws IOException {
    char[] password = console.readPassword("%s", prompt);
    if (password == null) {
      return null;
    }
    try {
      validateConsolePassword(password, consoleCharset(console));
      return password;
    } catch (IOException e) {
      Arrays.fill(password, '\0');
      throw e;
    }
  }

  private static Charset consoleCharset(Console console) throws IOException {
    try {
      // Console.charset() was added in JDK 17; keep the JDK 8 build compatible.
      return (Charset) Console.class.getMethod("charset").invoke(console);
    } catch (NoSuchMethodException e) {
      // On supported JDK 8 Linux/macOS runtimes Console uses the default charset.
      String os = System.getProperty("os.name");
      return "Linux".equals(os) || "Mac OS X".equals(os) ? Charset.defaultCharset() : null;
    } catch (ReflectiveOperationException | SecurityException e) {
      throw new IOException("Cannot determine console encoding; use UTF-8 password input", e);
    }
  }

  static void validateConsolePassword(char[] password, Charset charset) throws IOException {
    for (char c : password) {
      // Console decoders replace malformed bytes; the original input cannot be recovered.
      if (c == '\uFFFD' || (c > 0x7f && !StandardCharsets.UTF_8.equals(charset))) {
        throw new IOException("Password may be corrupted by the console encoding; "
            + "use a UTF-8 terminal or UTF-8 password file/stdin");
      }
    }
  }

  public static String inputPassword() {
    String password;
    Console cons = System.console();
    Scanner in = cons == null ? getSharedStdinScanner() : null;
    while (true) {
      if (cons != null) {
        char[] pwd;
        try {
          pwd = readConsolePassword(cons, "password: ");
        } catch (IOException e) {
          throw new TronError(e.getMessage(), e, TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
        }
        // Console EOF (e.g. Ctrl+D) returns null; fail fast instead of
        // crashing with a raw NullPointerException.
        if (pwd == null) {
          throw new TronError(
              "password input closed (EOF) while reading from the console; "
                  + "restart with --password or provide an interactive TTY",
              TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
        }
        try {
          password = String.valueOf(pwd);
        } finally {
          Arrays.fill(pwd, '\0');
        }
      } else {
        // Preserve the full password including embedded whitespace.
        // The previous implementation applied trim() + split("\\s+")[0]
        // which silently truncated passwords like "correct horse battery
        // staple" to "correct" when piped via stdin (e.g. echo ... | java).
        // stripPasswordLine only removes the UTF-8 BOM and trailing line
        // terminators — internal whitespace is part of the password.
        String line;
        try {
          line = in.nextLine();
        } catch (NoSuchElementException e) {
          if (in.ioException() != null) {
            throw passwordInputError(in.ioException());
          }
          // Piped stdin reached EOF before a password line was available;
          // fail fast instead of leaking a raw NoSuchElementException.
          throw new TronError(
              "password input closed (EOF): piped stdin provided no password "
                  + "line; restart with --password or provide an interactive TTY",
              e, TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
        }
        // Scanner treats reader failures as EOF and can return a partial line.
        if (in.ioException() != null) {
          throw passwordInputError(in.ioException());
        }
        password = stripPasswordLine(line);
      }
      if (passwordValid(password)) {
        return password;
      }
      System.out.println("Invalid password, please input again.");
    }
  }

  private static TronError passwordInputError(IOException cause) {
    return new TronError("Cannot read password input; stdin must contain valid UTF-8", cause,
        TronError.ErrCode.WITNESS_KEYSTORE_LOAD);
  }

}
