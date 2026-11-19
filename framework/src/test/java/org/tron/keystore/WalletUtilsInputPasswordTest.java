package org.tron.keystore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.tron.core.exception.TronError;

/**
 * Verifies that {@link WalletUtils#inputPassword()} preserves the full
 * password including internal whitespace on the non-TTY (stdin) path,
 * and that {@link WalletUtils#stripPasswordLine(String)} handles all
 * edge cases correctly.
 *
 * <p>Previously the non-TTY path applied {@code trim() + split("\\s+")[0]}
 * which silently truncated passphrases like "correct horse battery staple"
 * to "correct" when piped via stdin. This test locks in the fix.
 */
public class WalletUtilsInputPasswordTest {

  private InputStream originalIn;

  @Before
  public void saveStdin() {
    originalIn = System.in;
    // Clear the cached Scanner so each test binds to its own System.in
    WalletUtils.resetSharedStdinScanner();
  }

  @After
  public void restoreStdin() {
    System.setIn(originalIn);
    WalletUtils.resetSharedStdinScanner();
  }

  // ---------- inputPassword() behavioral tests ----------

  @Test(timeout = 5000)
  public void testInputPasswordPreservesInternalWhitespace() {
    System.setIn(new ByteArrayInputStream(
        "correct horse battery staple\n".getBytes(StandardCharsets.UTF_8)));

    String pw = WalletUtils.inputPassword();

    assertEquals("Password with internal whitespace must be preserved intact",
        "correct horse battery staple", pw);
  }

  @Test(timeout = 5000)
  public void testInputPasswordPreservesTabs() {
    System.setIn(new ByteArrayInputStream(
        "pass\tw0rd\n".getBytes(StandardCharsets.UTF_8)));

    String pw = WalletUtils.inputPassword();

    assertEquals("Internal tabs must be preserved", "pass\tw0rd", pw);
  }

  @Test(timeout = 5000)
  public void testInputPasswordStripsTrailingCr() {
    // Windows line endings
    System.setIn(new ByteArrayInputStream(
        "password123\r\n".getBytes(StandardCharsets.UTF_8)));

    String pw = WalletUtils.inputPassword();

    assertEquals("Trailing \\r must be stripped", "password123", pw);
  }

  @Test(timeout = 5000)
  public void testInputPasswordStripsBom() {
    System.setIn(new ByteArrayInputStream(
        "\uFEFFpassword123\n".getBytes(StandardCharsets.UTF_8)));

    String pw = WalletUtils.inputPassword();

    assertEquals("UTF-8 BOM must be stripped from the start", "password123", pw);
  }

  @Test(timeout = 5000)
  public void testInputPasswordPreservesLeadingAndTrailingSpaces() {
    // The legacy bug also called trim(); post-fix, spaces at the edges
    // are part of the password. Callers that want to trim should do so
    // themselves with full knowledge.
    System.setIn(new ByteArrayInputStream(
        "  with spaces  \n".getBytes(StandardCharsets.UTF_8)));

    String pw = WalletUtils.inputPassword();

    assertEquals("Leading and trailing spaces are part of the password",
        "  with spaces  ", pw);
  }

  // ---------- encoding validation ----------

  @Test(timeout = 5000)
  public void testInputPasswordPreservesUtf8AcrossReads() {
    String password = "密码测试 é🔑";
    System.setIn(new ByteArrayInputStream(
        (password + "\n" + password + "\n").getBytes(StandardCharsets.UTF_8)));

    assertEquals(password, WalletUtils.inputPassword());
    assertEquals(password, WalletUtils.inputPassword());
  }

  @Test(timeout = 5000)
  public void testInputPasswordRejectsMalformedUtf8() {
    System.setIn(new ByteArrayInputStream(new byte[]{(byte) 0xc3, 0x28, '\n'}));

    TronError error = assertThrows(TronError.class, WalletUtils::inputPassword);
    assertTrue(error.getMessage().contains("UTF-8"));
    assertEquals(TronError.ErrCode.WITNESS_KEYSTORE_LOAD, error.getErrCode());
  }

  @Test(timeout = 5000)
  public void testInputPasswordRejectsPartialLineOnDecoderFailure() {
    // Scanner can buffer a valid prefix before treating a decoder error as EOF.
    byte[] bytes = new byte[9001];
    Arrays.fill(bytes, (byte) 'a');
    bytes[bytes.length - 1] = (byte) 0xc3;
    System.setIn(new ByteArrayInputStream(bytes));

    TronError error = assertThrows(TronError.class, WalletUtils::inputPassword);
    assertTrue(error.getMessage().contains("UTF-8"));
  }

  @Test
  public void testConsolePasswordEncodingValidation() throws Exception {
    char[] unicode = "密码测试 é🔑".toCharArray();
    WalletUtils.validateConsolePassword(unicode, StandardCharsets.UTF_8);
    WalletUtils.validateConsolePassword("ascii password".toCharArray(),
        StandardCharsets.US_ASCII);
    WalletUtils.validateConsolePassword("ascii password".toCharArray(), null);

    assertThrows(IOException.class,
        () -> WalletUtils.validateConsolePassword(unicode, StandardCharsets.US_ASCII));
    assertThrows(IOException.class,
        () -> WalletUtils.validateConsolePassword(unicode, StandardCharsets.ISO_8859_1));
    assertThrows(IOException.class,
        () -> WalletUtils.validateConsolePassword(unicode, null));
    // Even a UTF-8 console may have already replaced malformed input bytes.
    char[] replaced = "pass\uFFFDword".toCharArray(); // U+FFFD: decoder replacement.
    assertThrows(IOException.class,
        () -> WalletUtils.validateConsolePassword(replaced, StandardCharsets.UTF_8));
  }

  @Test
  public void testDecodePasswordRejectsMalformedUtf8() {
    assertThrows(IOException.class, () -> WalletUtils.decodePassword(
        new byte[]{'p', 'a', 's', 's', (byte) 0xc3}));
  }

  @Test
  public void testConsoleReadRejectsAndClearsCorruptedPassword() {
    Console console = mock(Console.class);
    char[] password = "secret\uFFFD".toCharArray(); // U+FFFD: decoder replacement.
    when(console.readPassword("%s", "password: ")).thenReturn(password);

    IOException error = assertThrows(IOException.class,
        () -> WalletUtils.readConsolePassword(console, "password: "));
    assertTrue(error.getMessage().contains("UTF-8"));
    assertArrayEquals(new char[password.length], password);
  }

  @Test
  public void testConsoleReadClearsPasswordWhenOsPropertyDenied() {
    assumeTrue("1.8".equals(System.getProperty("java.specification.version")));
    Console console = mock(Console.class);
    char[] password = "secret password".toCharArray();
    when(console.readPassword("%s", "password: ")).thenReturn(password);
    SecurityException denied = new SecurityException("os.name access denied");
    SecurityManager original = System.getSecurityManager();
    try {
      System.setSecurityManager(new SecurityManager() {
        @Override
        public void checkPermission(Permission permission) {
          // Only deny the property read under test.
        }

        @Override
        public void checkPropertyAccess(String key) {
          if ("os.name".equals(key)) {
            throw denied;
          }
        }
      });

      IOException error = assertThrows(IOException.class,
          () -> WalletUtils.readConsolePassword(console, "password: "));
      assertSame(denied, error.getCause());
      assertArrayEquals(new char[password.length], password);
    } finally {
      System.setSecurityManager(original);
    }
  }

  @Test
  public void testConsoleReadPreservesEof() throws Exception {
    Console console = mock(Console.class);
    assertNull(WalletUtils.readConsolePassword(console, "password: "));
  }

  @Test(timeout = 5000)
  public void testInputPasswordPipedStdinEofThrowsTronError() {
    // Non-TTY branch: Scanner.nextLine() throws NoSuchElementException at
    // EOF; it must be translated into a fail-fast TronError.
    // Console EOF is covered separately using a mocked Console.
    System.setIn(new ByteArrayInputStream(new byte[0]));

    TronError err = assertThrows(TronError.class, WalletUtils::inputPassword);

    assertEquals("Piped stdin EOF must map to the keystore-load error code",
        TronError.ErrCode.WITNESS_KEYSTORE_LOAD, err.getErrCode());
  }

  // Note: the M1 double-read test (inputPassword2Twice) was dropped in
  // the 4.8.3 rebase - upstream #6978 removed inputPassword2Twice()
  // along with its only caller KeystoreFactory.
  // ---------- stripPasswordLine() direct unit tests (M3) ----------

  @Test
  public void testStripPasswordLineNull() {
    assertNull(WalletUtils.stripPasswordLine(null));
  }

  @Test
  public void testStripPasswordLineEmpty() {
    assertEquals("", WalletUtils.stripPasswordLine(""));
  }

  @Test
  public void testStripPasswordLineOnlyBom() {
    assertEquals("", WalletUtils.stripPasswordLine("\uFEFF"));
  }

  @Test
  public void testStripPasswordLineOnlyLineTerminators() {
    assertEquals("", WalletUtils.stripPasswordLine("\r\n\r\n"));
  }

  @Test
  public void testStripPasswordLineBomThenTerminator() {
    assertEquals("", WalletUtils.stripPasswordLine("\uFEFF\r\n"));
  }

  @Test
  public void testStripPasswordLineBomAndInternalWhitespace() {
    assertEquals("with spaces",
        WalletUtils.stripPasswordLine("\uFEFFwith spaces\r\n"));
  }

  @Test
  public void testStripPasswordLineNoChange() {
    assertEquals("password", WalletUtils.stripPasswordLine("password"));
  }

  @Test
  public void testStripPasswordLineTrailingLf() {
    assertEquals("password", WalletUtils.stripPasswordLine("password\n"));
  }

  @Test
  public void testStripPasswordLineTrailingCr() {
    assertEquals("password", WalletUtils.stripPasswordLine("password\r"));
  }

  @Test
  public void testStripPasswordLineMultipleTrailing() {
    assertEquals("password", WalletUtils.stripPasswordLine("password\r\n\r\n"));
  }
}
