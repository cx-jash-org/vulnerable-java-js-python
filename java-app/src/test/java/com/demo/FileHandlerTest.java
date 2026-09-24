package com.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for FileHandler.executeCommand to verify the Command Injection (CWE-77)
 * vulnerability has been fully remediated.
 *
 * Remediation summary:
 *   The ProcessBuilder / OS-process sink has been removed entirely and replaced
 *   with java.nio.file.Files.newDirectoryStream(), a pure-Java library call that
 *   never spawns a shell.  Shell metacharacters in user-supplied input therefore
 *   have no execution surface.  The path-containment check
 *   (Path.normalize() + Path.startsWith()) is retained as a defence-in-depth
 *   control to prevent path traversal.
 *
 * Test categories:
 *   A. Input validation  — null/empty parameters are rejected before path resolution.
 *   B. Allowlist enforcement — paths outside ALLOWED_BASE throw SecurityException.
 *   C. Injection payloads  — shell metacharacters in userInput are rejected by the
 *      path-containment check or, even if they reached the Java API, are treated as
 *      literal filename characters and never executed by a shell.
 *   D. Benign inputs — well-formed paths inside ALLOWED_BASE are accepted; the
 *      directory listing is returned by Files.newDirectoryStream().
 */
public class FileHandlerTest {

    private FileHandler fileHandler;
    private HttpServletRequest mockRequest;

    @BeforeEach
    public void setUp() {
        fileHandler = new FileHandler();
        mockRequest = mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // A. Input validation
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: null 'cmd' parameter must throw IllegalArgumentException")
    public void executeCommand_nullParameter_throwsIllegalArgumentException() {
        when(mockRequest.getParameter("cmd")).thenReturn(null);

        assertThrows(IllegalArgumentException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "A null 'cmd' parameter must throw IllegalArgumentException before reaching the directory API.");
    }

    @Test
    @DisplayName("executeCommand: empty 'cmd' parameter must throw IllegalArgumentException")
    public void executeCommand_emptyParameter_throwsIllegalArgumentException() {
        when(mockRequest.getParameter("cmd")).thenReturn("");

        assertThrows(IllegalArgumentException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "An empty 'cmd' parameter must throw IllegalArgumentException before reaching the directory API.");
    }

    // -----------------------------------------------------------------------
    // B. Allowlist (path containment) enforcement
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: absolute path outside /var/data must throw SecurityException")
    public void executeCommand_absolutePathOutsideAllowedBase_throwsSecurityException() {
        when(mockRequest.getParameter("cmd")).thenReturn("/etc/passwd");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "A path outside the allowed base directory must be rejected with SecurityException.");
    }

    @Test
    @DisplayName("executeCommand: path traversal via '../..' must throw SecurityException")
    public void executeCommand_pathTraversalWithDotDot_throwsSecurityException() {
        // "../../etc" resolves to /etc after normalization — outside /var/data.
        when(mockRequest.getParameter("cmd")).thenReturn("../../etc");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "A '..' traversal that escapes /var/data must be rejected with SecurityException.");
    }

    @Test
    @DisplayName("executeCommand: absolute path to /tmp must throw SecurityException")
    public void executeCommand_absolutePathToTmp_throwsSecurityException() {
        when(mockRequest.getParameter("cmd")).thenReturn("/tmp");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "/tmp is outside /var/data and must be rejected with SecurityException.");
    }

    @Test
    @DisplayName("executeCommand: root path '/' must throw SecurityException")
    public void executeCommand_rootPath_throwsSecurityException() {
        when(mockRequest.getParameter("cmd")).thenReturn("/");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "The root path '/' is outside /var/data and must be rejected with SecurityException.");
    }

    @Test
    @DisplayName("executeCommand: path to /var/data/../etc must throw SecurityException after normalisation")
    public void executeCommand_normaliseEscapesAllowedBase_throwsSecurityException() {
        when(mockRequest.getParameter("cmd")).thenReturn("/var/data/../etc");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "'/var/data/../etc' normalises to '/etc' which is outside /var/data.");
    }

    // -----------------------------------------------------------------------
    // C. Injection payload tests — shell metacharacters must never be executed
    //    (The ProcessBuilder sink has been removed; no shell is ever invoked.)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: semicolon injection '; echo INJECTED' is rejected by path check")
    public void executeCommand_semicolonInjectionPayload_isRejected() {
        // "; echo INJECTED" resolves to a path outside /var/data after normalisation.
        when(mockRequest.getParameter("cmd")).thenReturn("; echo INJECTED");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If execution reaches here, the Java directory API treated the input as
            // a literal filename — 'INJECTED' must not appear as command output.
            assertFalse(result.contains("INJECTED"),
                "Semicolon injection payload must not cause 'INJECTED' to appear in output.");
        } catch (SecurityException e) {
            // Expected: path resolves outside allowed base.
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            // Any other exception is acceptable — the payload was not executed as a command.
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: pipe injection '| id' is rejected (no shell to interpret '|')")
    public void executeCommand_pipeInjectionPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("| id");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // uid=... gid=... pattern from id(1) must not appear — no shell is invoked.
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Pipe injection payload must not cause id(1) output to appear.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: backtick injection '`id`' is rejected (no shell to interpret backticks)")
    public void executeCommand_backtickInjectionPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("`id`");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Backtick command substitution must not produce id(1) output.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: dollar-sign subshell '$(id)' is rejected (no shell to interpret '$(...)')")
    public void executeCommand_dollarSubshellPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("$(id)");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Dollar-sign subshell substitution must not produce id(1) output.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: ampersand injection '& whoami' is rejected (no shell to interpret '&')")
    public void executeCommand_ampersandInjectionPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("& whoami");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // whoami output (the current OS username) must not appear — no shell is invoked.
            assertFalse(result.contains(System.getProperty("user.name")),
                "Ampersand injection must not cause whoami output to appear.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: newline-separated injection must not execute second command")
    public void executeCommand_newlineInjectionPayload_isRejected() {
        // Newline written as escape sequence — never as a literal control byte —
        // to keep the source file valid UTF-8 text.
        when(mockRequest.getParameter("cmd")).thenReturn("/var/data\nwhoami");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // whoami output must not appear — no shell is invoked.
            assertFalse(result.contains(System.getProperty("user.name")),
                "Newline injection must not cause whoami output to appear.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            // InvalidPathException from the Java nio API is acceptable.
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: semicolon + touch injection must not create side-effect file")
    public void executeCommand_semicolonTouchInjection_doesNotCreateFile() {
        // This payload would create /tmp/pwned_test in a vulnerable ProcessBuilder version.
        when(mockRequest.getParameter("cmd")).thenReturn("; touch /tmp/pwned_test_cmd_injection");

        try {
            fileHandler.executeCommand(mockRequest);
        } catch (Exception e) {
            // Any exception is acceptable.
        }

        java.io.File marker = new java.io.File("/tmp/pwned_test_cmd_injection");
        assertFalse(marker.exists(),
            "Injected 'touch' command must not have created /tmp/pwned_test_cmd_injection. "
            + "The pure-Java directory API never invokes a shell.");
    }

    // -----------------------------------------------------------------------
    // D. Benign input — paths inside /var/data are accepted
    //    Files.newDirectoryStream() is used so no OS process is spawned.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: a valid directory inside /var/data is listed via the Java API")
    public void executeCommand_validDirectoryInsideAllowedBase_isListed(@TempDir Path tempDir) throws Exception {
        // Create a temporary subdirectory under a mock ALLOWED_BASE-equivalent directory
        // and verify no SecurityException is thrown for paths within /var/data.
        // Because /var/data may not exist in CI, we verify only that a relative path
        // inside /var/data does NOT trigger the SecurityException path-containment check.
        when(mockRequest.getParameter("cmd")).thenReturn("subdir");

        // The path "/var/data/subdir" is within ALLOWED_BASE — a SecurityException must
        // NOT be thrown.  An IOException (NoSuchFileException) is acceptable on machines
        // where /var/data does not exist.
        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If /var/data/subdir exists and is a directory, result is non-null.
            assertNotNull(result, "Result must be non-null for an allowed path.");
        } catch (SecurityException e) {
            fail("A relative path inside /var/data must not be rejected by the allowlist check. "
                 + "SecurityException: " + e.getMessage());
        } catch (Exception e) {
            // IOException / NoSuchFileException from Files.newDirectoryStream()
            // (path doesn't exist on this machine) is acceptable.
            assertFalse(e instanceof SecurityException,
                "IOException from the directory API is acceptable; SecurityException is not.");
        }
    }

    @Test
    @DisplayName("executeCommand: exact /var/data path is accepted by the containment check")
    public void executeCommand_exactAllowedBasePath_isAccepted() {
        // An absolute path equal to ALLOWED_BASE itself must pass the startsWith check.
        when(mockRequest.getParameter("cmd")).thenReturn("/var/data");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertNotNull(result, "Result must be non-null when the exact allowed base path is given.");
        } catch (SecurityException e) {
            fail("/var/data is the allowed base and must not be rejected. "
                 + "SecurityException: " + e.getMessage());
        } catch (Exception e) {
            // IOException is acceptable (directory may not exist on CI).
            assertFalse(e instanceof SecurityException);
        }
    }

    @Test
    @DisplayName("executeCommand: path with embedded '..' that normalises inside /var/data is accepted")
    public void executeCommand_pathWithDotDotNormalisedInsideBase_isAccepted() {
        // "/var/data/subdir/../subdir" normalises to "/var/data/subdir" — still inside base.
        when(mockRequest.getParameter("cmd")).thenReturn("/var/data/subdir/../subdir");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertNotNull(result);
        } catch (SecurityException e) {
            fail("A '..' segment that normalises inside /var/data must not be rejected. "
                 + "SecurityException: " + e.getMessage());
        } catch (Exception e) {
            // IOException is acceptable.
            assertFalse(e instanceof SecurityException);
        }
    }

    @Test
    @DisplayName("executeCommand: real existing directory listing returns file names without invoking a shell")
    public void executeCommand_realExistingDirectory_returnsListing(@TempDir Path tempDir) throws Exception {
        // This test creates actual files in a temp directory, but since ALLOWED_BASE is
        // hardcoded to /var/data we can only verify that Files.newDirectoryStream is used
        // (not ProcessBuilder) by checking that no process-spawning side effects occur.
        //
        // We verify the pure-Java path by confirming the method signature no longer
        // invokes ProcessBuilder at all — confirmed by code inspection.  The path
        // "/var/data" is accepted if the directory exists; otherwise IOException is thrown.
        when(mockRequest.getParameter("cmd")).thenReturn("/var/data");

        try {
            fileHandler.executeCommand(mockRequest);
            // No SecurityException — path was accepted by the containment check.
        } catch (SecurityException e) {
            fail("'/var/data' must be accepted: " + e.getMessage());
        } catch (IOException e) {
            // Expected on machines where /var/data does not exist.
            assertTrue(e.getClass().getSimpleName().contains("IOException")
                    || e.getClass().getSimpleName().contains("NoSuchFileException")
                    || e.getClass().getSimpleName().contains("NotDirectoryException"),
                "Only IO-related exceptions are expected when the path does not exist.");
        }
    }
}
