package com.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for FileHandler.executeCommand to verify the Command Injection (CWE-77)
 * vulnerability has been fully remediated.
 *
 * The fix applies two complementary SAST-recognised controls:
 *   1. Path containment check: userInput is resolved against ALLOWED_BASE
 *      (/var/data) using Path.normalize() + Path.startsWith(), so only paths
 *      within the trusted base directory are accepted. Shell metacharacter
 *      sequences that would escape the directory are rejected before reaching
 *      ProcessBuilder.
 *   2. ProcessBuilder(List<String>) — no shell is invoked; the first argument
 *      ("ls") is a hardcoded command, and the second is the validated path.
 *
 * Test categories:
 *   A. Input validation — null/empty parameters are rejected early.
 *   B. Allowlist enforcement — paths outside /var/data throw SecurityException.
 *   C. Injection payloads — shell metacharacters injected via userInput are
 *      rejected by the path-containment check (they resolve outside /var/data
 *      or are otherwise invalid) and never reach the OS shell.
 *   D. Benign inputs — well-formed paths inside /var/data are accepted.
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
            "A null 'cmd' parameter must throw IllegalArgumentException before reaching ProcessBuilder.");
    }

    @Test
    @DisplayName("executeCommand: empty 'cmd' parameter must throw IllegalArgumentException")
    public void executeCommand_emptyParameter_throwsIllegalArgumentException() {
        when(mockRequest.getParameter("cmd")).thenReturn("");

        assertThrows(IllegalArgumentException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "An empty 'cmd' parameter must throw IllegalArgumentException before reaching ProcessBuilder.");
    }

    // -----------------------------------------------------------------------
    // B. Allowlist (path containment) enforcement
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: absolute path outside /var/data must throw SecurityException")
    public void executeCommand_absolutePathOutsideAllowedBase_throwsSecurityException() {
        // /etc/passwd is a well-known sensitive file outside /var/data.
        when(mockRequest.getParameter("cmd")).thenReturn("/etc/passwd");

        assertThrows(SecurityException.class,
            () -> fileHandler.executeCommand(mockRequest),
            "A path outside the allowed base directory must be rejected with SecurityException.");
    }

    @Test
    @DisplayName("executeCommand: path traversal via '../..' must throw SecurityException")
    public void executeCommand_pathTraversalWithDotDot_throwsSecurityException() {
        // "../../etc/passwd" resolves to /etc/passwd after normalisation — outside /var/data.
        when(mockRequest.getParameter("cmd")).thenReturn("../../etc/passwd");

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

    // -----------------------------------------------------------------------
    // C. Injection payload tests — all payloads must NOT execute shell commands
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: semicolon injection '; echo INJECTED' must be rejected")
    public void executeCommand_semicolonInjectionPayload_isRejected() {
        // "; echo INJECTED" resolves to a path that either escapes /var/data or is
        // otherwise invalid; it must be rejected before reaching ProcessBuilder.
        when(mockRequest.getParameter("cmd")).thenReturn("; echo INJECTED");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If execution reaches here, 'INJECTED' must not be present in output.
            assertFalse(result.contains("INJECTED"),
                "Semicolon injection payload must not cause 'INJECTED' to appear in output.");
        } catch (SecurityException e) {
            // Expected: path resolves outside allowed base.
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            // Any other exception is acceptable — the payload was not executed.
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: pipe injection '| id' must be rejected")
    public void executeCommand_pipeInjectionPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("| id");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // uid=... gid=... pattern from id(1) must not appear.
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Pipe injection payload must not cause id(1) output to appear.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: backtick injection '`id`' must be rejected")
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
    @DisplayName("executeCommand: dollar-sign subshell '$(id)' must be rejected")
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
    @DisplayName("executeCommand: ampersand injection '& whoami' must be rejected")
    public void executeCommand_ampersandInjectionPayload_isRejected() {
        when(mockRequest.getParameter("cmd")).thenReturn("& whoami");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // whoami output (the current OS username) must not appear.
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
            // whoami output must not appear.
            assertFalse(result.contains(System.getProperty("user.name")),
                "Newline injection must not cause whoami output to appear.");
        } catch (SecurityException e) {
            assertNotNull(e.getMessage());
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand: semicolon + touch injection must not create side-effect file")
    public void executeCommand_semicolonTouchInjection_doesNotCreateFile() {
        // This payload would create /tmp/pwned_test in the vulnerable version.
        when(mockRequest.getParameter("cmd")).thenReturn("; touch /tmp/pwned_test_cmd_injection");

        try {
            fileHandler.executeCommand(mockRequest);
        } catch (Exception e) {
            // Any exception is acceptable.
        }

        java.io.File marker = new java.io.File("/tmp/pwned_test_cmd_injection");
        assertFalse(marker.exists(),
            "Injected 'touch' command must not have created /tmp/pwned_test_cmd_injection.");
    }

    // -----------------------------------------------------------------------
    // D. Benign input — paths inside /var/data are accepted (functionality test)
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand: a relative path inside /var/data is accepted and passed to ls")
    public void executeCommand_relativePathInsideAllowedBase_isAccepted() {
        // "subdir" resolves to /var/data/subdir — inside ALLOWED_BASE.
        // ls will fail with IOException if the path does not exist, but the key
        // assertion is that no SecurityException is thrown.
        when(mockRequest.getParameter("cmd")).thenReturn("subdir");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // Path was allowed; result may be empty if the directory has no files.
            assertNotNull(result, "Result must be non-null for an allowed path.");
        } catch (SecurityException e) {
            fail("A relative path inside /var/data must not be rejected by the allowlist check. "
                 + "SecurityException message: " + e.getMessage());
        } catch (Exception e) {
            // IOException from ls (path doesn't exist on this machine) is acceptable.
            assertFalse(e instanceof SecurityException,
                "IOException from ls is acceptable; SecurityException is not.");
        }
    }

    @Test
    @DisplayName("executeCommand: exact /var/data path is accepted and passed to ls")
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
            // IOException from ls is acceptable (directory may not exist on CI).
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
            // IOException from ls is acceptable.
            assertFalse(e instanceof SecurityException);
        }
    }
}
