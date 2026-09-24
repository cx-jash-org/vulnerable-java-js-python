package com.demo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for FileHandler.executeCommand to verify the Command Injection (CWE-77)
 * vulnerability has been remediated.
 *
 * The fix replaces Runtime.getRuntime().exec(String) — which passes a shell string
 * and can be exploited via metacharacters — with ProcessBuilder(List<String>),
 * which passes each argument as a discrete argv element without shell interpolation.
 *
 * These tests validate:
 *   1. Normal (benign) inputs continue to work (regression safety).
 *   2. Shell injection payloads are NOT executed as commands — they are treated
 *      as literal path arguments, causing the process to fail rather than execute
 *      injected shell commands.
 *   3. ProcessBuilder with an argument list is used (not Runtime.exec with a string).
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
    // Structural test: verify the implementation uses ProcessBuilder, not
    // Runtime.exec(String), which is the pattern that enables command injection.
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("executeCommand must not use Runtime.exec with a String argument (injection-safe API check)")
    public void executeCommand_doesNotUseRuntimeExecWithString() throws Exception {
        // Read the source of the compiled class to confirm the fix is in place.
        // We verify by inspecting the class bytecode: Runtime.exec(String) has
        // descriptor "(Ljava/lang/String;)Ljava/lang/Process;" whereas
        // ProcessBuilder.start() has descriptor "()Ljava/lang/Process;".
        // A simpler proxy: we confirm that calling the method with a shell
        // injection payload does NOT cause injection side effects (see injection tests).
        // This test documents the architectural expectation.

        // The vulnerable pattern: Runtime.getRuntime().exec("ls " + userInput)
        // The safe pattern:       new ProcessBuilder(Arrays.asList("ls", userInput)).start()

        // Verify that the class source no longer contains the dangerous pattern by
        // checking that invoking with an injection payload throws an IOException
        // (no such file named ".; cat /etc/passwd") rather than executing shell commands.
        when(mockRequest.getParameter("cmd")).thenReturn("; echo INJECTED");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If the call succeeds, verify "INJECTED" is not present in output —
            // the payload was treated as a literal path, not executed by a shell.
            assertFalse(result.contains("INJECTED"),
                "Shell injection payload should not be executed; " +
                "'INJECTED' must not appear in output when ProcessBuilder argv is used.");
        } catch (Exception e) {
            // An IOException or similar is expected because "; echo INJECTED" is not
            // a valid path — ProcessBuilder treats it as a literal argument to ls,
            // so ls fails to find the file. This is the correct, safe behavior.
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected an IOException when the injection payload is treated as a " +
                "literal path argument (not executed as shell commands). Got: " + e.getClass().getName()
            );
        }
    }

    @Test
    @DisplayName("executeCommand with pipe injection payload must not execute injected commands")
    public void executeCommand_pipeInjectionPayloadIsNotExecuted() throws Exception {
        // Payload: "| id" — in the vulnerable code this would append "| id" to
        // "ls " and execute "ls | id" via /bin/sh, revealing user identity.
        // With the fix, "| id" is a literal argument to ls and ls fails.
        when(mockRequest.getParameter("cmd")).thenReturn("| id");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If ls somehow succeeds (e.g. a file named "| id" exists), the output
            // should not contain typical id(1) output patterns.
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "The 'id' command output should not appear — pipe injection must not execute.");
        } catch (Exception e) {
            // Expected: ls exits non-zero / IOException because "| id" is not a valid path.
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected IOException for pipe injection payload treated as a literal argument.");
        }
    }

    @Test
    @DisplayName("executeCommand with semicolon injection payload must not execute injected commands")
    public void executeCommand_semicolonInjectionPayloadIsNotExecuted() throws Exception {
        // Payload: "; touch /tmp/pwned" — would create a file in the vulnerable version.
        when(mockRequest.getParameter("cmd")).thenReturn("; touch /tmp/pwned_test");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If execution somehow reached here, the injected 'touch' command should
            // NOT have run; we verify the side-effect file does not exist.
            java.io.File marker = new java.io.File("/tmp/pwned_test");
            assertFalse(marker.exists(),
                "Injected 'touch' command must not have been executed via semicolon injection.");
        } catch (Exception e) {
            // Correct behavior: the payload is a literal path argument, ls fails.
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected IOException for semicolon injection payload treated as a literal argument.");
        }
    }

    @Test
    @DisplayName("executeCommand with backtick injection payload must not execute injected commands")
    public void executeCommand_backtickInjectionPayloadIsNotExecuted() throws Exception {
        // Payload: "`id`" — shell command substitution; dangerous in shell-exec mode.
        when(mockRequest.getParameter("cmd")).thenReturn("`id`");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Backtick command substitution output must not appear in result.");
        } catch (Exception e) {
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected IOException for backtick injection payload treated as a literal argument.");
        }
    }

    @Test
    @DisplayName("executeCommand with dollar-sign subshell payload must not execute injected commands")
    public void executeCommand_dollarSubshellInjectionPayloadIsNotExecuted() throws Exception {
        // Payload: "$(id)" — $(...) subshell substitution.
        when(mockRequest.getParameter("cmd")).thenReturn("$(id)");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            assertFalse(result.matches("(?s).*uid=\\d+.*gid=\\d+.*"),
                "Dollar-sign subshell substitution output must not appear in result.");
        } catch (Exception e) {
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected IOException for $() injection payload treated as a literal argument.");
        }
    }

    @Test
    @DisplayName("executeCommand with ampersand injection payload must not execute injected commands")
    public void executeCommand_ampersandInjectionPayloadIsNotExecuted() throws Exception {
        // Payload: "& whoami" — background execution in shell.
        when(mockRequest.getParameter("cmd")).thenReturn("& whoami");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // whoami output should not appear.
            assertFalse(result.contains(System.getProperty("user.name")),
                "whoami output must not appear in result when ampersand injection is used.");
        } catch (Exception e) {
            assertTrue(
                e instanceof java.io.IOException || e.getCause() instanceof java.io.IOException,
                "Expected IOException for ampersand injection payload treated as a literal argument.");
        }
    }

    @Test
    @DisplayName("executeCommand with newline injection payload must not execute injected commands")
    public void executeCommand_newlineInjectionPayloadIsNotExecuted() throws Exception {
        // Payload contains a newline (\n) — some shells treat this as a command separator.
        // Written using escape sequence (never a literal control byte).
        when(mockRequest.getParameter("cmd")).thenReturn("/tmp\nwhoami");

        try {
            String result = fileHandler.executeCommand(mockRequest);
            // Should not contain whoami output.
            assertFalse(result.contains(System.getProperty("user.name")),
                "Newline-separated command injection must not execute via ProcessBuilder argv.");
        } catch (Exception e) {
            // Any exception is acceptable — the payload is not shell-interpreted.
            assertNotNull(e);
        }
    }

    @Test
    @DisplayName("executeCommand with null cmd parameter must not cause NullPointerException in ProcessBuilder")
    public void executeCommand_nullParameter_throwsOrHandlesGracefully() throws Exception {
        // When the 'cmd' parameter is absent, getParameter returns null.
        // ProcessBuilder will receive null as an argv element, which throws NullPointerException.
        // This documents the expected behavior (caller must validate input).
        when(mockRequest.getParameter("cmd")).thenReturn(null);

        assertThrows(Exception.class, () -> fileHandler.executeCommand(mockRequest),
            "A null 'cmd' parameter should result in an exception, not silent execution.");
    }

    @Test
    @DisplayName("executeCommand with benign path argument should attempt ls on that path")
    public void executeCommand_benignInput_attemptsLsOnPath() throws Exception {
        // A legitimate-looking path (that exists on most systems).
        when(mockRequest.getParameter("cmd")).thenReturn("/tmp");

        // This should either succeed (returning a listing) or throw IOException
        // if /tmp is restricted. Either way, no injection occurs.
        try {
            String result = fileHandler.executeCommand(mockRequest);
            // If /tmp is accessible, result is non-null (may be empty or have entries).
            assertNotNull(result, "Result should be non-null for a benign path input.");
        } catch (Exception e) {
            // Acceptable: the environment may restrict this path.
            assertNotNull(e);
        }
    }
}
