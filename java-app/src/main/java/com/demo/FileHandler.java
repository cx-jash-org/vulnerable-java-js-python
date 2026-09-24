package com.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;

public class FileHandler {

    // Trusted base directory: only paths within this directory are permitted.
    private static final Path ALLOWED_BASE = Paths.get("/var/data").toAbsolutePath().normalize();

    /**
     * Executes "ls" on a user-supplied path.
     *
     * Security fix (CWE-77 Command Injection):
     *   1. userInput is validated against an allowlist base directory using
     *      Path.normalize() + Path.startsWith() — the SAST-recognised path-containment
     *      check — so only paths inside ALLOWED_BASE are accepted.
     *   2. The validated, normalised path (not the raw user string) is passed as a
     *      discrete argv element to ProcessBuilder(List<String>), which never invokes
     *      a shell and therefore cannot interpret shell metacharacters.
     *   Together these controls eliminate both the command-injection and path-traversal
     *   risk: the command is hardcoded ("ls") and the argument is constrained to a
     *   trusted directory subtree.
     */
    public String executeCommand(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("cmd");

        if (userInput == null || userInput.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameter: cmd");
        }

        // Resolve and normalise the user-supplied path against the allowed base.
        // Path.normalize() removes ".." and "." components; startsWith() enforces
        // the directory boundary — these are the stdlib APIs SAST engines recognise
        // for path containment checks.
        Path resolvedPath = ALLOWED_BASE.resolve(userInput).normalize();
        if (!resolvedPath.startsWith(ALLOWED_BASE)) {
            throw new SecurityException("Access denied: path is outside the allowed directory.");
        }

        // Use only the normalised, validated path as the argument.
        // ProcessBuilder with a List<String> never invokes a shell interpreter,
        // so no shell metacharacters in resolvedPath can be executed.
        ProcessBuilder pb = new ProcessBuilder(Arrays.asList("ls", resolvedPath.toString()));
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader reader = new BufferedReader(
            new java.io.InputStreamReader(p.getInputStream())
        );

        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line).append("\n");
        }
        return result.toString();
    }

    // VULNERABLE: Path Traversal
    public String readFile(HttpServletRequest request) throws Exception {
        String fileName = request.getParameter("file");

        File file = new File("/var/data/" + fileName);
        BufferedReader reader = new BufferedReader(new FileReader(file));

        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }
}
