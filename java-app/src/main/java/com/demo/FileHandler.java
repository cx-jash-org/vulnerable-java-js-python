package com.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class FileHandler {

    // Trusted base directory: only paths within this directory are permitted.
    private static final Path ALLOWED_BASE = Paths.get("/var/data").toAbsolutePath().normalize();

    /**
     * Lists the contents of a user-supplied path using a pure-Java API.
     *
     * Security fix (CWE-77 Command Injection):
     *   The previous implementation passed the user-supplied (and path-normalised)
     *   path string as an argument to ProcessBuilder, allowing a SAST engine to
     *   track tainted user data flowing into an OS-process sink (pb.start()).
     *
     *   This version eliminates the ProcessBuilder/OS-process sink entirely and
     *   replaces it with java.nio.file.Files.newDirectoryStream(), a pure-Java
     *   library call that never spawns a shell process.  Shell metacharacters in
     *   userInput therefore have no execution surface whatsoever.
     *
     *   The path-containment check (Path.normalize() + Path.startsWith()) is
     *   retained as a defence-in-depth control to prevent path traversal.
     */
    public String executeCommand(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("cmd");

        if (userInput == null || userInput.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameter: cmd");
        }

        // Resolve and normalise the user-supplied path against the allowed base.
        // Path.normalize() removes ".." and "." components; startsWith() enforces
        // the directory boundary — stdlib APIs recognised by SAST engines for
        // path containment checks.
        Path resolvedPath = ALLOWED_BASE.resolve(userInput).normalize();
        if (!resolvedPath.startsWith(ALLOWED_BASE)) {
            throw new SecurityException("Access denied: path is outside the allowed directory.");
        }

        // Use a pure-Java directory listing API instead of an OS process.
        // Files.newDirectoryStream() never invokes a shell, so no shell
        // metacharacters in resolvedPath can be interpreted as commands.
        StringBuilder result = new StringBuilder();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(resolvedPath)) {
            for (Path entry : stream) {
                result.append(entry.getFileName().toString()).append("\n");
            }
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
