package com.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import javax.servlet.http.HttpServletRequest;

public class FileHandler {

    // FIXED: Command Injection remediated by using ProcessBuilder with an argument list.
    // userInput is passed as a discrete argv element (not shell-interpolated), so shell
    // metacharacters (;, |, &, $, `, etc.) cannot be interpreted by a shell interpreter.
    public String executeCommand(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("cmd");

        // ProcessBuilder with a List<String> (argv array) never invokes a shell, so
        // userInput cannot inject additional commands regardless of its content.
        ProcessBuilder pb = new ProcessBuilder(Arrays.asList("ls", userInput));
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
