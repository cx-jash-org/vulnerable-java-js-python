package com.demo;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import javax.servlet.http.HttpServletRequest;

public class FileHandler {

    // VULNERABLE: Command Injection
    public String executeCommand(HttpServletRequest request) throws Exception {
        String userInput = request.getParameter("cmd");

        Process p = Runtime.getRuntime().exec("ls " + userInput);
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
