package com.demo;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserController {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/demo";
    private static final String DB_USER = "demo";
    private static final String DB_PASS = "demo";

    // VULNERABLE: SQL Injection
    public ResultSet getUserById(HttpServletRequest request) throws Exception {
        String userId = request.getParameter("id");

        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        // Direct string concatenation - SAST will flag this
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return stmt.executeQuery(query);
    }

    // VULNERABLE: SQL Injection in login
    public boolean login(HttpServletRequest request) throws Exception {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();

        String query = "SELECT * FROM users WHERE username = '" + username
                       + "' AND password = '" + password + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next();
    }
}
