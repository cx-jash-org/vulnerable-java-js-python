package com.demo;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SearchServlet {

    // VULNERABLE: Reflected XSS
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String searchTerm = request.getParameter("q");

        PrintWriter out = response.getWriter();
        // Unsanitized output - SAST will flag this
        out.println("<html><body>");
        out.println("<h1>Search results for: " + searchTerm + "</h1>");
        out.println("</body></html>");
    }

    // VULNERABLE: Open Redirect
    public void redirect(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("url");
        response.sendRedirect(target);
    }
}
