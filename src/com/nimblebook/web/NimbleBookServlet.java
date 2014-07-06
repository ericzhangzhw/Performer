package com.nimblebook.web;

import java.io.IOException;

import javax.servlet.http.*;

import com.google.apphosting.utils.config.ClientDeployYamlMaker.Request;

@SuppressWarnings("serial")
public class NimbleBookServlet extends HttpServlet {
	public void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws IOException {
		
		resp.setContentType("text/plain");
		resp.getWriter().println("Hello, world");
		req.getRequestDispatcher("");
	}
}
