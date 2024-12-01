/**
This application is for demonstration use only. It contains known application security
vulnerabilities that were created expressly for demonstrating the functionality of
application security testing tools. These vulnerabilities may present risks to the
technical environment in which the application is installed. You must delete and
uninstall this demonstration application upon completion of the demonstration for
which it is intended. 

IBM DISCLAIMS ALL LIABILITY OF ANY KIND RESULTING FROM YOUR USE OF THE APPLICATION
OR YOUR FAILURE TO DELETE THE APPLICATION FROM YOUR ENVIRONMENT UPON COMPLETION OF
A DEMONSTRATION. IT IS YOUR RESPONSIBILITY TO DETERMINE IF THE PROGRAM IS APPROPRIATE
OR SAFE FOR YOUR TECHNICAL ENVIRONMENT. NEVER INSTALL THE APPLICATION IN A PRODUCTION
ENVIRONMENT. YOU ACKNOWLEDGE AND ACCEPT ALL RISKS ASSOCIATED WITH THE USE OF THE APPLICATION.

IBM AltoroJ
(c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */
package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import com.ibm.security.appscan.Log4AltoroJ;
import com.ibm.security.appscan.altoromutual.util.DBUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

/**
 * This servlet processes user's login and logout operations
 * Servlet implementation class LoginServlet
 * @author Alexei
 */
public class LoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public LoginServlet() {
        super();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		//log out
		try {
			HttpSession session = request.getSession(false);
			session.removeAttribute(ServletUtil.SESSION_ATTR_USER);
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			connection.setSSLSocketFactory(new TLS12SocketFactory());
		} catch (Exception e){
			// do nothing
		} finally {
			response.sendRedirect("index.jsp");
		}
		
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		//log in
		// Create session if there isn't one:
		HttpSession session = request.getSession(true);

		String username = null;
		
		try {
			username = request.getParameter("uid");
			if (username != null)
				username = username.trim().toLowerCase();
			
			String password = request.getParameter("passw");
			password = password.trim().toLowerCase(); //in real life the password usually is case sensitive and this cast would not be done
			
			if (!DBUtil.isValidUser(username, password)){
				Log4AltoroJ.getInstance().logError("Login failed >>> User: " +username + " >>> Password: " + password);
				throw new Exception("Login Failed: We're sorry, but this username or password was not found in our system. Please try again.");
			}
		} catch (Exception ex) {
			request.getSession(true).setAttribute("loginError", ex.getLocalizedMessage());
			response.sendRedirect("login.jsp");
			return;
		}

		//Handle the cookie using ServletUtil.establishSession(String)
		try{
			Cookie accountCookie = ServletUtil.establishSession(username,session);
			response.addCookie(accountCookie);
			response.sendRedirect(request.getContextPath()+"/bank/main.jsp");
			}
		catch (Exception ex){
			ex.printStackTrace();
			response.sendError(500);
		}
			
		
		return;
	}
	 public class TLS12SocketFactory extends SSLSocketFactory {
      private final SSLSocketFactory delegate;

      public TLS12SocketFactory() throws Exception {
          SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
          sslContext.init(null, null, null);
          delegate = sslContext.getSocketFactory();
      }

      @Override
      public String[] getDefaultCipherSuites() {
          return delegate.getDefaultCipherSuites();
      }

      @Override
      public String[] getSupportedCipherSuites() {
          return delegate.getSupportedCipherSuites();
      }

      @Override
      public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
          return enableTLS12OnSocket(delegate.createSocket(s, host, port, autoClose));
      }

      @Override
      public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
          return enableTLS12OnSocket(delegate.createSocket(host, port));
      }

      @Override
      public Socket createSocket(InetAddress host, int port) throws IOException {
          return enableTLS12OnSocket(delegate.createSocket(host, port));
      }

      @Override
      public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException, UnknownHostException {
          return enableTLS12OnSocket(delegate.createSocket(host, port, localHost, localPort));
      }

      @Override
      public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
          return enableTLS12OnSocket(delegate.createSocket(address, port, localAddress, localPort));
      }

      private Socket enableTLS12OnSocket(Socket socket) {
          if (socket instanceof SSLSocket) {
              SSLSocket sslSocket = (SSLSocket) socket;
              sslSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
          }
          return socket;
      }
  }

}
