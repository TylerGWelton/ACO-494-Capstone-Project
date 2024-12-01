package com.ibm.security.appscan.altoromutual.listener;

import javax.net.ssl.SSLContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import com.ibm.security.appscan.Log4AltoroJ;
import com.ibm.security.appscan.altoromutual.util.DBUtil;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

public class StartupListener implements ServletContextListener {

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		try {
		ServletUtil.initializeAppProperties(sce.getServletContext());
		ServletUtil.initializeLogFile(sce.getServletContext());
		DBUtil.isValidUser("bogus", "user");
		ServletUtil.initializeRestAPI(sce.getServletContext());
		System.setProperty("https.protocols", "TLSv1.2");
		System.SSLContext.getInstance("TLSv1.1");
		System.out.println("AltoroJ initialized");
		} catch (Exception e) {
			Log4AltoroJ.getInstance().logError("Error during AltoroJ initialization:" + e.getMessage());
//			e.printStackTrace();
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		// do nothing
	}

}
