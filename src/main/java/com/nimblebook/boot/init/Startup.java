package com.nimblebook.boot.init;

import java.io.File;

import javax.jms.JMSException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.web.context.WebApplicationContext;

import com.nimblebook.framework.worker.IndexWorker;
import com.nimblebook.support.config.SystemConfig;
import com.nimblebook.support.utility.EmbeddedMQ;

public class Startup {

	private static final Logger log = LoggerFactory.getLogger(Startup.class);

	private static EmbeddedMQ mq;
	
	public static File rootWorkDir;
	
	public static int aggregateSize;
	
	public static int aggregateSeconds;
	
	@Autowired
	private ApplicationContext applicationContext;
	
	private static SystemConfig config;
	
	public void init() {
		System.out.println("Startup init() has been called.");
		log.info("Starting service @" + applicationContext);

		config = new SystemConfig((WebApplicationContext) applicationContext);

		String wd = config.getString("workDirectory");
		if (wd == null) {
			log.error("Unable to start because workDirectory is missing from config");
			return;
		}
		rootWorkDir = new File(wd);
		if (!rootWorkDir.exists()) {	
			log.error("Unable to start because workDirectory is not found - " + rootWorkDir.getPath());
			return;
		}
		
		
		String domainId = config.getString("domainId");
		if (domainId == null) {
			log.error("Unable to start because domainId is missing in config");
			return;
		}


		try {
			mq = new EmbeddedMQ();
			com.nimblebook.support.utility.MqUtil mqUtil = mq.getMqUtil();
			int indexInstance = 10; //config.getInt(Constants.CONCURRENT_INDEX_WORKER);
			if (indexInstance < 3) indexInstance = 3; //Make it at least 3 instances to serve.
			for (int i=0; i < indexInstance; i++) {
				mqUtil.createQueueMessageConsumer("nimble-mq", new IndexWorker());
			}

			
		} catch (JMSException je) {
			je.printStackTrace();
		}
		config.setReady(true);
	}
	
	public void shutdown() {
		System.out.println("Startup shutdown() has been called.");
	}
	
}
