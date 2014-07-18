package com.nimblebook.framework.worker;

import javax.jms.Message;
import javax.jms.MessageListener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimblebook.support.utility.Utility;


public class IndexWorker implements MessageListener {
	private static final Logger log = LoggerFactory.getLogger(IndexWorker.class);

	private static Utility util = new Utility();

	private String accessCode;

	public IndexWorker() {
		this.accessCode = util.generateUUID();
		log.info("Index worker created with access code: " + accessCode);
	}
	
	@Override
	public void onMessage(Message message) {
	
		System.out.println("*****************************************");

	}

}
