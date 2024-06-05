package com.karytech.mio.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.ApplicationContext;

import java.lang.management.ManagementFactory;
import java.nio.charset.Charset;
import java.util.Locale;
import java.util.TimeZone;

@SpringBootApplication
public class SignatureApplication {
	private static final Logger LOGGER = LoggerFactory.getLogger(SignatureApplication.class);

	public static void main(String[] args) {
		ApplicationContext context = SpringApplication.run(SignatureApplication.class, args);
		ServerProperties serverProperties = context.getBean(ServerProperties.class);
		LOGGER.info("\n\n");
		LOGGER.info("------------------------------");
		LOGGER.info("Api Application is running...");
		LOGGER.info("PID                  : " + getPID());
		LOGGER.info("server.port          : " + serverProperties.getPort());
		LOGGER.info("Default Charset      : " + Charset.defaultCharset());
		LOGGER.info("Default Locale       : " + Locale.getDefault());
		LOGGER.info("Default Timezone     : " + TimeZone.getDefault().getID());
		LOGGER.info("------------------------------");
		LOGGER.info("\n\n");
	}
	private static String getPID() {
		String name = ManagementFactory.getRuntimeMXBean().getName();
		return name.substring(0, name.indexOf("@"));
	}
}
