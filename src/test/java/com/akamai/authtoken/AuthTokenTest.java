package com.akamai.authtoken;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Map;

import static org.junit.Assert.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class AuthTokenTest {
	private static long DEFAULT_WINDOW_SECONDS = 500L;
	
	private AuthToken at;
	private AuthToken cat;
	private AuthToken hat;
	
	private String atHostname;
	private String atEncryptionKey;
	private String atTransitionKey;
	private String atSalt;
	
	
	@Before
	public void setUp() throws AuthTokenException {
		Map<String, String> env = System.getenv();
		
		if (env.get("TEST_MODE") == "TRAVIS") {
			// $ export TEST_MODE=TRAVIS
			this.atHostname = env.get("AT_HOSTNAME");
			this.atEncryptionKey = env.get("AT_ENCRYPTION_KEY");
			this.atTransitionKey = env.get("AT_TRANSITION_KEY");
			this.atSalt = env.get("AT_SALT_KEY");
		} else {
			// Secret Class
			this.atHostname = Secret.AT_HOSTNAME;
			this.atEncryptionKey = Secret.AT_ENCRYPTION_KEY;
			this.atTransitionKey = Secret.AT_TRANSITION_KEY;
			this.atSalt = Secret.AT_SALT_KEY;
		}
		
		this.at = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.build();
		this.cat = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.algorithm("sha1")
				.build();
		this.hat = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.algorithm("md5")
				.build();
	}
	
	@After
	public void tearDown() {}
	
	private void tokenSetting(char ttype, boolean escapeEarly, boolean transition) throws AuthTokenException {
		AuthToken t = null;
		
		if (ttype == 'q') {
			t = this.at;
		} else if(ttype == 'c') {
			t = this.cat;
		} else if(ttype == 'h') {
			t = this.hat;
		}
		
		if (transition) {
			t.setKey(this.atTransitionKey);
		}
		
		t.setEscapeEarly(escapeEarly);
	}
	
	private static String requests(String hostname, String path, String qs, String header) throws UnknownHostException, IOException {
		Socket socket = new Socket(hostname, 80);
		
		PrintWriter request = new PrintWriter (socket.getOutputStream());
		
		StringBuilder sb = new StringBuilder();
		
		sb.append("GET ");
		sb.append(path);
		if (qs != null && !qs.isEmpty()) {
			sb.append("?");
			sb.append(qs);
		}
		sb.append(" HTTP/1.1\r\n");
		sb.append("Host: ");
		sb.append(hostname);
		sb.append("\r\n");
		if (header != null && !header.isEmpty()) {
			sb.append(header);
			sb.append("\r\n");
		}
		sb.append("\r\n");
		
		request.print(sb.toString());
		request.flush();
		
		InputStream inStream = socket.getInputStream();
		BufferedReader rd = new BufferedReader(
			new InputStreamReader(inStream));
		
		String statusCode = "";
		try {
			statusCode = rd.readLine().split(" ")[1];
		} catch (Exception e) {}
		
		rd.close();
		inStream.close();
		request.close();
		socket.close();
		
		return statusCode;
	}
	
	private void queryAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws AuthTokenException, UnknownHostException, IOException { 
		this.tokenSetting('q', escapeEarly, transition);
		
		at.setPayload(payload);
		at.setSessionId(sessionId);
		
		String token = "";
		if (isUrl) {
			token = this.at.generateURLToken(path);
		} else {
			token = this.at.generateACLToken(path);
		}

		String qs = this.at.getTokenName() + "=" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, path, qs, null);
		assertEquals("404", statusCode);
	}
	
	private void cookieAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws AuthTokenException, UnknownHostException, IOException { 
		this.tokenSetting('c', escapeEarly, transition);
		
		cat.setPayload(payload);
		cat.setSessionId(sessionId);
		
		String token = "";
		if (isUrl) {
			token = this.cat.generateURLToken(path);
		} else {
			token = this.cat.generateACLToken(path);
		}

		String cookie = "Cookie: " + this.cat.getTokenName() + "=" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, path, null, cookie);
		assertEquals("404", statusCode);
	}
	
	private void headerAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws AuthTokenException, UnknownHostException, IOException { 
		this.tokenSetting('h', escapeEarly, transition);
		
		hat.setPayload(payload);
		hat.setSessionId(sessionId);
		
		String token = "";
		if (isUrl) {
			token = this.hat.generateURLToken(path);
		} else {
			token = this.hat.generateACLToken(path);
		}

		String header = this.hat.getTokenName() + ":" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, path, null, header);
		assertEquals("404", statusCode);
	}
	
	private void testCaseSet(String queryPath, String cookiePath, String headerPath, boolean escapeEarly, boolean isUrl) throws UnknownHostException, AuthTokenException, IOException {
		this.queryAssertEqual(queryPath, "404", escapeEarly, false, null, null, isUrl);
		this.cookieAssertEqual(cookiePath, "404", escapeEarly, false, null, null, isUrl);
		this.headerAssertEqual(headerPath, "404", escapeEarly, false, null, null, isUrl);
	}
	
	
	@Test
	public void test_url_escape_on__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", true, true);
	}
}