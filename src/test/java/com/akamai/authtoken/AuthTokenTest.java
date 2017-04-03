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
		if (env.get("TEST_MODE") != null && env.get("TEST_MODE").equalsIgnoreCase("TRAVIS")) {
			this.atHostname = env.get("AT_HOSTNAME");
			this.atEncryptionKey = env.get("AT_ENCRYPTION_KEY");
			this.atTransitionKey = env.get("AT_TRANSITION_KEY");
			this.atSalt = env.get("AT_SALT_KEY");
		} else {
			// this.atHostname = Secret.AT_HOSTNAME;
			// this.atEncryptionKey = Secret.AT_ENCRYPTION_KEY;
			// this.atTransitionKey = Secret.AT_TRANSITION_KEY;
			// this.atSalt = Secret.AT_SALT_KEY;
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
			if (path.contains("?")) {
				sb.append("&");
			} else {
				sb.append("?");
			}
			sb.append(qs);
		}
		//System.out.println(sb.toString());
		sb.append(" HTTP/1.1\r\n");
		sb.append("Host: ");
		sb.append(hostname);
		sb.append("\r\n");
		if (header != null && header != "") {
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
		} catch (Exception e) { 
			System.out.println(e.getMessage());
		} finally {
			rd.close();
		}
		
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
		assertEquals(expacted, statusCode);
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
		assertEquals(expacted, statusCode);
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
		assertEquals(expacted, statusCode);
	}
	
	private void testCaseSet(String queryPath, String cookiePath, String headerPath, boolean escapeEarly, boolean isUrl) throws UnknownHostException, AuthTokenException, IOException {
		// General Test
		this.queryAssertEqual(queryPath, "404", escapeEarly, false, null, null, isUrl);
		this.cookieAssertEqual(cookiePath, "404", escapeEarly, false, null, null, isUrl);
		this.headerAssertEqual(headerPath, "404", escapeEarly, false, null, null, isUrl);
		
		// Query String Test
		if (isUrl) {
			String queryString = "?foo=bar&hello=world";
			this.queryAssertEqual(queryPath + queryString, "403", escapeEarly==false, false, null, null, isUrl);
			this.cookieAssertEqual(cookiePath + queryString, "403", escapeEarly==false, false, null, null, isUrl);
			this.headerAssertEqual(headerPath + queryString, "403", escapeEarly==false, false, null, null, isUrl);
		}
		
		// Transition Key Test
		this.queryAssertEqual(queryPath, "404", escapeEarly, true, null, null, isUrl);
		this.cookieAssertEqual(cookiePath, "404", escapeEarly, true, null, null, isUrl);
		this.headerAssertEqual(headerPath, "404", escapeEarly, true, null, null, isUrl);
		
		// Payload Test
		this.queryAssertEqual(queryPath, "404", escapeEarly, false, "SOME_PAYLOAD_DATA", null, isUrl);
		this.cookieAssertEqual(cookiePath, "404", escapeEarly, false, "SOME_PAYLOAD_DATA", null, isUrl);
		this.headerAssertEqual(headerPath, "404", escapeEarly, false, "SOME_PAYLOAD_DATA", null, isUrl);
		
		// SessionId Test
		this.queryAssertEqual(queryPath, "404", escapeEarly, false, null, "SOME_SESSIONID_DATA", isUrl);
		this.cookieAssertEqual(cookiePath, "404", escapeEarly, false, null, "SOME_SESSIONID_DATA", isUrl);
		this.headerAssertEqual(headerPath, "404", escapeEarly, false, null, "SOME_SESSIONID_DATA", isUrl);   
	}
	
	/**********
	 * URL TEST
	 **********/
	@Test
	public void test_url_escape_on__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", true, true);
	}
	
	@Test
	public void test_url_escape_off__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_ignore", "/c_ignore", "/h_ignore", false, true);
	}
	
	@Test
	public void test_url_escape_on__ignoreQuery_no() throws UnknownHostException, AuthTokenException, IOException {
		String queryPath = "/q_escape";
		String cookiePath = "/c_escape";
		String headerPath = "/h_escape";
		this.testCaseSet(queryPath, cookiePath, headerPath, true, true);

		String queryString = "?foo=bar&hello=world";
		this.queryAssertEqual(queryPath + queryString, "404", true, false, null, null, true);
		this.cookieAssertEqual(cookiePath + queryString, "404", true, false, null, null, true);
		this.headerAssertEqual(headerPath + queryString, "404", true, false, null, null, true);
	}
	
	@Test
	public void test_url_escape_off__ignoreQuery_no() throws UnknownHostException, AuthTokenException, IOException {
		String queryPath = "/q";
		String cookiePath = "/c";
		String headerPath = "/h";
		this.testCaseSet(queryPath, cookiePath, headerPath, false, true);

		String queryString = "?foo=bar&hello=world";
		this.queryAssertEqual(queryPath + queryString, "404", false, false, null, null, true);
		this.cookieAssertEqual(cookiePath + queryString, "404", false, false, null, null, true);
		this.headerAssertEqual(headerPath + queryString, "404", false, false, null, null, true);
	}
	
	@Test
	public void test_url_query_escape_on__ignore_yes_with_salt() throws UnknownHostException, AuthTokenException, IOException {
		String querySaltPath = "/salt";
		AuthToken ats = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.salt(this.atSalt)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.escapeEarly(true)
				.build();
		String token = ats.generateURLToken(querySaltPath);
		String qs = ats.getTokenName() + "=" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, querySaltPath, qs, null);
		assertEquals("404", statusCode);
	}
	
	/**********
	 * ACL TEST
	 **********/
	@Test
	public void test_acl_escape_on__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", false, false);
	}
	
	@Test
	public void test_acl_escape_off__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_ignore", "/c_ignore", "/h_ignore", false, false);
	}
	
	@Test
	public void test_acl_escape_on__ignoreQuery_no() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q_escape", "/c_escape", "/h_escape", false, false);
	}
	
	@Test
	public void test_acl_escape_off__ignoreQuery_no() throws UnknownHostException, AuthTokenException, IOException {
		this.testCaseSet("/q", "/c", "/h", false, false);
	}
	
	@Test
	public void test_acl_asta_escape_on__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		AuthToken ata = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.build();
		String token = ata.generateACLToken("/q_escape_ignore/*");
		String qs = ata.getTokenName() + "=" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, "/q_escape_ignore/hello", qs, null);
		assertEquals("404", statusCode);
	}
	
	@Test
	public void test_acl_deli_escape_on__ignoreQuery_yes() throws UnknownHostException, AuthTokenException, IOException {
		AuthToken atd = new AuthTokenBuilder()
				.key(this.atEncryptionKey)
				.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
				.build();
		String acl[] = { "/q_escape_ignore", "/q_escape_ignore/*" };

		// For Java 8
		// String token = atd.generateACLToken(String.join(AuthToken.ACL_DELIMITER, acl));
		
		// For All
		String token = atd.generateACLToken(AuthToken.join(AuthToken.ACL_DELIMITER, acl));
		
		String qs = atd.getTokenName() + "=" + token;
		String statusCode = AuthTokenTest.requests(this.atHostname, "/q_escape_ignore", qs, null);
		assertEquals("404", statusCode);
		
		statusCode = AuthTokenTest.requests(this.atHostname, "/q_escape_ignore/world/", qs, null);
		assertEquals("404", statusCode);
	}
	
	@Test 
	public void test_exceptions() {
		try {
			AuthToken att = new AuthTokenBuilder()
					// .key(this.atEncryptionKey)
					.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
					.build();
		} catch(AuthTokenException ae) {
			assertEquals(ae.getMessage(), "You must provide a secret in order to generate a new token.");
		}
		try {
			AuthToken att = new AuthTokenBuilder()
					 .key(this.atEncryptionKey)
//					.windowSeconds(AuthTokenTest.DEFAULT_WINDOW_SECONDS)
					.build();
		} catch(AuthTokenException ae) {
			assertEquals(ae.getMessage(), "You must provide an expiration time or a duration window ( > 0 )");
		}		
	}
}