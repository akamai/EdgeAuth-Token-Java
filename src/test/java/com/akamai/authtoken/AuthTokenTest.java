package com.akamai.authtoken;

import java.util.Map;

import static org.junit.Assert.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class AuthTokenTest {
	private AuthToken at;
	private AuthToken cat;
	private AuthToken hat;
	
	private String atHostname;
	private String atEncryptionKey;
	private String atTransitionKey;
	private String atSalt;
	
	
	@Before
	public void setUp() {
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
	}
	
	@After
	public void tearDown() {}
	
	@Test 
	public void testSomeLibraryMethod() {
//      Library classUnderTest = new Library();
//      assertTrue("someLibraryMethod should return 'true'", classUnderTest.someLibraryMethod());
	}
}