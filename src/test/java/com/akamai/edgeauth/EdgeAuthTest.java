package com.akamai.edgeauth;

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


public class EdgeAuthTest {
    private static long DEFAULT_WINDOW_SECONDS = 500L;

    private EdgeAuth ea;
    private EdgeAuth cea;
    private EdgeAuth hea;

    private String eaHostname;
    private String eaEncryptionKey;
    private String eaTransitionKey;
    private String eaSalt;

    @Before
    public void setUp() throws EdgeAuthException {
        Map<String, String> env = System.getenv();
        if (env.get("TEST_MODE") != null && env.get("TEST_MODE").equalsIgnoreCase("travis")) {
            this.eaHostname = env.get("EA_HOSTNAME");
            this.eaEncryptionKey = env.get("EA_ENCRYPTION_KEY");
            this.eaTransitionKey = env.get("EA_TRANSITION_KEY");
            this.eaSalt = env.get("EA_SALT_KEY");
        } else {
            try {
                Class<?> Secret = Class.forName("com.akamai.edgeauth.Secret");

                this.eaHostname = Secret.getField("EA_HOSTNAME").get("EA_HOSTNAME").toString();
                this.eaEncryptionKey = Secret.getField("EA_ENCRYPTION_KEY").get("EA_ENCRYPTION_KEY").toString();
                this.eaTransitionKey = Secret.getField("EA_TRANSITION_KEY").get("EA_TRANSITION_KEY").toString();
                this.eaSalt = Secret.getField("EA_SALT_KEY").get("EA_SALT_KEY").toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        this.ea = new EdgeAuthBuilder()
                .key(this.eaEncryptionKey)
                .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                .build();
        this.cea = new EdgeAuthBuilder()
                .key(this.eaEncryptionKey)
                .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                .algorithm("sha1")
                .build();
        this.hea = new EdgeAuthBuilder()
                .key(this.eaEncryptionKey)
                .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                .algorithm("md5")
                .build();
    }

    @After
    public void tearDown() {}

    private void tokenSetting(char ttype, boolean escapeEarly, boolean transition) throws EdgeAuthException {
        EdgeAuth t = null;

        if (ttype == 'q') {
            t = this.ea;
        } else if(ttype == 'c') {
            t = this.cea;
        } else if(ttype == 'h') {
            t = this.hea;
        }

        if (transition) {
            t.setKey(this.eaTransitionKey);
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

    private void queryAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws EdgeAuthException, UnknownHostException, IOException {
        this.tokenSetting('q', escapeEarly, transition);

        ea.setPayload(payload);
        ea.setSessionId(sessionId);

        String token = "";
        if (isUrl) {
            token = this.ea.generateURLToken(path);
        } else {
            token = this.ea.generateACLToken(path);
        }

        String qs = this.ea.getTokenName() + "=" + token;
        String statusCode = EdgeAuthTest.requests(this.eaHostname, path, qs, null);
        assertEquals(expacted, statusCode);
    }

    private void cookieAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws EdgeAuthException, UnknownHostException, IOException {
        this.tokenSetting('c', escapeEarly, transition);

        cea.setPayload(payload);
        cea.setSessionId(sessionId);

        String token = "";
        if (isUrl) {
            token = this.cea.generateURLToken(path);
        } else {
            token = this.cea.generateACLToken(path);
        }

        String cookie = "Cookie: " + this.cea.getTokenName() + "=" + token;
        String statusCode = EdgeAuthTest.requests(this.eaHostname, path, null, cookie);
        assertEquals(expacted, statusCode);
    }

    private void headerAssertEqual(String path, String expacted, boolean escapeEarly, boolean transition, String payload, String sessionId, boolean isUrl) throws EdgeAuthException, UnknownHostException, IOException {
        this.tokenSetting('h', escapeEarly, transition);

        hea.setPayload(payload);
        hea.setSessionId(sessionId);

        String token = "";
        if (isUrl) {
            token = this.hea.generateURLToken(path);
        } else {
            token = this.hea.generateACLToken(path);
        }

        String header = this.hea.getTokenName() + ":" + token;
        String statusCode = EdgeAuthTest.requests(this.eaHostname, path, null, header);
        assertEquals(expacted, statusCode);
    }

    private void testCaseSet(String queryPath, String cookiePath, String headerPath, boolean escapeEarly, boolean isUrl) throws UnknownHostException, EdgeAuthException, IOException {
        // General Test
        this.queryAssertEqual(queryPath, "404", escapeEarly, false, null, null, isUrl);
        this.cookieAssertEqual(cookiePath, "404", escapeEarly, false, null, null, isUrl);
        this.headerAssertEqual(headerPath, "404", escapeEarly, false, null, null, isUrl);

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
    public void test_url_escape_on__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", true, true);
    }

    @Test
    public void test_url_escape_off__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q_ignore", "/c_ignore", "/h_ignore", false, true);
    }

    @Test
    public void test_url_escape_on__ignoreQuery_no() throws UnknownHostException, EdgeAuthException, IOException {
        String queryPath = "/q_escape";
        String cookiePath = "/c_escape";
        String headerPath = "/h_escape";
        this.testCaseSet(queryPath, cookiePath, headerPath, true, true);

        String queryString = "?foo=bar&hello=world"; // # ( ) ... // URLEncoder.encode("", "UTF-8");
        this.queryAssertEqual(queryPath + queryString, "404", true, false, null, null, true);
        this.cookieAssertEqual(cookiePath + queryString, "404", true, false, null, null, true);
        this.headerAssertEqual(headerPath + queryString, "404", true, false, null, null, true);
    }

    @Test
    public void test_url_escape_off__ignoreQuery_no() throws UnknownHostException, EdgeAuthException, IOException {
        String queryPath = "/q";
        String cookiePath = "/c";
        String headerPath = "/h";
        this.testCaseSet(queryPath, cookiePath, headerPath, false, true);

        String queryString = "?foo=bar&hello=world"; // ...
        this.queryAssertEqual(queryPath + queryString, "404", false, false, null, null, true);
        this.cookieAssertEqual(cookiePath + queryString, "404", false, false, null, null, true);
        this.headerAssertEqual(headerPath + queryString, "404", false, false, null, null, true);
    }

    // Doesn't support for the salt
    // @Test
    // public void test_url_query_escape_on__ignore_yes_with_salt() throws UnknownHostException, EdgeAuthException, IOException {
    // 	String querySaltPath = "/salt";
    // 	EdgeAuth eas = new EdgeAuthBuilder()
    // 			.key(this.eaEncryptionKey)
    // 			.salt(this.eaSalt)
    // 			.windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
    // 			.escapeEarly(true)
    // 			.build();
    // 	String token = eas.generateURLToken(querySaltPath);
    // 	String qs = eas.getTokenName() + "=" + token;
    // 	String statusCode = EdgeAuthTest.requests(this.eaHostname, querySaltPath, qs, null);
    // 	assertEquals("404", statusCode);
    // }

    /**********
     * ACL TEST
     **********/
    @Test
    public void test_acl_escape_on__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", false, false);
    }

    @Test
    public void test_acl_escape_off__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q_ignore", "/c_ignore", "/h_ignore", false, false);
    }

    @Test
    public void test_acl_escape_on__ignoreQuery_no() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q_escape", "/c_escape", "/h_escape", false, false);
    }

    @Test
    public void test_acl_escape_off__ignoreQuery_no() throws UnknownHostException, EdgeAuthException, IOException {
        this.testCaseSet("/q", "/c", "/h", false, false);
    }

    @Test
    public void test_acl_asta_escape_on__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        EdgeAuth eaa = new EdgeAuthBuilder()
                .key(this.eaEncryptionKey)
                .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                .build();
        String token = eaa.generateACLToken("/q_escape_ignore/*");
        String qs = eaa.getTokenName() + "=" + token;
        String statusCode = EdgeAuthTest.requests(this.eaHostname, "/q_escape_ignore/hello", qs, null);
        assertEquals("404", statusCode);
    }

    @Test
    public void test_acl_deli_escape_on__ignoreQuery_yes() throws UnknownHostException, EdgeAuthException, IOException {
        EdgeAuth ead = new EdgeAuthBuilder()
                .key(this.eaEncryptionKey)
                .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                .build();
        String acl[] = { "/q_escape_ignore", "/q_escape_ignore/*" };

        // For Java 8=
        // String token = ead.generateACLToken(String.join(EdgeAuth.ACL_DELIMITER, acl));

        // For All
        // String token = ead.generateACLToken(EdgeAuth.join(EdgeAuth.ACL_DELIMITER, acl));

        String token = ead.generateACLToken(acl);
        String qs = ead.getTokenName() + "=" + token;
        String statusCode = EdgeAuthTest.requests(this.eaHostname, "/q_escape_ignore", qs, null);
        assertEquals("404", statusCode);

        statusCode = EdgeAuthTest.requests(this.eaHostname, "/q_escape_ignore/world/", qs, null);
        assertEquals("404", statusCode);

        assertEquals(null, ead.getStartTime());
        assertEquals(null, ead.getEndTime());
    }

    @Test
    public void test_exceptions() {
        try {
            EdgeAuth eat = new EdgeAuthBuilder()
                    // .key(this.eaEncryptionKey)
                    .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                    .build();
        } catch(EdgeAuthException eae) {
            assertEquals(eae.getMessage(), "You must provide a secret in order to generate a new token.");
        }
        try {
            EdgeAuth eat = new EdgeAuthBuilder()
                    .key(this.eaEncryptionKey)
                    // .windowSeconds(EdgeAuthTest.DEFAULT_WINDOW_SECONDS)
                    .build();
        } catch(EdgeAuthException eae) {
            assertEquals(eae.getMessage(), "You must provide an expiration time or a duration window ( > 0 )");
        }
    }
}