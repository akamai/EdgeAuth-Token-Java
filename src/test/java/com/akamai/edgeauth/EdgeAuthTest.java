package com.akamai.edgeauth;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Instant;
import java.util.regex.Pattern;

// Test content taken from https://github.com/mobilerider/EdgeAuth-Token-Golang/blob/master/edgeauth_test.go
public class EdgeAuthTest {

    private static final String sampleKey = "52a152a152a152a152a152a152a1";
    private static final String samplePath = "/this/is/a/test";

    @Test
    public void testGenerateAclToken() throws EdgeAuthException {
        EdgeAuth ea = new EdgeAuthBuilder().algorithm("SHA256").key(sampleKey).startTime(Instant.now().toEpochMilli()/1000).windowSeconds(300).build();
        String token = ea.generateACLToken(samplePath);

        String[] fields = token.split(String.valueOf(ea.getFieldDelimiter()));
        Assert.assertEquals("ACL token should consists of 4 parts: " + token, 4, fields.length);

        String expectedStart = "st=" + ea.getStartTime();
        Assert.assertEquals("Start field does not match", expectedStart, fields[0]);

        String expectedExpire = "exp=" + (ea.getStartTime() + ea.getWindowSeconds());
        Assert.assertEquals("Expire field does not match", expectedExpire, fields[1]);

        String expectedAcl = "acl=.+";
        Assert.assertTrue("ACL field does not match: " + fields[2], Pattern.matches(expectedAcl, fields[2]));

        String expectedHmac = "hmac=[a-f0-9]{64}";
        Assert.assertTrue("Hmac field does not match: " + fields[3], Pattern.matches(expectedHmac, fields[3]));
    }

    @Test
    public void testGenerateUrlToken() throws EdgeAuthException {
        EdgeAuth ea = new EdgeAuthBuilder().algorithm("SHA256").key(sampleKey).startTime(Instant.now().toEpochMilli()/1000).windowSeconds(300).build();
        String token = ea.generateURLToken(samplePath);

        String[] fields = token.split(String.valueOf(ea.getFieldDelimiter()));
        Assert.assertEquals("URL token should consists of 3 parts: " + token, 3, fields.length);

        String expectedStart = "st=" + ea.getStartTime();
        Assert.assertEquals("Start field does not match", expectedStart, fields[0]);

        String expectedExpire = "exp=" + (ea.getStartTime() + ea.getWindowSeconds());
        Assert.assertEquals("Expire field does not match", expectedExpire, fields[1]);

        String expectedHmac = "hmac=[a-f0-9]{64}";
        Assert.assertTrue("Hmac field does not match: " + fields[2], Pattern.matches(expectedHmac, fields[2]));
    }

    @Rule
    public ExpectedException exceptionRule = ExpectedException.none();

    @Test
    public void testGenerateTokenWithInvalidStartAndEndDate() throws EdgeAuthException {
        exceptionRule.expect(EdgeAuthException.class);
        exceptionRule.expectMessage("Token will have already expired.");

        long startTimeSeconds = Instant.now().toEpochMilli() / 1000;
        EdgeAuth ea = new EdgeAuthBuilder().algorithm("SHA256").key(sampleKey)
                .startTime(startTimeSeconds + 300)
                .endTime(startTimeSeconds).build();
        ea.generateURLToken(samplePath);

    }

}