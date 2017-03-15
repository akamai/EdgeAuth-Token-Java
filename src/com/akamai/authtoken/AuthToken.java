/*
* Author: Astin Choi <achoi@akamai.com>

* Copyright 2017 Akamai Technologies http://developer.akamai.com.

* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.akamai.authtoken;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



class AuthTokenException extends Exception {
    public AuthTokenException(String msg) {
        super(msg);
    }
}


public class AuthToken {
    public static Long NOW = 0L;

    private String tokenType;
    private String tokenName;
    private String key;
    private String algorithm;
    private String salt;
    private String ip;
    private String payload;
    private String sessionId;
    private Long startTime;
    private Long endTime;
    private Long windowSeconds;
    private char fieldDelimiter;
    private char aclDelimiter;
    private boolean escapeEarly;
    private boolean verbose;

    public AuthToken(
        String tokenType,
        String tokenName,
        String key,
        String algorithm,
        String salt,
        String ip, 
        String payload,
        String sessionId,
        Long startTime,
        Long endTime,
        Long windowSeconds,
        char fieldDelimiter,
        char aclDelimiter,
        boolean escapeEarly,
        boolean verbose) throws AuthTokenException
    {
        this.setTokenType(tokenType);
        this.setTokenName(tokenName);
        this.setKey(key);
        this.setAlgorithm(algorithm);
        this.setSalt(salt);
        this.setIp(ip);
        this.setPayload(payload);
        this.setSessionId(sessionId);
        this.setStartTime(startTime);
        this.setEndTime(endTime);
        this.setWindowSeconds(windowSeconds);
        this.setFieldDelimiter(fieldDelimiter);
        this.setAclDelimiter(aclDelimiter);
        this.setEscapeEarly(escapeEarly);
        this.setVerbose(verbose);
    }

    private String escapeEarly(final String text) {
        if (this.escapeEarly == true) {
            try {
                StringBuilder newText = new StringBuilder(URLEncoder.encode(text, "UTF-8"));
                Pattern pattern = Pattern.compile("%..");
                Matcher matcher = pattern.matcher(newText);
                String tmpText;
                while (matcher.find()) {
                    tmpText = newText.substring(matcher.start(), matcher.end()).toLowerCase();
                    newText.replace(matcher.start(), matcher.end(), tmpText);
                }
                return newText.toString();
            } catch (UnsupportedEncodingException e) {
                return text;
            }
        } else {
            return text;
        }
    }
    private String generateToken(String path, boolean isUrl) throws AuthTokenException {
        if (this.startTime == this.NOW) {
            this.startTime = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L;
        }

        if (this.endTime == null) {
            if (this.windowSeconds > 0) {
                if (this.startTime == null) {
                    this.endTime = (Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L) +
                        this.windowSeconds;
                } else {
                    this.endTime = this.startTime + this.windowSeconds;
                }
            } else {
                throw new AuthTokenException("You must provide an expiration time or a duration window..");
            }
        }

        if (this.startTime != null && (this.endTime <= this.startTime)) {
            throw new AuthTokenException("Token will have already expired.");
        }


        return "";
    }

    public String generateURLToken(String url) throws AuthTokenException {
        return generateToken(url, true);
    }

    public String generateACLToken(String acl) throws AuthTokenException {
        return generateToken(acl, false);
    }

    // Temp to test
    public static void main(String[] args) throws AuthTokenException {
        
        AuthToken at = new AuthTokenBuilder()
                .key("something")
                .windowSeconds(500)
                .escapeEarly(true)
                .build();
        
        System.out.println(at.key);
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public void setTokenName(String tokenName) throws AuthTokenException {
        if (tokenName.isEmpty()) {
            throw new AuthTokenException("You must provide a token name.");
        }
        this.tokenName = tokenName;
    }
    public void setKey(String key) throws AuthTokenException {
        if (key.isEmpty()) {
            throw new AuthTokenException("You must provide a secret in order to generate a new token.");
        }
        this.key = key;
    }
    public void setAlgorithm(String algorithm) throws AuthTokenException {
        if (!algorithm.equalsIgnoreCase("md5") &&
        !algorithm.equalsIgnoreCase("sha1") &&
        !algorithm.equalsIgnoreCase("sha256")) {
            throw new AuthTokenException("Unknown Algorithm");
        }
        if (algorithm.equalsIgnoreCase("sha256"))
            this.algorithm = "HmacSHA256";
        else if (algorithm.equalsIgnoreCase("sha1"))
            this.algorithm = "HmacSHA1";
        else if (algorithm.equalsIgnoreCase("md5"))
            this.algorithm = "HmacMD5";
    }
    public void setSalt(String salt) {
        this.salt = salt;
    }
    public void setIp(String ip) {
        this.ip = ip;
    }
    public void setPayload(String payload) {
        this.payload = payload;
    }
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }
    public void setEndTime(long endTime) {
        this.endTime = endTime;
    }
    public void setWindowSeconds(long windowSeconds) {
        this.windowSeconds = windowSeconds;
    }
    public void setFieldDelimiter(char fieldDelimiter) {
        this.fieldDelimiter = fieldDelimiter;
    }
    public void setAclDelimiter(char aclDelimiter) {
        this.aclDelimiter = aclDelimiter;
    }
    public void setEscapeEarly(boolean escapeEarly) {
        this.escapeEarly = escapeEarly;
    }
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }
    public String getTokenType() {
        return this.tokenType;
    }
    public String getTokenName() {
        return this.tokenName;
    }
    public String getKey() {
        return this.key;
    }
    public String getAlgorithm() {
        return this.algorithm;
    }
    public String getSalt() {
        return this.salt;
    }
    public String getIp() {
        return this.ip;
    }
    public String getPayload() {
        return this.payload;
    }
    public String getSessionId() {
        return this.sessionId;
    }
    public long getStartTime() {
        return this.startTime;
    }
    public long getEndTime() {
        return this.endTime;
    }
    public long getwindowSeconds() {
        return this.windowSeconds;
    }
    public char getFieldDelimiter() {
        return this.fieldDelimiter;
    }
    public char getAclDelimiter() {
        return this.aclDelimiter;
    }
    public boolean isEscapeEarly() {
        return this.escapeEarly;
    }
    public boolean isVerbose() {
        return this.verbose;
    }
}


class AuthTokenBuilder {
    private String tokenType = null;
    private String tokenName = "__token__";
    private String key = null;
    private String algorithm = "sha256";
    private String salt = null;
    private String ip = null;
    private String payload = null;
    private String sessionId = null;
    private Long startTime = null;
    private Long endTime = null;
    private Long windowSeconds = null;
    private char fieldDelimiter = '~';
    private char aclDelimiter = '!';
    private boolean escapeEarly = false;
    private boolean verbose = false;


    public AuthTokenBuilder tokenType(String tokenType) {
        this.tokenType = tokenType;
        return this;
    }
    public AuthTokenBuilder tokenName(String tokenName) {
        this.tokenName = tokenName;
        return this;
    }
    public AuthTokenBuilder key(String key) {
        this.key = key;
        return this;
    }
    public AuthTokenBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }
    public AuthTokenBuilder salt(String salt) {
        this.salt = salt;
        return this;
    }
    public AuthTokenBuilder ip(String ip) {
        this.ip = ip;
        return this;
    }
    public AuthTokenBuilder payload(String payload) {
        this.payload = payload;
        return this;
    }
    public AuthTokenBuilder sessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }
    public AuthTokenBuilder startTime(long startTime) {
        this.startTime = startTime;
        return this;
    }
    public AuthTokenBuilder endTime(long endTime) {
        this.endTime = endTime;
        return this;
    }
    public AuthTokenBuilder windowSeconds(long windowSeconds) {
        this.windowSeconds = windowSeconds;
        return this;
    }
    public AuthTokenBuilder fieldDelimiter(char fieldDelimiter) {
        this.fieldDelimiter = fieldDelimiter;
        return this;
    }
    public AuthTokenBuilder aclDelimiter(char aclDelimiter) {
        this.aclDelimiter = aclDelimiter;
        return this;
    }
    public AuthTokenBuilder escapeEarly(boolean escapeEarly) {
        this.escapeEarly = escapeEarly;
        return this;
    }
    public AuthTokenBuilder verbose(boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    public AuthToken build() throws AuthTokenException {
        return new AuthToken(
            tokenType, tokenName,
            key, algorithm, salt,
            ip, payload, sessionId,
            startTime, endTime, windowSeconds,
            fieldDelimiter, aclDelimiter,
            escapeEarly, verbose
        );
    }
}

