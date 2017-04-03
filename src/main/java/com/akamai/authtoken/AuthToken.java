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
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


class AuthTokenException extends Exception {
    public AuthTokenException(String msg) {
        super(msg);
    }
}


public class AuthToken {
    public static Long NOW = 0L;
    public static String ACL_DELIMITER = "!";
    
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
        this.setEscapeEarly(escapeEarly);
        this.setVerbose(verbose);
    }

    public static String join(String delimiter, String[] lists) {
        StringBuilder sb = new StringBuilder();
		for (String list : lists) {
			if (sb.length() > 0) sb.append(delimiter);
			sb.append(list);
		}
        return sb.toString();
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
        if (this.startTime == AuthToken.NOW) {
            this.startTime = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L;
        } else if(this.startTime != null && this.startTime > 0) {
            throw new AuthTokenException("startTime must be ( > 0 )");
        }

        if (this.endTime == null) {
            if (this.windowSeconds != null && this.windowSeconds > 0) {
                if (this.startTime == null) {
                    this.endTime = (Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L) +
                        this.windowSeconds;
                } else {
                    this.endTime = this.startTime + this.windowSeconds;
                }
            } else {
                throw new AuthTokenException("You must provide an expiration time or a duration window ( > 0 )");
            }
        } else if(this.endTime <= 0) {
            throw new AuthTokenException("endTime must be ( > 0 )");
        }

        if (this.startTime != null && (this.endTime <= this.startTime)) {
            throw new AuthTokenException("Token will have already expired.");
        }

        if (path == null || path == "") {
            if (isUrl) {
                throw new AuthTokenException("You must provide a URL.");
            } else {
                throw new AuthTokenException("You must provide a ARL.");
            }
        }

        if (this.verbose) {
            System.out.println("Akamai Token Generation Parameters");
            if (isUrl) {
                System.out.println("    URL             : " + path);
            } else {
                System.out.println("    ACL             : " + path);
            }
            System.out.println("    Token Type      : " + this.tokenType);
            System.out.println("    Token Name      : " + this.tokenName);
            System.out.println("    Key/Secret      : " + this.key);
            System.out.println("    Algo            : " + this.algorithm);
            System.out.println("    Salt            : " + this.salt);
            System.out.println("    IP              : " + this.ip);
            System.out.println("    Payload         : " + this.payload);
            System.out.println("    Session ID      : " + this.sessionId);
            System.out.println("    Start Time      : " + this.startTime);
            System.out.println("    Window(seconds) : " + this.windowSeconds);
            System.out.println("    End Time        : " + this.endTime);
            System.out.println("    Field Delimiter : " + this.fieldDelimiter);
            System.out.println("    ACL Delimiter   : " + AuthToken.ACL_DELIMITER);
            System.out.println("    Escape Early    : " + this.escapeEarly);
        }

        StringBuilder newToken = new StringBuilder();
        if (this.ip != null) {
            newToken.append("ip=");
            newToken.append(escapeEarly(this.ip));
            newToken.append(this.fieldDelimiter);
        }
        if (this.startTime != null) {
            newToken.append("st=");
            newToken.append(Long.toString(this.startTime));
            newToken.append(this.fieldDelimiter);
        }
        newToken.append("exp=");
        newToken.append(Long.toString(this.endTime));
        newToken.append(this.fieldDelimiter);
        
        if (!isUrl) {
            newToken.append("acl=");
            newToken.append(escapeEarly(path));
            newToken.append(this.fieldDelimiter);
        }

        if (this.sessionId != null) {
            newToken.append("id=");
            newToken.append(escapeEarly(this.sessionId));
            newToken.append(this.fieldDelimiter);
        }

        if (this.payload != null) {
            newToken.append("data=");
            newToken.append(escapeEarly(this.payload));
            newToken.append(this.fieldDelimiter);
        }

        StringBuilder hashSource = new StringBuilder(newToken);
        if (isUrl) {
            hashSource.append("url=");
            hashSource.append(escapeEarly(path));
            hashSource.append(this.fieldDelimiter);
        }

        if (this.salt != null) {
        	hashSource.append("salt=");
            hashSource.append(this.salt);
            hashSource.append(this.fieldDelimiter);
        }
        hashSource.deleteCharAt(hashSource.length() - 1);
        
        try {
            Mac hmac = Mac.getInstance(this.algorithm);
            byte[] keyBytes = DatatypeConverter.parseHexBinary(this.key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, this.algorithm);
            hmac.init(secretKey);

            byte[] hmacBytes = hmac.doFinal(hashSource.toString().getBytes());
            return newToken.toString() + "hmac=" + 
                String.format("%0" + (2*hmac.getMacLength()) +  "x", new BigInteger(1, hmacBytes));
        } catch (NoSuchAlgorithmException e) {
            throw new AuthTokenException(e.toString());
        } catch (InvalidKeyException e) {
            throw new AuthTokenException(e.toString());
        }
    }

    public String generateURLToken(String url) throws AuthTokenException {
        return generateToken(url, true);
    }

    public String generateACLToken(String acl) throws AuthTokenException {
        return generateToken(acl, false);
    }

    /***************
    * Setter/Getter
    ****************/
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
    public void setTokenName(String tokenName) throws AuthTokenException {
        if (tokenName == null || tokenName == "") {
            throw new AuthTokenException("You must provide a token name.");
        }
        this.tokenName = tokenName;
    }
    public void setKey(String key) throws AuthTokenException {
        if (key == null || key == "") {
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
    public void setStartTime(Long startTime) {
        this.startTime = startTime;
    }
    public void setEndTime(Long endTime) {
        this.endTime = endTime;
    }
    public void setWindowSeconds(Long windowSeconds) {
        this.windowSeconds = windowSeconds;
    }
    public void setFieldDelimiter(char fieldDelimiter) {
        this.fieldDelimiter = fieldDelimiter;
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
            fieldDelimiter, escapeEarly, verbose
        );
    }
}