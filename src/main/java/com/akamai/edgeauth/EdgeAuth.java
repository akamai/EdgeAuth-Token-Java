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


package com.akamai.edgeauth;

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

import static com.akamai.edgeauth.hexutils.DataTypeConverter.parseHexBinary;

/**
 * This is for returning authorization token string. You can build an instance 
 * using {@link EdgeAuthBuilder} and this can throw {@link EdgeAuthException}.
 */
public class EdgeAuth {
    /** Current time when using startTime */
    public static final Long NOW = 0L;

    /** select a preset. (Not Supported Yet) */
    private String tokenType;

    /** parameter name for the new token. */
    private String tokenName;

    /** secret required to generate the token. It must be hexadecimal digit string with even-length. */
    private String key;

    /** to use to generate the token. (sha1, sha256, or md5) */
    private String algorithm;

    /** additional data validated by the token but NOT included in the token body. It will be deprecated. */
    private String salt;

    /** IP Address to restrict this token to. Troublesome in many cases (roaming, NAT, etc) so not often used. */
    private String ip;

    /** additional text added to the calculated digest. */
    private String payload;

    /** the session identifier for single use tokens or other advanced cases. */
    private String sessionId;

    /** what is the start time? ({@code NOW} for the current time) */
    private Long startTime;

    /** when does this token expire? It overrides {@code windowSeconds} */
    private Long endTime;

    /** How long is this token valid for? */
    private Long windowSeconds;

    /** character used to delimit token body fields. */
    private char fieldDelimiter;

    /** Character used to delimit acl. */
    private char aclDelimiter;

    /** causes strings to be url encoded before being used. */
    private boolean escapeEarly;

    /** print all parameters. */
    private boolean verbose;

    public EdgeAuth(
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
            boolean verbose) throws EdgeAuthException
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

    /**
     * Makes a string array to joined a string with delimiter.
     *
     * @param delimiter {@code ACL_DELIMITER}
     * @param lists ACL(Access Control List) string array
     * @return joined string with delimiter
     * @throws EdgeAuthException EdgeAuthException
     */
    public static String join(char delimiter, String[] lists) throws EdgeAuthException {
        try {
            StringBuilder sb = new StringBuilder();
            for (String list : lists) {
                if (sb.length() > 0) sb.append(delimiter);
                sb.append(list);
            }
            return sb.toString();
        } catch(Exception e) {
            throw new EdgeAuthException(e.getMessage());
        }
    }

    /**
     * Causes strings to be 'url' encoded before being used.
     *
     * @param text string
     * @return escaped string up to {@value escapeEarly}.
     * @throws EdgeAuthException EdgeAuthException
     */
    private String escapeEarly(final String text) throws EdgeAuthException {
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
            } catch (Exception e) {
                throw new EdgeAuthException(e.getMessage());
            }
        } else {
            return text;
        }
    }

    /**
     * Generate authorization token called by
     * {@code generateURLToken} and {@code generateACLToken}
     *
     * @param path acl or acl path
     * @param isUrl is Url?
     * @return authorization token string
     * @throws EdgeAuthException EdgeAuthException
     */
    private String generateToken(String path, boolean isUrl) throws EdgeAuthException {
        Long startTime = this.startTime;
        Long endTime = this.endTime;

        if (startTime == EdgeAuth.NOW) {
            startTime = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L;
        } else if(startTime != null && startTime < 0) {
            throw new EdgeAuthException("startTime must be ( > 0 )");
        }

        if (endTime == null) {
            if (this.windowSeconds != null && this.windowSeconds > 0) {
                if (startTime == null) {
                    endTime = (Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis() / 1000L) +
                            this.windowSeconds;
                } else {
                    endTime = startTime + this.windowSeconds;
                }
            } else {
                throw new EdgeAuthException("You must provide an expiration time or a duration window ( > 0 )");
            }
        } else if(endTime <= 0) {
            throw new EdgeAuthException("endTime must be ( > 0 )");
        }

        if (startTime != null && (endTime <= startTime)) {
            throw new EdgeAuthException("Token will have already expired.");
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
            System.out.println("    ACL Delimiter   : " + this.aclDelimiter);
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
            newToken.append(startTime.toString());
            newToken.append(this.fieldDelimiter);
        }
        newToken.append("exp=");
        newToken.append(endTime.toString());
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
            byte[] keyBytes = parseHexBinary(this.key);
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, this.algorithm);
            hmac.init(secretKey);

            byte[] hmacBytes = hmac.doFinal(hashSource.toString().getBytes());
            return newToken.toString() + "hmac=" +
                    String.format("%0" + (2*hmac.getMacLength()) +  "x", new BigInteger(1, hmacBytes));
        } catch (NoSuchAlgorithmException e) {
            throw new EdgeAuthException(e.toString());
        } catch (InvalidKeyException e) {
            throw new EdgeAuthException(e.toString());
        }
    }

    /**
     * Call {@code generateToken}
     *
     * @param url a single path
     * @return authorization token string
     * @throws EdgeAuthException EdgeAuthException
     */
    public String generateURLToken(String url) throws EdgeAuthException {
        if (url == null || url == "") {
            throw new EdgeAuthException("You must provide a URL.");
        }
        return generateToken(url, true);
    }

    /**
     * Call {@code generateToken}
     *
     * @param acl access control list (String)
     * @return authorization token string
     * @throws EdgeAuthException EdgeAuthException
     */
    public String generateACLToken(String acl) throws EdgeAuthException {
        if (acl == null || acl == "") {
            throw new EdgeAuthException("You must provide an ACL.");
        }
        return generateToken(acl, false);
    }

    /**
     * Call {@code generateToken}
     *
     * @param acl access control list (String[])
     * @return authorization token string
     * @throws EdgeAuthException EdgeAuthException
     */
    public String generateACLToken(String[] acl) throws EdgeAuthException {
        if (acl == null || acl.length == 0) {
            throw new EdgeAuthException("You must provide an ACL.");
        }

        String newAcl = join(this.getAclDelimiter(), acl);
        return generateToken(newAcl, false);
    }

    /**
     * @param tokenType tokenType
     */
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * @param tokenName tokenName
     * @throws EdgeAuthException EdgeAuthException
     */
    public void setTokenName(String tokenName) throws EdgeAuthException {
        if (tokenName == null || tokenName == "") {
            throw new EdgeAuthException("You must provide a token name.");
        }
        this.tokenName = tokenName;
    }

    /**
     * @param key key
     * @throws EdgeAuthException EdgeAuthException
     */
    public void setKey(String key) throws EdgeAuthException {
        if (key == null || key == "") {
            throw new EdgeAuthException("You must provide a secret in order to generate a new token.");
        }
        this.key = key;
    }

    /**
     * @param algorithm algorithm
     * @throws EdgeAuthException EdgeAuthException
     */
    public void setAlgorithm(String algorithm) throws EdgeAuthException {
        if (algorithm.equalsIgnoreCase("sha256"))
            this.algorithm = "HmacSHA256";
        else if (algorithm.equalsIgnoreCase("sha1"))
            this.algorithm = "HmacSHA1";
        else if (algorithm.equalsIgnoreCase("md5"))
            this.algorithm = "HmacMD5";
        else
            throw new EdgeAuthException("Unknown Algorithm");
    }

    /**
     * @param salt salt
     */
    public void setSalt(String salt) {
        this.salt = salt;
    }

    /**
     * @param ip ip
     */
    public void setIp(String ip) {
        this.ip = ip;
    }

    /**
     * @param payload payload
     */
    public void setPayload(String payload) {
        this.payload = payload;
    }

    /**
     * @param sessionId sessionId
     */
    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * @param startTime startTime
     */
    public void setStartTime(Long startTime) {
        this.startTime = startTime;
    }

    /**
     * @param endTime endTime
     */
    public void setEndTime(Long endTime) {
        this.endTime = endTime;
    }

    /**
     * @param windowSeconds windowSeconds
     */
    public void setWindowSeconds(Long windowSeconds) {
        this.windowSeconds = windowSeconds;
    }

    /**
     * @param aclDelimiter aclDelimiter
     */
    public void setAclDelimiter(char aclDelimiter) {
        this.aclDelimiter = aclDelimiter;
    }

    /**
     * @param fieldDelimiter fieldDelimiter
     */
    public void setFieldDelimiter(char fieldDelimiter) {
        this.fieldDelimiter = fieldDelimiter;
    }

    /**
     * @param escapeEarly escapeEarly
     */
    public void setEscapeEarly(boolean escapeEarly) {
        this.escapeEarly = escapeEarly;
    }
    /**
     * @param verbose verbose
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * @return tokenType
     */
    public String getTokenType() {
        return this.tokenType;
    }
    /**
     * @return tokenName
     */
    public String getTokenName() {
        return this.tokenName;
    }

    /**
     * @return key
     */
    public String getKey() {
        return this.key;
    }

    /**
     * @return algorithm
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * @return salt
     */
    public String getSalt() {
        return this.salt;
    }

    /**
     * @return ip
     */
    public String getIp() {
        return this.ip;
    }

    /**
     * @return payload
     */
    public String getPayload() {
        return this.payload;
    }

    /**
     * @return sessionId
     */
    public String getSessionId() {
        return this.sessionId;
    }

    /**
     * @return startTime
     */
    public Long getStartTime() {
        return this.startTime;
    }

    /**
     * @return endTime
     */
    public Long getEndTime() {
        return this.endTime;
    }

    /**
     * @return windowSeconds
     */
    public Long getwindowSeconds() {
        return this.windowSeconds;
    }

    /**
     * @return fieldDelimiter
     */
    public char getFieldDelimiter() {
        return this.fieldDelimiter;
    }

    /**
     * @return aclDelimiter
     */
    public char getAclDelimiter() {
        return this.aclDelimiter;
    }

    /**
     * @return escapeEarly
     */
    public boolean isEscapeEarly() {
        return this.escapeEarly;
    }

    /**
     * @return verbose
     */
    public boolean isVerbose() {
        return this.verbose;
    }
}
