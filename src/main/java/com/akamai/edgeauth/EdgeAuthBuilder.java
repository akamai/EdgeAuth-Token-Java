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


/**
 * To build an {@link EdgeAuth} instance.
 */
public class EdgeAuthBuilder {

    /** select a preset. (Not Supported Yet) */
    private String tokenType = null;

    /** parameter name for the new token. */
    private String tokenName = "__token__";

    /** secret required to generate the token. It must be hexadecimal digit string with even-length. */
    private String key = null;

    /** to use to generate the token. (sha1, sha256, or md5) */
    private String algorithm = "sha256";

    /** additional data validated by the token but NOT included in the token body. It will be deprecated. */
    private String salt = null;

    /** IP Address to restrict this token to. Troublesome in many cases (roaming, NAT, etc) so not often used. */
    private String ip = null;

    /** additional text added to the calculated digest. */
    private String payload = null;

    /** the session identifier for single use tokens or other advanced cases. */
    private String sessionId = null;

    /** what is the start time? */
    private Long startTime = null;

    /** when does this token expire? It overrides {@code windowSeconds} */
    private Long endTime = null;

    /** How long is this token valid for? */
    private Long windowSeconds = null;

    /** character used to delimit token body fields. */
    private char fieldDelimiter = '~';

    /** Character used to delimit acl. */
    private char aclDelimiter = '!';

    /** causes strings to be url encoded before being used. */
    private boolean escapeEarly = false;

    /** print all parameters. */
    private boolean verbose = false;

    /**
     * @param tokenType tokenType
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder tokenType(String tokenType) {
        this.tokenType = tokenType;
        return this;
    }

    /**
     * @param tokenName tokenName
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder tokenName(String tokenName) {
        this.tokenName = tokenName;
        return this;
    }

    /**
     * @param key key
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder key(String key) {
        this.key = key;
        return this;
    }

    /**
     * @param algorithm algorithm
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * @param salt salt
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder salt(String salt) {
        this.salt = salt;
        return this;
    }

    /**
     * @param ip ip
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder ip(String ip) {
        this.ip = ip;
        return this;
    }

    /**
     * @param payload payload
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder payload(String payload) {
        this.payload = payload;
        return this;
    }

    /**
     * @param sessionId sessionId
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder sessionId(String sessionId) {
        this.sessionId = sessionId;
        return this;
    }

    /**
     * @param startTime startTime
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder startTime(long startTime) {
        this.startTime = startTime;
        return this;
    }

    /**
     * @param endTime End Time
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder endTime(long endTime) {
        this.endTime = endTime;
        return this;
    }

    /**
     * @param windowSeconds Window Seconds
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder windowSeconds(long windowSeconds) {
        this.windowSeconds = windowSeconds;
        return this;
    }

    /**
     * @param fieldDelimiter Field Delimiter
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder fieldDelimiter(char fieldDelimiter) {
        this.fieldDelimiter = fieldDelimiter;
        return this;
    }

    /**
     * @param aclDelimiter ACL Delimiter
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder aclDelimiter(char aclDelimiter) {
        this.aclDelimiter = aclDelimiter;
        return this;
    }

    /**
     * @param escapeEarly Escape Early
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder escapeEarly(boolean escapeEarly) {
        this.escapeEarly = escapeEarly;
        return this;
    }

    /**
     * @param verbose verbose
     * @return EdgeAuthBuilder
     */
    public EdgeAuthBuilder verbose(boolean verbose) {
        this.verbose = verbose;
        return this;
    }

    /**
     * build an {@link EdgeAuth} instance
     *
     * @return {@link EdgeAuth}
     * @throws EdgeAuthException EdgeAuthException
     */
    public EdgeAuth build() throws EdgeAuthException {
        return new EdgeAuth(
                tokenType, tokenName,
                key, algorithm, salt,
                ip, payload, sessionId,
                startTime, endTime, windowSeconds,
                fieldDelimiter, aclDelimiter, escapeEarly, verbose
        );
    }
}