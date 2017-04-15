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


package io.github.astinchoi.authtoken;


public class AuthTokenBuilder {
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