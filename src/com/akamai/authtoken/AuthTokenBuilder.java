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


public class AuthTokenBuilder {
    private String tokenType = null;
    private String tokenName = "__token__";
    private String key = null;
    private String algorithm = "sha256";
    private String startTime = null;
    private String endTime = null;
    private String windowSeconds = null;
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
    public AuthTokenBuilder startTime(String startTime) {
        this.startTime = startTime;
        return this;
    }
    public AuthTokenBuilder endTime(String endTime) {
        this.endTime = endTime;
        return this;
    }
    public AuthTokenBuilder windowSeconds(String windowSeconds) {
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

    public AuthToken build() {
        return new AuthToken(
            tokenType, tokenName, key, algorithm, 
            startTime, endTime, windowSeconds, 
            fieldDelimiter, aclDelimiter, 
            escapeEarly, verbose 
        );
    }
}