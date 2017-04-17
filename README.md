# Akamai-AuthToken: Akamai Authorization Token for Java

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.github.astinchoi/Akamai-AuthToken-Java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.github.astinchoi/Akamai-AuthToken-Java)
[![Javadoc](https://javadoc-emblem.rhcloud.com/doc/io.github.astinchoi/Akamai-AuthToken-Java/badge.svg)](http://www.javadoc.io/doc/io.github.astinchoi/Akamai-AuthToken-Java)
[![Build Status](https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Java.svg?branch=master)](https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Java)
[![License](http://img.shields.io/:license-apache-blue.svg)](https://github.com/AstinCHOI/Akamai-AuthToken-Java/blob/master/LICENSE)

Akamai-AuthToken is Akamai Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.

Akamai-AuthToken supports Java 1.6+. (This is Akamai unofficial code)

<div style="text-align:center"><img src=https://github.com/AstinCHOI/akamai-asset/blob/master/authtoken/authtoken.png?raw=true /></div>


## Build
[Click Here](https://maven-badges.herokuapp.com/maven-central/io.github.astinchoi/Akamai-AuthToken-Java)


## Example
```java
import io.github.astinchoi.authtoken.AuthToken;
import io.github.astinchoi.authtoken.AuthTokenBuilder;
import io.github.astinchoi.authtoken.AuthTokenException;


public class AuthTokenExample {
  public static void main(String[] args) {
    String hostname = "YourAkamaizedHostname";
    String encrpytionKey = "YourEncryptionKey";
    long duration = 500L;

    // => Option Code
  }
}
```

#### URL parameter option
```java
try {
  AuthToken at = new AuthTokenBuilder()
      .key(encrpytionKey)
      .windowSeconds(duration)
      .escapeEarly(true)
      .build();

  /******** 
  1) Cookie 
  *********/
  String path = "/akamai/authtoken";
  String token = at.generateURLToken(path);
  String url = String.format("http(s)://%s%s", hostname, path);
  String cookie = String.format("%s=%s", at.getTokenName(), token);
  // => Link or Request "url" /w "cookie"

  /************** 
  2) Query String 
  ***************/
  String path = "/akamai/authtoken";
  String token = at.generateURLToken(path);
  String url = String.format("http(s)://%s%s?%s=%s", hostname, path,
    at.getTokenName(), token);
  // => Link or Request "url" /w Query string
} catch (AuthTokenException e) {
  e.printStackTrace();
}
```
```java
// In the URL option,
// It depends on turning on/off 'Escape token input' in the property manager. 
// on: escapeEarly(true) / off: escapeEarly(false)

// In the [2) Query String], 
// it's only okay for 'Ignore query string' option on

// If you want to 'Ignore query string' off using query string as your token, 
// Please contact your Akamai representative.
```

#### ACL(Access Control List) parameter option
```java
try {
  AuthToken at = new AuthTokenBuilder()
      .key(encrpytionKey)
      .windowSeconds(duration)
      .build();

  /******************
  3) Header using '*' 
  *******************/
  String acl = "/akamai/authtoken/list/*"; //*/
  String token = at.generateACLToken(acl);
  String url = String.format("http(s)://%s%s", hostname, "/akamai/authtoken/list/something");
  String header = String.format("%s: %s", at.getTokenName(), token);
  // => Link or Request "url" /w "header"

  /************************* 
  4) Cookie Delimited by '!'
  **************************/
  String acl2[] = { "/akamai/authtoken", "/akamai/authtoken/list/*" };
  String token = at.generateACLToken(AuthToken.join(AuthToken.ACL_DELIMITER, acl2));
  String url = String.format("http(s)://%s%s", hostname, "/akamai/authtoken/list/something2");
  String cookie = String.format("%s=%s", at.getTokenName(), token);
  // => Link or Request "url" /w "cookie"
} catch (AuthTokenException e) {
  e.printStackTrace();
}
```
```java
// In the ACL option,
// It doesn't matter turning on/off 'Escape token input' in the property manager
// but you should keep escapeEarly(false) as default
```


## Usage

#### AuthToken, AuthTokenBuilder Class
| Parameter | Description |
|-----------|-------------|
| tokenType | Select a preset. (Not Supported Yet) |
| tokenName | Parameter name for the new token. [ Default: \_\_token\_\_ ] |
| key | Secret required to generate the token. It must be hexadecimal digit string with even-length. |
| algorithm  | Algorithm to use to generate the token. (sha1, sha256, or md5) [ Default:sha256 ] |
| salt | Additional data validated by the token but NOT included in the token body. (It will be deprecated) |
| ip | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
| payload | Additional text added to the calculated digest. |
| sessionId | The session identifier for single use tokens or other advanced cases. |
| starTime | What is the start time? (Use 'AuthToken.NOW' for the current time) |
| endTime | When does this token expire? 'endTime' overrides 'windowSeconds' |
| windowSeconds | How long is this token valid for? |
| fieldDelimiter | Character used to delimit token body fields. [ Default: ~ ] |
| escapeEarly | Causes strings to be 'url' encoded before being used. |
| verbose | Print all parameters. |

#### AuthToken Static Variable
```java
public static final Long NOW = 0L; // When using startTime
public static String ACL_DELIMITER = "!"; // When using ACL
```


#### AuthToken's Method
| Method | Description |
|--------|-------------|
| generateURLToken(String url) | Single URL path. |
| generateACLToken(String acl) | Access control list delimited by ! [ ie. /\* ] |

Returns the authorization token string.


## License

Copyright 2017 Akamai Technologies, Inc.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.