# Akamai-AuthToken: Akamai Authorization Token for Java

[![Build Status](https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Java.svg?branch=master)](https://travis-ci.org/AstinCHOI/Akamai-AuthToken-Java)
[![License](http://img.shields.io/:license-apache-blue.svg)](https://github.com/AstinCHOI/Akamai-AuthToken-Java/blob/master/LICENSE)

Akamai-AuthToken is Akamai Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.  

Akamai-AuthToken supports Java 1.6+. (This is Akamai unofficial code)

<div style="text-align:center"><img src=https://github.com/AstinCHOI/akamai-asset/blob/master/authtoken/authtoken.png?raw=true /></div>


## Build
#### Gradle
```groovy
dependencies {
  compile 'io.github.astinchoi:Akamai-AuthToken-Java:0.2.6'
}
```

#### Maven
```xml
<dependency>
  <groupId>io.github.astinchoi</groupId>
  <artifactId>Akamai-AuthToken-Java</artifactId>
  <version>0.2.6</version>
  <type>pom</type>
</dependency>
```


## Example

#### URL parameter option

#### ACL(Access Control List) parameter option

## Usage

#### AuthToken Class

| Parameter | Description |
|-----------|-------------|
| token_type | Select a preset. (Not Supported Yet) |
| token_name | Parameter name for the new token. [ Default: \_\_token\_\_ ] |
| key | Secret required to generate the token. It must be hexadecimal digit string with even-length. |
| algorithm  | Algorithm to use to generate the token. (sha1, sha256, or md5) [ Default:sha256 ] |
| salt | Additional data validated by the token but NOT included in the token body. (It will be deprecated) |
| start_time | What is the start time? (Use string 'now' for the current time) |
| end_time | When does this token expire? 'end_time' overrides 'window_seconds' |
| window_seconds | How long is this token valid for? |
| field_delimiter | Character used to delimit token body fields. [ Default: ~ ] |
| escape_early | Causes strings to be 'url' encoded before being used. |
| verbose | Print all parameters. |

#### AuthToken Static Variable

#### AuthToken's Method

| Parameter | Description |
|-----------|-------------|
| url | Single URL path. |
| acl | Access control list delimited by ! [ ie. /\* ] |
| start_time <br/> end_time <br/> window_seconds | Same as Authtoken's parameters, but they overrides Authtoken's. |
| ip | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
| payload | Additional text added to the calculated digest. |
| session_id | The session identifier for single use tokens or other advanced cases. |


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