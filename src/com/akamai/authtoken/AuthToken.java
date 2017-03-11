/*
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


class AuthToken {
    private String token_type = null;
    private String token_name = "__token__";
    private String key = null;
    private String algorithm = "sha256";
    private String start_time = null;
    private String end_time = null;
    private String window_seconds = null;
    private char field_delimiter = '~';
    private char acl_delimiter = '!';
    private boolean escape_early = false;
    private boolean verbose = false;

    public AuthToken() {

    }
}