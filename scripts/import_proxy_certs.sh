#!/bin/sh
#
# Copyright (C) 2020 Bosch.IO GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# License-Filename: LICENSE

if [ -z "$https_proxy" ]; then
    echo "Skipping the import of certificates as no HTTPS proxy is set."
    exit
fi

CONNECT_SERVER="jcenter.bintray.com:443"

TEMP_DIR="$(mktemp -d)"
FILE="$TEMP_DIR/proxy.crt"
FILE_PREFIX="proxy-"

REGEX_BEGIN="/^-----BEGIN CERTIFICATE-----$/"
REGEX_END="/^-----END CERTIFICATE-----$"

# Strip a leading protocol as "openssl s_client" expects none.
PROXY=${https_proxy#*//}
# Strip a trailing slash as "openssl s_client" expects none.
PROXY=${PROXY%%/}

# Strip authentication info as "openssl s_client" cannot handle any.
PROXY_NO_AUTH=${PROXY#*@}

if [ "$PROXY_NO_AUTH" != "$PROXY" ]; then
    echo "This script cannot handle proxies that require authentication."
    exit
fi

# Pick a server to connect to that is used during the Gradle build, and which reports the proxy's certificate instead of
# its own.
echo "Getting the certificates for proxy $PROXY_NO_AUTH..."

openssl s_client -showcerts -proxy $PROXY_NO_AUTH -connect $CONNECT_SERVER | \
    sed -n "$REGEX_BEGIN,$REGEX_END/p" > $FILE

if [ ! -f "$FILE" ]; then
    echo "Failed getting the certificates, no output file was created."
    exit
fi

# Split the potentially multiple certificates into multiple files to avoid only the first certificate being imported.
echo "Splitting proxy certificates to separate files..."
csplit -f $FILE_PREFIX -b "%02d.crt" -z $FILE "$REGEX_BEGIN" "{*}"

# Import the proxy certificates into the JVM keystore.
KEYTOOL=$(realpath $(command -v keytool))

for KEYSTORE_CANDIDATE in "$(realpath -m $(dirname $KEYTOOL)/../lib/security/cacerts)" "$(realpath -m $(dirname $KEYTOOL)/../jre/lib/security/cacerts)"; do
    if [ -f "$KEYSTORE_CANDIDATE" ]; then
        KEYSTORE=$KEYSTORE_CANDIDATE
        break
    fi
done

if [ -n "$KEYSTORE" ]; then
    for CRT_FILE in $FILE_PREFIX*; do
        echo "Adding the following proxy certificate from '$CRT_FILE' to the JRE's certificate store at '$KEYSTORE':"
        cat $CRT_FILE

        ALIAS=$(basename $CRT_FILE .crt)
        $KEYTOOL -importcert -noprompt -trustcacerts -alias $ALIAS -file $CRT_FILE -keystore $KEYSTORE -storepass changeit
    done
else
    echo "No JVM keystore found, skipping the import."
fi

# Also add the proxy certificates to the system certificates, e.g. for curl to work.
echo "Adding proxy certificates to the system certificates..."
cp $FILE_PREFIX* /usr/local/share/ca-certificates/
update-ca-certificates

rm -fr $TEMP_DIR
