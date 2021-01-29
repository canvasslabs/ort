/*
 * Copyright (C) 2020 Bosch.IO GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

val jacksonVersion: String by project
val retrofitVersion: String by project
val wiremockVersion: String by project

plugins {
    // Apply core plugins.
    `java-library`
}

dependencies {
    api("com.squareup.retrofit2:retrofit:$retrofitVersion")

    implementation(project(":utils"))

    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")
    implementation("com.squareup.retrofit2:converter-jackson:$retrofitVersion")

    testImplementation("com.github.tomakehurst:wiremock:$wiremockVersion")
}
