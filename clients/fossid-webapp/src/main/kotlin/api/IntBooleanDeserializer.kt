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

package org.ossreviewtoolkit.fossid.api

import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.deser.std.StdDeserializer

/**
 * This class deserializes a String containing 0/1 to boolean.
 * Null string leads to null Boolean.
 */
class IntBooleanDeserializer : StdDeserializer<Boolean>(Boolean::class.java) {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): Boolean =
        when (val text = p.text) {
            "0" -> false
            "1" -> true
            else -> text.toBoolean()
        }
}
