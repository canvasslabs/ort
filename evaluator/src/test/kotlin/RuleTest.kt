/*
 * Copyright (C) 2017-2019 HERE Europe B.V.
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

package com.here.ort.evaluator

import com.here.ort.model.Identifier
import com.here.ort.model.LicenseSource
import com.here.ort.model.Severity

import io.kotlintest.matchers.haveSize
import io.kotlintest.should
import io.kotlintest.shouldBe
import io.kotlintest.specs.WordSpec

class RuleTest : WordSpec() {
    private val ruleSet = RuleSet(ortResult)
    private val id = Identifier("type:namespace:name:version")
    private val license = "license"
    private val licenseSource = LicenseSource.DECLARED
    private val message = "violation message"

    private fun createRule() = object : Rule(ruleSet, "test") {
        override val description = "test"
        override fun issueSource() = name
    }

    init {
        "hint" should {
            "add an issue with the correct severity" {
                val rule = createRule()

                rule.hint(id, license, licenseSource, message)

                rule.violations should haveSize(1)
                rule.violations.first().let { violation ->
                    violation.rule shouldBe rule.name
                    violation.pkg shouldBe id
                    violation.license shouldBe license
                    violation.licenseSource shouldBe licenseSource
                    violation.severity shouldBe Severity.HINT
                    violation.message shouldBe message
                }
            }
        }

        "warning" should {
            "add an issue with the correct severity" {
                val rule = createRule()

                rule.warning(id, license, licenseSource, message)

                rule.violations should haveSize(1)
                rule.violations.first().let { violation ->
                    violation.rule shouldBe rule.name
                    violation.pkg shouldBe id
                    violation.license shouldBe license
                    violation.licenseSource shouldBe licenseSource
                    violation.severity shouldBe Severity.WARNING
                    violation.message shouldBe message
                }
            }
        }

        "error" should {
            "add an issue with the correct severity" {
                val rule = createRule()

                rule.error(id, license, licenseSource, message)

                rule.violations should haveSize(1)
                rule.violations.first().let { violation ->
                    violation.rule shouldBe rule.name
                    violation.pkg shouldBe id
                    violation.license shouldBe license
                    violation.licenseSource shouldBe licenseSource
                    violation.severity shouldBe Severity.ERROR
                    violation.message shouldBe message
                }
            }
        }

        "require" should {
            "add the expected matchers" {
                fun matcher() = object : RuleMatcher {
                    override val description = "test"
                    override fun matches() = true
                }

                val rule = createRule()

                rule.require {
                    +matcher()
                    -matcher()
                }

                rule.matchers should haveSize(2)
                rule.matchers[0].description shouldBe "test"
                rule.matchers[1].description shouldBe "!(test)"
            }
        }
    }
}