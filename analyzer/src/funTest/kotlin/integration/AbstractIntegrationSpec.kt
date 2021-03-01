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

package org.ossreviewtoolkit.analyzer.integration

import io.kotest.core.spec.Spec
import io.kotest.core.spec.style.StringSpec
import io.kotest.inspectors.forAll
import io.kotest.matchers.collections.beEmpty
import io.kotest.matchers.collections.containExactly
import io.kotest.matchers.nulls.beNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot

import java.io.File

import kotlin.io.path.createTempDirectory

import org.ossreviewtoolkit.analyzer.ManagedProjectFiles
import org.ossreviewtoolkit.analyzer.PackageManager
import org.ossreviewtoolkit.downloader.Downloader
import org.ossreviewtoolkit.downloader.VersionControlSystem
import org.ossreviewtoolkit.model.Identifier
import org.ossreviewtoolkit.model.Package
import org.ossreviewtoolkit.model.Provenance
import org.ossreviewtoolkit.utils.ORT_NAME
import org.ossreviewtoolkit.utils.safeDeleteRecursively
import org.ossreviewtoolkit.utils.test.DEFAULT_ANALYZER_CONFIGURATION
import org.ossreviewtoolkit.utils.test.DEFAULT_REPOSITORY_CONFIGURATION
import org.ossreviewtoolkit.utils.test.ExpensiveTag
import org.ossreviewtoolkit.utils.test.USER_DIR
import org.ossreviewtoolkit.utils.test.shouldNotBeNull

abstract class AbstractIntegrationSpec : StringSpec() {
    /**
     * The software package to download.
     */
    protected abstract val pkg: Package

    /**
     * The definition files that are expected to be found by the [PackageManager].
     */
    protected abstract val expectedManagedFiles: ManagedProjectFiles

    /**
     * The definition files by package manager that are to be used for testing dependency resolution. Defaults to
     * [expectedManagedFiles], but can be e.g. limited to a subset of files in big projects to speed up the test.
     */
    protected open val managedFilesForTest by lazy { expectedManagedFiles }

    /**
     * The list of package identifiers for which issues are expected.
     */
    protected open val identifiersWithExpectedIssues = setOf<Identifier>()

    /**
     * The temporary parent directory for downloads.
     */
    protected lateinit var outputDir: File

    /**
     * The directory where the source code of [pkg] was downloaded to.
     */
    protected lateinit var provenance: Provenance

    override fun beforeSpec(spec: Spec) {
        // Do not use the usual simple class name as the suffix here to shorten the path which otherwise gets too long
        // on Windows for SimpleFormIntegrationTest.
        outputDir = createTempDirectory("$ORT_NAME-${javaClass.simpleName}").toFile()
        provenance = Downloader.download(pkg, outputDir)
    }

    override fun afterSpec(spec: Spec) {
        outputDir.safeDeleteRecursively(force = true)
    }

    init {
        "Source code was downloaded successfully".config(tags = setOf(ExpensiveTag)) {
            VersionControlSystem.forDirectory(outputDir) shouldNotBeNull {
                isValid() shouldBe true
                vcsType shouldBe pkg.vcs.type

                provenance.sourceArtifact should beNull()
                provenance.vcsInfo shouldNotBeNull {
                    type shouldBe vcsType
                }
            }
        }

        "All package manager definition files are found".config(tags = setOf(ExpensiveTag)) {
            val managedFiles = PackageManager.findManagedFiles(outputDir)

            managedFiles.size shouldBe expectedManagedFiles.size
            managedFiles.entries.forAll { (manager, files) ->
                println("Verifying definition files for $manager.")

                // The keys in expected and actual maps of definition files are different instances of package manager
                // factories. So to compare values use the package manager names as keys instead.
                val expectedManagedFilesByName = expectedManagedFiles.mapKeys { (manager, _) ->
                    manager.managerName
                }

                expectedManagedFilesByName[manager.managerName] shouldNotBeNull {
                    files.sorted().joinToString("\n") shouldBe sorted().joinToString("\n")
                }
            }
        }

        "Analyzer creates one non-empty result per definition file".config(tags = setOf(ExpensiveTag)) {
            managedFilesForTest.entries.forAll { (manager, files) ->
                println("Resolving $manager dependencies in $files.")
                val results = manager.create(USER_DIR, DEFAULT_ANALYZER_CONFIGURATION, DEFAULT_REPOSITORY_CONFIGURATION)
                    .resolveDependencies(files)

                results.size shouldBe files.size
                results.values.flatten().forAll { result ->
                    VersionControlSystem.forType(result.project.vcsProcessed.type) shouldBe
                            VersionControlSystem.forType(pkg.vcs.type)
                    result.project.vcsProcessed.url shouldBe pkg.vcs.url
                    result.project.scopes shouldNot beEmpty()
                    result.packages shouldNot beEmpty()
                    result.collectIssues().keys should containExactly(identifiersWithExpectedIssues)
                }
            }
        }
    }
}
