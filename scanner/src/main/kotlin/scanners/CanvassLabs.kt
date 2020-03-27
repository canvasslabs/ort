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

package org.ossreviewtoolkit.scanner.scanners

import com.fasterxml.jackson.databind.JsonNode

import org.ossreviewtoolkit.model.EMPTY_JSON_NODE
import org.ossreviewtoolkit.model.LicenseFinding
import org.ossreviewtoolkit.model.Provenance
import org.ossreviewtoolkit.model.ScanResult
import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.TextLocation
import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.model.jsonMapper
import org.ossreviewtoolkit.scanner.AbstractScannerFactory
import org.ossreviewtoolkit.scanner.HTTP_CACHE_PATH
import org.ossreviewtoolkit.scanner.LocalScanner
import org.ossreviewtoolkit.scanner.ScanException
import org.ossreviewtoolkit.spdx.calculatePackageVerificationCode
import org.ossreviewtoolkit.utils.ORT_NAME
import org.ossreviewtoolkit.utils.Os
import org.ossreviewtoolkit.utils.OkHttpClientHelper
import org.ossreviewtoolkit.utils.ProcessCapture
import org.ossreviewtoolkit.utils.log
import org.ossreviewtoolkit.utils.unpack

import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.time.Instant

import okhttp3.Request

class CanvassLabs(name: String, config: ScannerConfiguration) : LocalScanner(name, config) {
    class Factory : AbstractScannerFactory<CanvassLabs>("CanvassLabs") {
        override fun create(config: ScannerConfiguration) = CanvassLabs(scannerName, config)
    }

    companion object {
        val CONFIGURATION_OPTIONS = listOf(
            "--confidence", "0.95", // Cut-off value to only get most relevant matches.
            "--format", "json"
        )
    }

    override val scannerVersion = "1.3.1"
    override val resultFileExt = "json"

    override fun command(workingDir: File?) =
        listOfNotNull(workingDir, if (Os.isWindows) "ORTClient.exe" else "ORTClient").joinToString(File.separator)

    override fun transformVersion(output: String) =
        // "ORTClient --version" returns a string like "ORTClient version 1.1.1", so simply remove the prefix.
        output.removePrefix("ORTClient version ")

    override fun bootstrap(): File {
        val platform = when {
            Os.isLinux -> "x86_64-unknown-linux"
            Os.isMac -> "x86_64-apple-darwin"
            Os.isWindows -> "x86_64-pc-windows"
            else -> throw IllegalArgumentException("Unsupported operating system.")
        }

        val archive = "ORTClient-$scannerVersion-$platform.zip"
        //val url = "https://127.0.0.1:5000/lian_ort/download/v$scannerVersion/$archive"
        val url = "http://127.0.0.1:5000/lian_ort/download/v$scannerVersion/$archive"

        log.info { "Downloading $scannerName from $url... " }

        val request = Request.Builder().get().url(url).build()

        return OkHttpClientHelper.execute(HTTP_CACHE_PATH, request).use { response ->
            val body = response.body

            if (response.code != HttpURLConnection.HTTP_OK || body == null) {
                throw IOException("Failed to download $scannerName from $url.")
            }

            if (response.cacheResponse != null) {
                log.info { "Retrieved $scannerName from local cache." }
            }

            val unpackDir = createTempDir(ORT_NAME, "$scannerName-$scannerVersion").apply { deleteOnExit() }

            log.info { "Unpacking '$archive' to '$unpackDir'... " }
            body.byteStream().unpack(archive, unpackDir)

            if (!Os.isWindows) {
                // The Linux version is distributed as a ZIP, but without having the Unix executable mode bits stored.
                File(unpackDir, command()).setExecutable(true)
            }

            unpackDir
        }
    }

    override fun getConfiguration() = CONFIGURATION_OPTIONS.joinToString(" ")

    override fun scanPathInternal(path: File, resultsFile: File): ScanResult {
        val startTime = Instant.now()

        //val lianCredentials = "/home/charliec/.lian_credentials"
	val home_directory = System.getenv("HOME")
        val lianCredentials = "$home_directory/.lian_credentials"
	log.info {"checking for credentials in $lianCredentials"}
	var lianCredentialsFile = File(lianCredentials)
	var credentialsFileExists = lianCredentialsFile.exists()
	val errorSubscriptionRequiredMessage = "Use of CanvassLab's LiAn scan tool requires a subscription. Please visit https://lianort.canvasslabs.com for more information."

	if(!credentialsFileExists) {
            throw ScanException(errorSubscriptionRequiredMessage)
        }

        val process = ProcessCapture(
            scannerPath.absolutePath,
            "-i", path.absolutePath,
            "-o", resultsFile.absolutePath
        )

        val endTime = Instant.now()

        if (process.stderr.isNotBlank()) {
            log.debug { process.stderr }
        }

        with(process) {
            if (isSuccess) {
                val result = getRawResult(resultsFile)
                val summary = generateSummary(startTime, endTime, path, result)
                return ScanResult(Provenance(), getDetails(), summary, result)
            } else {
                throw ScanException(errorMessage)
            }
        }
    }

    override fun getRawResult(resultsFile: File) =
        if (resultsFile.isFile && resultsFile.length() > 0L) {
            jsonMapper.readTree(resultsFile)
        } else {
            EMPTY_JSON_NODE
        }

    private fun generateSummary(startTime: Instant, endTime: Instant, scanPath: File, result: JsonNode): ScanSummary {
        val licenseFindings = sortedSetOf<LicenseFinding>()

        result.flatMapTo(licenseFindings) { file ->
            val filePath = File(file["file_path"].textValue())
            file["matches"].map {
               LicenseFinding(
                    license = it["matched_license"].textValue(),
                    location = TextLocation(
                        relativizePath(scanPath, filePath),
			it["start_line_ind"].intValue(),
			it["end_line_ind"].intValue()
                    )
                )
            }
        }

        return ScanSummary(
            startTime = startTime,
            endTime = endTime,
            fileCount = result.size(),
            packageVerificationCode = calculatePackageVerificationCode(scanPath),
            licenseFindings = licenseFindings,
            copyrightFindings = sortedSetOf(),
            issues = mutableListOf()
        )
    }
}
