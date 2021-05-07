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
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.time.Instant
import kotlin.io.path.createTempDirectory
import okhttp3.Request
import org.ossreviewtoolkit.model.EMPTY_JSON_NODE
import org.ossreviewtoolkit.model.LicenseFinding
import org.ossreviewtoolkit.model.CopyrightFinding
import org.ossreviewtoolkit.model.ScanSummary
import org.ossreviewtoolkit.model.TextLocation
import org.ossreviewtoolkit.model.config.ScannerConfiguration
import org.ossreviewtoolkit.model.jsonMapper
import org.ossreviewtoolkit.scanner.AbstractScannerFactory
import org.ossreviewtoolkit.scanner.LocalScanner
import org.ossreviewtoolkit.scanner.ScanException
import org.ossreviewtoolkit.spdx.calculatePackageVerificationCode
import org.ossreviewtoolkit.utils.ORT_NAME
import org.ossreviewtoolkit.utils.OkHttpClientHelper
import org.ossreviewtoolkit.utils.Os
import org.ossreviewtoolkit.utils.ProcessCapture
import org.ossreviewtoolkit.utils.log
import org.ossreviewtoolkit.utils.unpackZip
import java.util.UUID


class CanvassLabs(name: String, config: ScannerConfiguration) : LocalScanner(name, config) {
    class Factory : AbstractScannerFactory<CanvassLabs>("CanvassLabs") {
        override fun create(config: ScannerConfiguration) = CanvassLabs(scannerName, config)
    }

    companion object {
        val CONFIGURATION_OPTIONS = listOf("")
    }

    var user_metadata_id = UUID.randomUUID()

    override val expectedVersion = "1.3.1"
    override val configuration = CONFIGURATION_OPTIONS.joinToString(" ")
    override val resultFileExt = "json"

    override fun command(workingDir: File?) =
        listOfNotNull(workingDir, if (Os.isWindows) "ORT2LiAn.exe" else "ORT2LiAn").joinToString(File.separator)


    override fun transformVersion(output: String) = output.removePrefix("ORT2LiAn version ").dropLastWhile { 0 != it.compareTo(',') }.dropLast(1) 
    override fun bootstrap(): File {
        val platform = when {
            Os.isLinux -> "x86_64-unknown-linux"
            Os.isMac -> "x86_64-apple-darwin"
            Os.isWindows -> "x86_64-pc-windows"
            else -> throw IllegalArgumentException("Unsupported operating system.")
        }

        val archive = "ORT2LiAn-$expectedVersion-$platform.zip"
        val url = "https://ortclient.s3-us-west-2.amazonaws.com/v$expectedVersion/$archive"
        
        log.info { "Downloading $scannerName from $url... " }

        val request = Request.Builder().get().url(url).build()

        return OkHttpClientHelper.execute(request).use { response ->
            val body = response.body

            if (response.code != HttpURLConnection.HTTP_OK || body == null) {
                throw IOException("Failed to download $scannerName from $url.")
            }

            if (response.cacheResponse != null) {
                log.info { "Retrieved $scannerName from local cache." }
            }

            val unpackDir = createTempDirectory("$ORT_NAME-$scannerName-$expectedVersion").toFile().apply {
                deleteOnExit()
            }

            log.info { "Unpacking '$archive' to '$unpackDir'... " }
            body.bytes().unpackZip(unpackDir)

            unpackDir
        }
    }

    override fun scanPathInternal(path: File, resultsFile: File): ScanSummary {
        val startTime = Instant.now()

        val process = ProcessCapture(
            scannerPath.absolutePath,
            "-i", path.absolutePath,
            "-u", "$user_metadata_id",
            "-o", resultsFile.absolutePath
        )

        val endTime = Instant.now()

        if (process.stderr.isNotBlank()) {
            log.debug { process.stderr }
        }

        with(process) {
            if (isSuccess) {
                val result = getRawResult(resultsFile)
                return generateSummary(startTime, endTime, path, result)
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
        val copyrightFindings = sortedSetOf<CopyrightFinding>()

        /*
            The idea here is to iterate through 'matches' and first pick out
            the ones that are not copyrights, and assume they're licenses by
            default. The quirk is that currently matched_type returns
            'copyright' for copyrights, but the spdx name for licenses,
            instead of 'license'. Using mapNotNull() allows us to not populate
            the sets defined above with None values, which violate some
            assertion downstream.
        */

	/* STOCK
	result.flatMapTo(licenseFindings) { file ->
            val filePath = File(file["Directory"].textValue(), file["Filename"].textValue())
            file["LicenseGuesses"].map {
                LicenseFinding(
                    license = getSpdxLicenseIdString(it["LicenseId"].textValue()),
                    location = TextLocation(
                        // Turn absolute paths in the native result into relative paths to not expose any information.
                        relativizePath(scanPath, filePath),
                        TextLocation.UNKNOWN_LINE
                    )
                )
            }
        }
	*/

        result.flatMapTo(licenseFindings) { file ->
            file["matches"].mapNotNull {   
                // currently, if matched_type does not equal copyright, it will be the
                // SPDX name for a known license.
                it -> if(!it["matched_type"].textValue().equals("copyright"))
                    LicenseFinding(
                        license = getSpdxLicenseIdString(it["matched_type"].textValue()),
                        location = TextLocation(
                            // Turn absolute paths in the native result into relative paths to not expose any information.
                            //relativizePath(scanPath, filePath),
                            //this code needs the path to the file to be the file_n.json file, even though we give it an aggregate file.
                            //hence, all cached dependencies would have 'file_1.json' for the path if we didn't take from input_fp instead.
                            relativizePath(scanPath, File(it["input_fp"].textValue())),
                            it["start_line_ind"].intValue() + 1,
                            it["end_line_ind"].intValue() + 1
                        )
                    ) else null
            }
        }

        result.flatMapTo(copyrightFindings) { file ->
            file["matches"].mapNotNull {   
                it -> if(it["matched_type"].textValue().equals("copyright"))
                    CopyrightFinding(
                        statement = it["found_region"].textValue(),
                        location = TextLocation(
                            // Turn absolute paths in the native result into relative paths to not expose any information.
                            //relativizePath(scanPath, filePath),
                            //relativizePath(scanPath, it["input_fp"].textValue()),
                            relativizePath(scanPath, File(it["input_fp"].textValue())),
                            // copyright lines appear to need an increment
                            it["start_line_ind"].intValue() + 1,
                            it["end_line_ind"].intValue() + 1
                        )
                    ) else null
            }
        }
    
        return ScanSummary(
            startTime = startTime,
            endTime = endTime,
            fileCount = result.size(),
            packageVerificationCode = calculatePackageVerificationCode(scanPath),
            licenseFindings = licenseFindings,
            copyrightFindings = copyrightFindings,
            issues = mutableListOf()
        )
    }
}
