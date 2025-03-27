package org.egov.filestore.validator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.tika.Tika;
import org.egov.filestore.config.FileStoreConfig;
import org.egov.filestore.domain.model.Artifact;
import org.egov.tracer.model.CustomException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

@Component
public class StorageValidator {

	private FileStoreConfig fileStoreConfig;

	@Autowired
	public StorageValidator(FileStoreConfig fileStoreConfig) {
		super();
		this.fileStoreConfig = fileStoreConfig;
	}

	public void validate(Artifact artifact) {

		String filename = artifact.getMultipartFile().getOriginalFilename();
		if (filename == null || filename.trim().isEmpty()) {
			throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Filename cannot be null or empty.");
		}
		if (filename.indexOf('.') != filename.lastIndexOf('.')) {
			throw new CustomException("EG_FILESTORE_INVALID_INPUT",
					"Invalid input provided for file: " + filename + ". Multiple extensions are not allowed.");
		}

		String extension = (FilenameUtils.getExtension(artifact.getMultipartFile().getOriginalFilename()))
				.toLowerCase();
		validateFileExtention(extension);
		validateContentType(artifact.getFileContentInString(), extension);
		validateInputContentType(artifact);
		scanFileForMaliciousContent(artifact);
	}

	private void validateFileExtention(String extension) {
		if (!fileStoreConfig.getAllowedFormatsMap().containsKey(extension)) {
			throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Inalvid input provided for file : " + extension
					+ ", please upload any of the allowed formats : " + fileStoreConfig.getAllowedKeySet());
		}
	}

	private void validateContentType(String inputStreamAsString, String extension) {

		String inputFormat = null;
		Tika tika = new Tika();
		try {

			InputStream ipStreamForValidation = IOUtils.toInputStream(inputStreamAsString,
					fileStoreConfig.getImageCharsetType());
			inputFormat = tika.detect(ipStreamForValidation);
			ipStreamForValidation.close();
		} catch (IOException e) {
			throw new CustomException("EG_FILESTORE_PARSING_ERROR",
					"not able to parse the input please upload a proper file of allowed type : " + e.getMessage());
		}

		if (!fileStoreConfig.getAllowedFormatsMap().get(extension).contains(inputFormat)) {
			throw new CustomException("EG_FILESTORE_INVALID_INPUT",
					"Inalvid input provided for file, the extension does not match the file format. Please upload any of the allowed formats : "
							+ fileStoreConfig.getAllowedKeySet());
		}
	}

	private void validateInputContentType(Artifact artifact) {

		MultipartFile file = artifact.getMultipartFile();
		String contentType = file.getContentType();
		String extension = (FilenameUtils.getExtension(artifact.getMultipartFile().getOriginalFilename()))
				.toLowerCase();

		if (!fileStoreConfig.getAllowedFormatsMap().get(extension).contains(contentType)) {
			throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Invalid Content Type");
		}
	}

	// added for mallicious content check
	private void scanFileForMaliciousContent(Artifact artifact) {
		List<Pattern> maliciousPatterns = Arrays.asList(
				// 🛑 Cross-Site Scripting (XSS)
				Pattern.compile("(?i)<script>.*?</script>"), // Inline script tags
				Pattern.compile("(?i)document\\.cookie"), // Cookie stealing
				Pattern.compile("(?i)document\\.write\\("), // Modifying page content
				Pattern.compile("(?i)window\\.location"), // Redirect attacks
				Pattern.compile("(?i)javascript:\\s*"), // Inline JavaScript URLs
				Pattern.compile("(?i)onerror\\s*=\\s*"), // JavaScript event handlers
				Pattern.compile("(?i)alert\\s*\\(.*?\\)"), // Common XSS test payload
				Pattern.compile("(?i)eval\\(.*?\\)"), // JavaScript eval() function
				Pattern.compile("(?i)onload\\s*=\\s*"), // Event handler injection
				Pattern.compile("(?i)iframe\\s*src\\s*=\\s*"), // iFrame injection

				// 🛑 SQL Injection (SQLi)
				Pattern.compile("(?i)(union.*?select|drop\\s+table|delete\\s+from)"), // Basic SQLi
				Pattern.compile("(?i)(--|#|;|\\*/|\\*/--)"), // SQL comments that might be used in attacks
				Pattern.compile("(?i)(select\\s+.*?from\\s+.*?where)"), // Basic SELECT SQL injection pattern
				Pattern.compile("(?i)(insert\\s+into\\s+.*?values)"), // INSERT SQL injection pattern
				Pattern.compile("(?i)(update\\s+.*?set\\s+.*?where)"), // UPDATE SQL injection pattern

				// 🛑 Command Injection (RCE)
				Pattern.compile("(?i)(exec\\s*\\(|cmd.exe|powershell.exe|bash -c|sh -c)"), // Shell execution
				Pattern.compile("(?i)(system\\(|popen\\(|proc_open\\(|shell_exec\\()"), // PHP/Perl system calls
				Pattern.compile("(?i)(;\\s*rm\\s*-rf\\s*/|;\\s*shutdown\\s*-h\\s*now)"), // Destructive commands
				Pattern.compile("(?i)(nc\\s*-e\\s*|netcat\\s*|socat\\s*)"), // Reverse shell patterns
				Pattern.compile("(?i)(wget\\s+http|curl\\s+-o)"), // External downloads

				// 🛑 PHP Code Injection
				Pattern.compile("(?i)base64_decode\\("), // Encoding evasion
				Pattern.compile("(?i)assert\\s*\\("), // Running arbitrary PHP code
				Pattern.compile("(?i)preg_replace\\s*\\(.*?\\/e"), // PHP regex execution
				Pattern.compile("(?i)phpinfo\\s*\\("), // Information leakage
				Pattern.compile("(?i)system\\s*\\("), // System command execution

				// 🛑 File Inclusion Attacks (LFI & RFI)
				Pattern.compile("(?i)(\\.\\./|/etc/passwd|/proc/self)"), // Directory traversal
				Pattern.compile("(?i)(http:\\/\\/|https:\\/\\/).*?\\.php"), // Remote file inclusion
				Pattern.compile("(?i)(php:\\/\\/input|data:\\/\\/text)"), // PHP input streams

				// 🛑 NoSQL Injection
				Pattern.compile("(?i)\\{\\s*\\$where\\s*:\\s*"), // MongoDB injection pattern
				Pattern.compile("(?i)db\\.getCollection\\("), // MongoDB collections
				Pattern.compile("(?i)db\\.runCommand\\("), // MongoDB command execution

				// 🛑 Dangerous File Extensions (for uploads)
				Pattern.compile("(?i)\\.php$|\\.jsp$|\\.asp$|\\.exe$|\\.sh$|\\.bat$|\\.cmd$"), // Prevent executable
																								// uploads

				// 🛑 Headers Manipulation & SSRF
				Pattern.compile("(?i)(x-forwarded-for|x-real-ip|client-ip):\\s*"), // Fake IP headers
				Pattern.compile("(?i)(metadata.google.internal|169.254.169.254)"), // Cloud metadata access attempt

				// 🛑 Code Execution in Java
				Pattern.compile("(?i)(Runtime\\.getRuntime\\(\\))"), // Java Runtime exec()
				Pattern.compile("(?i)ProcessBuilder\\s*\\("), // Java ProcessBuilder execution
				Pattern.compile("(?i)Class\\.forName\\("), // Java Reflection (can be abused)
				Pattern.compile("(?i)Method\\.invoke\\(") // Java Reflection Method execution
		);
		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(artifact.getMultipartFile().getInputStream()))) {
			String line;
			while ((line = reader.readLine()) != null) {
				for (Pattern pattern : maliciousPatterns) {
					if (pattern.matcher(line).find()) {
						throw new CustomException("EG_FILESTORE_MALICIOUS_FILE",
								"Malicious content detected in uploaded file.");
					}
				}
			}
		} catch (IOException e) {
			throw new CustomException("EG_FILESTORE_IO_ERROR", "Error reading file: " + e.getMessage());
		}
	}

	/*
	 * private void validateFilesToUpload(List<MultipartFile> filesToStore, String
	 * module, String tag, String tenantId) {
	 * if (CollectionUtils.isEmpty(filesToStore)) {
	 * throw new EmptyFileUploadRequestException(module, tag, tenantId);
	 * }
	 * }
	 */

}
