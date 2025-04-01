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
		Tika tika = new Tika();
		String fileType;
		try {
			fileType = tika.detect(artifact.getMultipartFile().getInputStream());
		} catch (IOException e) {
			throw new CustomException("EG_FILESTORE_IO_ERROR", "Error detecting file type: " + e.getMessage());
		}
	
		// Skip scanning for known binary file types
		if (fileType.startsWith("image/") || fileType.startsWith("video/") || fileType.startsWith("application/pdf")) {
			return; // Allow image, video, and PDF uploads without scanning
		}
	
		List<Pattern> maliciousPatterns = Arrays.asList(
    // 🔍 SQL Injection Detection
    Pattern.compile("(?i)(union.*?select|drop\\s+table|delete\\s+from)"), 
    Pattern.compile("(?i)(--|#|;|\\*/|\\*/--)"), 
    Pattern.compile("(?i)(select\\s+.*?from\\s+.*?where)"), 
    Pattern.compile("(?i)(insert\\s+into\\s+.*?values)"), 
    Pattern.compile("(?i)(update\\s+.*?set\\s+.*?where)"), 
    Pattern.compile("(?i)\\{\\s*\\$where\\s*:\\s*"), 
    Pattern.compile("(?i)db\\.getCollection\\("), 
    Pattern.compile("(?i)db\\.runCommand\\("),

    // 🔍 XSS (Cross-Site Scripting) Detection
    Pattern.compile("(?i)<script>.*?</script>"), 
    Pattern.compile("(?i)document\\.cookie"), 
    Pattern.compile("(?i)document\\.write\\("), 
    Pattern.compile("(?i)window\\.location"), 
    Pattern.compile("(?i)javascript:\\s*"), 
    Pattern.compile("(?i)onerror\\s*=\\s*"), 
    Pattern.compile("(?i)alert\\s*\\(.*?\\)"), 
    Pattern.compile("(?i)eval\\(.*?\\)"), 
    Pattern.compile("(?i)onload\\s*=\\s*"), 
    Pattern.compile("(?i)iframe\\s*src\\s*=\\s*"),

    // 🔍 JavaScript & PHP Execution Detection
    Pattern.compile("(?i)base64_decode\\("),  // PHP execution
    Pattern.compile("(?i)assert\\s*\\("),  // PHP execution
    Pattern.compile("(?i)preg_replace\\s*\\(.*?\\/e"), // PHP eval injection
    Pattern.compile("(?i)phpinfo\\s*\\("), // PHP function exposure
    Pattern.compile("(?i)system\\s*\\("), // PHP system command execution
    Pattern.compile("(?i)(php:\\/\\/input|data:\\/\\/text)"),  // PHP payloads
    Pattern.compile("(?i)document\\.getElementById\\("),  // JavaScript DOM manipulation
    Pattern.compile("(?i)setTimeout\\s*\\("),  // Potential JavaScript delayed execution
    Pattern.compile("(?i)Function\\s*\\("),  // JavaScript dynamic function execution
    Pattern.compile("(?i)fetch\\s*\\("),  // JavaScript network request
    Pattern.compile("(?i)XMLHttpRequest"),  // JavaScript AJAX request
    Pattern.compile("(?i)WebSocket\\s*\\("),  // JavaScript WebSocket

    // 🔍 Remote Command Execution (RCE)
    Pattern.compile("(?i)(exec\\s*\\(|cmd.exe|powershell.exe|bash -c|sh -c)"), 
    Pattern.compile("(?i)(system\\(|popen\\(|proc_open\\(|shell_exec\\()"), 
    Pattern.compile("(?i)(Runtime\\.getRuntime\\(\\))"), 
    Pattern.compile("(?i)ProcessBuilder\\s*\\("), 
    Pattern.compile("(?i)Class\\.forName\\("), 
    Pattern.compile("(?i)Method\\.invoke\\("),

    // 🔍 Malicious File Uploads (Executable & Script Files)
    Pattern.compile("(?i)\\.php$|\\.jsp$|\\.asp$|\\.exe$|\\.sh$|\\.bat$|\\.cmd$|\\.py$|\\.rb$|\\.ps1$|\\.vbs$")
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
