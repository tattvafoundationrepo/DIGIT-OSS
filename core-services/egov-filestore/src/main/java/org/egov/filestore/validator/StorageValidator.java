package org.egov.filestore.validator;

import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
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

    private static final long MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB
    private FileStoreConfig fileStoreConfig;

    @Autowired
    public StorageValidator(FileStoreConfig fileStoreConfig) {
        this.fileStoreConfig = fileStoreConfig;
    }

    public void validate(Artifact artifact) {
        MultipartFile file = artifact.getMultipartFile();
        String filename = file.getOriginalFilename();
        
        if (filename == null || filename.trim().isEmpty()) {
            throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Filename cannot be null or empty.");
        }
        if (filename.indexOf('.') != filename.lastIndexOf('.')) {
            throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Multiple extensions are not allowed.");
        }

        String extension = FilenameUtils.getExtension(filename).toLowerCase();
        validateFileExtention(extension);
        validateContentType(artifact.getFileContentInString(), extension);
        validateInputContentType(artifact);
        scanFileForMaliciousContent(artifact);
    }

    private void validateFileExtention(String extension) {
        if (!fileStoreConfig.getAllowedFormatsMap().containsKey(extension)) {
            throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Invalid file format: " + extension);
        }
    }

    private void validateContentType(String content, String extension) {
        Tika tika = new Tika();
        try (InputStream inputStream = IOUtils.toInputStream(content, fileStoreConfig.getImageCharsetType())) {
            String detectedType = tika.detect(inputStream);
            if (!fileStoreConfig.getAllowedFormatsMap().get(extension).contains(detectedType)) {
                throw new CustomException("EG_FILESTORE_INVALID_INPUT", "File extension does not match format.");
            }
        } catch (IOException e) {
            throw new CustomException("EG_FILESTORE_PARSING_ERROR", "Error parsing file: " + e.getMessage());
        }
    }

    private void validateInputContentType(Artifact artifact) {
        MultipartFile file = artifact.getMultipartFile();
        String contentType = file.getContentType();
        String extension = FilenameUtils.getExtension(file.getOriginalFilename()).toLowerCase();
        if (!fileStoreConfig.getAllowedFormatsMap().get(extension).contains(contentType)) {
            throw new CustomException("EG_FILESTORE_INVALID_INPUT", "Invalid content type.");
        }
    }

    private void scanFileForMaliciousContent(Artifact artifact) {
        MultipartFile file = artifact.getMultipartFile();
        validateImageIntegrity(file);
        if (file.getSize() > MAX_IMAGE_SIZE) {
            throw new CustomException("EG_FILESTORE_INVALID_SIZE", "File size exceeds 5MB.");
        }

		List<Pattern> maliciousPatterns = Arrays.asList(
			Pattern.compile("(?i)<script>.*?</script>"),
			Pattern.compile("(?i)document\\.cookie"),
			Pattern.compile("(?i)eval\\(.*?\\)"),
			Pattern.compile("(?i)onerror\\s*=\\s*"),
			Pattern.compile("(?i)iframe\\s*src\\s*=\\s*"),
			Pattern.compile("(?i)phpinfo\\s*\\("),
			Pattern.compile("(?i)Runtime\\.getRuntime\\("),
			Pattern.compile("(?i)ProcessBuilder\\s*\\("),
			Pattern.compile("(?i)Class\\.forName\\("),
			Pattern.compile("(?i)\\.(php|jsp|exe|sh|bat|cmd|py|rb|ps1|vbs)$")
		);
		

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (Pattern pattern : maliciousPatterns) {
                    if (pattern.matcher(line).find()) {
                        throw new CustomException("EG_FILESTORE_MALICIOUS_FILE", "Malicious content detected.");
                    }
                }
            }
        } catch (IOException e) {
            throw new CustomException("EG_FILESTORE_IO_ERROR", "Error reading file: " + e.getMessage());
        }
    }

    private void validateImageIntegrity(MultipartFile file) {
        try {
            String mimeType = new Tika().detect(file.getInputStream());
            if (!mimeType.startsWith("image/")) {
                throw new CustomException("EG_FILESTORE_INVALID_TYPE", "File is not a valid image.");
            }
            BufferedImage img = ImageIO.read(file.getInputStream());
            if (img == null) {
                throw new CustomException("EG_FILESTORE_INVALID_IMAGE", "Invalid image format.");
            }
            byte[] header = new byte[4];
            try (InputStream is = file.getInputStream()) {
                is.read(header);
            }
            String magicNumber = String.format("%02X%02X%02X%02X", header[0], header[1], header[2], header[3]);
            List<String> executableHeaders = Arrays.asList("7F454C46", "4D5A9000", "FEEDFACE", "CAFEBABE");
            if (executableHeaders.contains(magicNumber)) {
                throw new CustomException("EG_FILESTORE_INVALID_TYPE", "Executable files are not allowed.");
            }
        } catch (IOException e) {
            throw new CustomException("EG_FILESTORE_IO_ERROR", "Error verifying file integrity: " + e.getMessage());
        }
    }
}
