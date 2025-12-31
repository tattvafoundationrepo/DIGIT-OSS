package org.egov.web.notification.mail.service;

import java.util.Base64;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;

import org.egov.web.notification.mail.config.EmailProperties;
import org.egov.web.notification.mail.consumer.contract.Email;
import org.egov.web.notification.mail.consumer.contract.EmailAttachment;
import org.egov.web.notification.mail.consumer.contract.EmailRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@ConditionalOnProperty(value = "mail.enabled", havingValue = "true")
@Slf4j
public class ExternalEmailService implements EmailService {

	public static final String EXCEPTION_MESSAGE = "Exception creating HTML email";
	private JavaMailSenderImpl mailSender;

	@Autowired
	private EmailProperties emailProperties;

	public ExternalEmailService(JavaMailSenderImpl mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public void sendEmail(Email email) {
		log.info("📧 Attempting to send email to: {}", email.getEmailTo());
		log.info("📧 Subject: {}", email.getSubject());
		boolean hasHtmlContent = (email.getBody() != null &&
				(email.getBody().trim().startsWith("<") ||
						email.getBody().contains("<!DOCTYPE html>")));
		if (email.isHTML() || hasHtmlContent) {
			sendHTMLEmail(email);
		} else {
			sendTextEmail(email);
		}
	}

	private void sendTextEmail(Email email) {
		try {
			final SimpleMailMessage mailMessage = new SimpleMailMessage();

			// ADD THIS - Set FROM address
			mailMessage.setFrom(emailProperties.getMailFrom());

			mailMessage.setTo(email.getEmailTo().toArray(new String[0]));
			mailMessage.setSubject(email.getSubject());
			mailMessage.setText(email.getBody());

			mailSender.send(mailMessage);
			log.info("✅ Text email sent successfully");
		} catch (Exception e) {
			log.error("❌ Failed to send text email", e);
			throw new RuntimeException("Failed to send text email: " + e.getMessage(), e);
		}
	}

	// private void sendHTMLEmail(Email email) {
	// MimeMessage message = mailSender.createMimeMessage();
	// MimeMessageHelper helper;
	// try {
	// helper = new MimeMessageHelper(message, true, "UTF-8");

	// // ADD THIS - Set FROM address
	// helper.setFrom(emailProperties.getMailFrom());

	// helper.setTo(email.getEmailTo().toArray(new String[0]));
	// helper.setSubject(email.getSubject());
	// helper.setText(email.getBody(), true);

	// mailSender.send(message);
	// log.info("✅ HTML email sent successfully");
	// } catch (MessagingException e) {
	// log.error(EXCEPTION_MESSAGE, e);
	// throw new RuntimeException("Failed to send HTML email: " + e.getMessage(),
	// e);
	// }
	// }

	public void sendHTMLEmail(Email email) {
		try {
			MimeMessage message = mailSender.createMimeMessage();
			MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

			helper.setFrom(emailProperties.getMailFrom());
			helper.setTo(email.getEmailTo().toArray(new String[0]));

			// IMPORTANT: Add the CC logic here
			if (email.getEmailCc() != null && !email.getEmailCc().isEmpty()) {
				helper.setCc(email.getEmailCc().toArray(new String[0]));
			}
			helper.setSubject(email.getSubject());

			helper.setText(email.getBody(), true);

			log.info("📧 Email type: {}", true ? "HTML" : "Plain Text");

			// CRITICAL: This is the part that was missing in your text/html methods
			if (email.getAttachments() != null && !email.getAttachments().isEmpty()) {
				log.info("📎 Found {} attachment(s). Processing...", email.getAttachments().size());
				for (EmailAttachment attachment : email.getAttachments()) {
					// Decode the Base64 data from Kafka
					byte[] decodedBytes = Base64.getDecoder().decode(attachment.getData());

					helper.addAttachment(
							attachment.getName(),
							new ByteArrayResource(decodedBytes),
							attachment.getMimeType());
				}
			}

			mailSender.send(message);
			log.info("✅ Email sent successfully with attachments!");

		} catch (Exception e) {
			log.error("❌ Error sending email: ", e);
			throw new RuntimeException("Failed to send email", e);
		}
	}

}
