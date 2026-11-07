package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.enums.IssueType;
import jakarta.mail.internet.InternetAddress;
import java.util.*;
import java.util.concurrent.Executor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.transaction.event.*;

import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Classification.STANDARD;
import static com.pareidolia.incidentmanagement.notification.IncidentEmailDetailAuthority.Route.*;

/** Best effort after-commit delivery. No durable queue or automatic retries. */
public final class IncidentEmailNotifications {
    public record Settings(boolean enabled,String from,String itRecipients,String hrRecipients,String devAllowlist) { }
    private static final org.slf4j.Logger LOG=org.slf4j.LoggerFactory.getLogger(IncidentEmailNotifications.class);
    private static final String APPROVED_PRODUCTION_SENDER="alerts@pareidolia.in";
    private static final String HR_CASE_MAILBOX = "schakravorty@pareidolia.in";
    private final Settings settings;
    private final Environment environment;
    private final ObjectProvider<JavaMailSender> senders;
    private final Executor executor;
    private final IncidentEmailDetailPolicy detailPolicy;
    IncidentEmailNotifications(Settings settings, Environment environment, ObjectProvider<JavaMailSender> senders,
            Executor executor, IncidentEmailDetailPolicy detailPolicy) {
        this.settings=settings;this.environment=environment;this.senders=senders;this.executor=executor;
        this.detailPolicy = detailPolicy;
    }
    @TransactionalEventListener(phase=TransactionPhase.AFTER_COMMIT,fallbackExecution=false)
    public void created(IncidentCreated event) {
        if(!settings.enabled()) return;
        try {executor.execute(() -> deliver(event));}
        catch(RuntimeException failure) {LOG.warn("Incident email task was not queued.");}
    }
    private void deliver(IncidentCreated event) {
        try {
            boolean dev=environment.acceptsProfiles(Profiles.of("dev & !prod & !production & !default"));
            boolean production=environment.acceptsProfiles(Profiles.of("default & !dev & !prod & !production"))
                    && environment.getProperty("app.notifications.email.local-postfix-enabled",Boolean.class,false);
            if(!settings.enabled() || dev==production) return;
            if(event.incidentNumber()==null || !event.incidentNumber().matches("INC-[0-9]{4}-[0-9]{8}-[0-9]{6}-[A-F0-9]{8}")) return;
            boolean v2=environment.getProperty("app.notifications.email.v2.enabled",Boolean.class,false);
            // Reporter input may only narrow delivery. It cannot establish an IT or HR route.
            if (event.issueType() != IssueType.IT_ISSUE && event.issueType() != IssueType.SERVICE_REQUEST) return;
            var decision = detailPolicy.assess(event.incidentNumber()).orElse(null);
            if (decision == null) return;
            boolean hrCase = decision.route() == HR;
            if (!hrCase && (decision.route() != ORDINARY_IT || decision.classification() != STANDARD)) return;

            var recipients = hrCase ? Set.of(HR_CASE_MAILBOX)
                    : addresses(settings.itRecipients()+","+settings.hrRecipients());
            if (v2 && !hrCase) {
                addDepartmentRecipients(recipients,event.reporterDepartment(),
                        environment.getProperty("app.notifications.email.v2.department-recipients",""));
            }
            var allowlist=dev ? addresses(settings.devAllowlist()) : Set.<String>of();
            if(recipients.isEmpty() || (dev && allowlist.isEmpty())) return;
            String from=address(settings.from());
            if(production && !APPROVED_PRODUCTION_SENDER.equals(from)) {LOG.warn("Incident email sender is not approved.");return;}
            JavaMailSender sender=senders.getIfUnique();
            if(sender==null) {LOG.warn("Incident email transport is unavailable.");return;}
            if(production && !approvedPostfix(sender)) {LOG.warn("Incident email transport is not approved.");return;}
            for(String recipient:recipients) {
                // Final transport boundary: never put an unapproved recipient in To/CC/BCC.
                if(dev && !allowlist.contains(recipient)) {LOG.warn("Incident email recipient blocked by DEV allowlist.");continue;}
                try {
                    if (v2 || hrCase) {
                        String portalOrigin = environment.getProperty("app.notifications.email.portal-origin", "");
                        boolean approved = v2 && detailPolicy.allowsDetails(decision, recipient,
                                IncidentEmailPortalLink.url(portalOrigin));
                        if (hrCase && !approved && !decision.hrMinimalApproved()) continue;
                        var rendered = hrCase && !approved ? IncidentEmailTemplate.renderMinimal(portalOrigin)
                                : IncidentEmailTemplate.render(event, approved, portalOrigin);
                        var message=sender.createMimeMessage();
                        var helper=new org.springframework.mail.javamail.MimeMessageHelper(message,true,"UTF-8");
                        helper.setFrom(from);helper.setTo(recipient);helper.setSubject(rendered.subject());
                        helper.setText(rendered.plainText(),rendered.html());sender.send(message);
                    } else {
                        var message=new SimpleMailMessage();message.setFrom(from);message.setTo(recipient);
                        message.setSubject("New incident created");
                        message.setText("A new incident was created: "+event.incidentNumber()+".\nSign in to the incident management portal to review it.");
                        sender.send(message);
                    }
                } catch(Exception failure) {LOG.warn("Incident email delivery failed.");}
            }
        } catch(RuntimeException failure) {LOG.warn("Incident email delivery configuration is invalid.");}
    }
    private static boolean approvedPostfix(JavaMailSender sender) {
        if(!(sender instanceof JavaMailSenderImpl mail)) return false;
        var p=mail.getJavaMailProperties();
        return "localhost".equalsIgnoreCase(mail.getHost()) && mail.getPort()==25
                && (mail.getUsername()==null || mail.getUsername().isBlank())
                && (mail.getPassword()==null || mail.getPassword().isBlank())
                && "false".equalsIgnoreCase(p.getProperty("mail.smtp.auth","false"))
                && "false".equalsIgnoreCase(p.getProperty("mail.smtp.starttls.enable","false"))
                && "false".equalsIgnoreCase(p.getProperty("mail.smtp.starttls.required","false"))
                && "false".equalsIgnoreCase(p.getProperty("mail.smtp.ssl.enable","false"))
                && !p.containsKey("mail.smtp.proxy.host") && !p.containsKey("mail.smtp.socks.host")
                && !p.containsKey("mail.smtp.socketFactory.class");
    }
    private static Set<String> addresses(String value) {
        var result=new LinkedHashSet<String>();
        if(value==null || value.isBlank()) return result;
        for(String part:value.split(",")) if(!part.isBlank()) result.add(address(part));
        return result;
    }
    private static void addDepartmentRecipients(Set<String> recipients, String department, String mappings) {
        if(department==null || department.isBlank() || mappings==null || mappings.isBlank()) return;
        for(String mapping:mappings.split(";",-1)) {
            String[] parts=mapping.split("=",2);
            if(parts.length!=2 || !parts[0].trim().equals(department.trim())) continue;
            try {recipients.addAll(addresses(parts[1]));}
            catch(IllegalArgumentException failure) {LOG.warn("Incident email department recipient configuration is invalid.");}
        }
    }
    private static String address(String value) {
        if(value==null || value.isBlank() || value.contains("\r") || value.contains("\n")) throw new IllegalArgumentException();
        String normalized=value.trim().toLowerCase(Locale.ROOT);
        try {var parsed=new InternetAddress(normalized,true);parsed.validate();
            if(!normalized.equals(parsed.getAddress()) || !normalized.contains("@")) throw new IllegalArgumentException();
            return normalized;
        } catch(jakarta.mail.internet.AddressException failure) {throw new IllegalArgumentException();}
    }
}
