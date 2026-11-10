package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.service.HrReassignmentReferralService;
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
    private final Settings settings;
    private final Environment environment;
    private final ObjectProvider<JavaMailSender> senders;
    private final Executor executor;
    private final IncidentEmailDetailPolicy detailPolicy;
    private final VerifiedIncidentMailRouting verifiedRouting;
    private HrReassignmentReferralService hrReferrals;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void hrReferrals(HrReassignmentReferralService referrals) {
        this.hrReferrals = referrals;
    }
    IncidentEmailNotifications(Settings settings, Environment environment, ObjectProvider<JavaMailSender> senders,
            Executor executor, IncidentEmailDetailPolicy detailPolicy) {
        this(settings, environment, senders, executor, detailPolicy, null);
    }

    IncidentEmailNotifications(Settings settings, Environment environment, ObjectProvider<JavaMailSender> senders,
            Executor executor, IncidentEmailDetailPolicy detailPolicy, VerifiedIncidentMailRouting verifiedRouting) {
        this.settings=settings;this.environment=environment;this.senders=senders;this.executor=executor;
        this.detailPolicy = detailPolicy;
        this.verifiedRouting = verifiedRouting;
    }
    @TransactionalEventListener(phase=TransactionPhase.AFTER_COMMIT,fallbackExecution=false)
    public void created(IncidentCreated event) {
        if(!settings.enabled() || environment.getProperty("app.incident-access.enabled", Boolean.class, false)) return;
        try {executor.execute(() -> deliver(event));}
        catch(RuntimeException failure) {LOG.warn("Incident email task was not queued.");}
    }
    @TransactionalEventListener(phase=TransactionPhase.AFTER_COMMIT, fallbackExecution=false)
    public void classificationReady(IncidentMailReady event) {
        if (!settings.enabled() || !environment.getProperty("app.incident-access.enabled", Boolean.class, false)
                || !environment.getProperty("app.notifications.email.verified-department-routing.enabled", Boolean.class, false)) return;
        try {
            executor.execute(() -> {
                try {
                    boolean dev = environment.acceptsProfiles(Profiles.of("dev & !prod & !production & !default"));
                    boolean production = environment.acceptsProfiles(Profiles.of("default & !dev & !prod & !production"))
                            && environment.getProperty("app.notifications.email.local-postfix-enabled", Boolean.class, false);
                    if (dev != production && environment.getProperty("app.notifications.email.enabled", Boolean.class, settings.enabled())) {
                        deliverVerified(event.incidentNumber(), dev, production);
                    }
                } catch (RuntimeException failure) {
                    LOG.warn("Incident mail authorization unavailable. Notification withheld.");
                }
            });
        } catch (RuntimeException failure) {
            LOG.warn("Incident email task was not queued.");
        }
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void hrReferralQueued(HrReassignmentReferralService.HrReferralQueued event) {
        if (!hrReferralMailEnabled()) return;
        try {
            executor.execute(() -> {
                try {
                    deliverHrReferral(event.referralId());
                } catch (RuntimeException failure) {
                    LOG.warn("Referral email could not be processed. referral_id={}", event.referralId());
                }
            });
        } catch (RuntimeException failure) {
            LOG.warn("Referral email task was not queued. referral_id={}", event.referralId());
        }
    }

    private boolean hrReferralMailEnabled() {
        return hrReferrals != null && settings.enabled()
                && environment.getProperty("app.notifications.email.enabled", Boolean.class, false)
                && environment.getProperty("app.notifications.email.hr-referrals.enabled", Boolean.class, false);
    }

    private void deliverHrReferral(UUID referralId) {
        if (!hrReferralMailEnabled()) return;
        boolean dev = environment.acceptsProfiles(Profiles.of("dev & !prod & !production & !default"));
        boolean production = environment.acceptsProfiles(Profiles.of("default & !dev & !prod & !production"))
                && environment.getProperty("app.notifications.email.local-postfix-enabled", Boolean.class, false);
        if (dev == production) return;
        String portal = IncidentEmailPortalLink.url(environment.getProperty("app.notifications.email.portal-origin", ""));
        if (portal == null) return;
        String from = address(settings.from());
        JavaMailSender sender = senders.getIfUnique();
        if (sender == null || (production && (!APPROVED_PRODUCTION_SENDER.equals(from) || !approvedPostfix(sender)))) return;
        var allowedAddresses = dev ? addresses(settings.devAllowlist()) : null;
        for (long reviewer : hrReferrals.notificationReviewerIds()) {
            if (!hrReferralMailEnabled()) return;
            try {
                String email = hrReferrals.claimNotice(referralId, reviewer, allowedAddresses);
                if (email == null) continue;
                boolean sent = false;
                try {
                    var message = new SimpleMailMessage();
                    message.setFrom(from);
                    message.setTo(address(email));
                    message.setSubject("Portal review requested");
                    message.setText("A review is pending. Sign in to the portal: " + portal
                            + "\nReview reference: " + referralId);
                    sender.send(message);
                    sent = true;
                } catch (RuntimeException failure) {
                    LOG.warn("Referral email delivery is uncertain. referral_id={} recipient_id={}", referralId, reviewer);
                }
                hrReferrals.recordNoticeResult(referralId, reviewer, sent);
            } catch (RuntimeException failure) {
                LOG.warn("Referral email authorization or audit unavailable. referral_id={} recipient_id={}", referralId, reviewer);
            }
        }
    }

    private void deliver(IncidentCreated event) {
        try {
            boolean dev=environment.acceptsProfiles(Profiles.of("dev & !prod & !production & !default"));
            boolean production=environment.acceptsProfiles(Profiles.of("default & !dev & !prod & !production"))
                    && environment.getProperty("app.notifications.email.local-postfix-enabled",Boolean.class,false);
            if(!settings.enabled() || !environment.getProperty("app.notifications.email.enabled", Boolean.class, settings.enabled()) || dev==production) return;
            if(event.incidentNumber()==null || !event.incidentNumber().matches("INC-[0-9]{4}-[0-9]{8}-[0-9]{6}-[A-F0-9]{8}")) return;
            if (environment.getProperty("app.notifications.email.verified-department-routing.enabled", Boolean.class, false)) {
                deliverVerified(event.incidentNumber(), dev, production);
                return;
            }
            if (environment.getProperty("app.incident-access.enabled", Boolean.class, false)) return;
            boolean v2=environment.getProperty("app.notifications.email.v2.enabled",Boolean.class,false);
            var hint = RoutineIncidentEmailRoute.from(event);
            if (hint == UNKNOWN || hint == SECURITY) return;
            var assessment = detailPolicy.assess(event.incidentNumber());
            var decision = assessment.decision();
            boolean routine = v2 && !assessment.authorityConfigured()
                    && !environment.getProperty("app.incident-access.enabled", Boolean.class, false)
                    && "true".equalsIgnoreCase(
                    environment.getProperty("app.notifications.email.v2.routine-routing-enabled"));
            if (!routine && (decision == null || (hint == HR && decision.route() != HR))) return;
            var route = routine ? hint : decision.route();
            boolean hrCase = route == HR;
            if (!hrCase && (route != ORDINARY_IT || (!routine && decision.classification() != STANDARD))) return;

            var recipients = hrCase ? addresses(environment.getProperty("app.notifications.email.hr-case-recipients", ""))
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
                        String portalUrl = IncidentEmailPortalLink.url(portalOrigin);
                        boolean approved = v2 && (routine
                                ? !hrCase && detailPolicy.detailsEnabled(portalUrl)
                                : detailPolicy.allowsDetails(decision, recipient, portalUrl));
                        if (hrCase && !approved && !routine && !decision.hrMinimalApproved()) continue;
                        IncidentEmailTemplate.Rendered rendered;
                        if (hrCase) {
                            rendered = approved ? IncidentEmailTemplate.renderHrDetails(event, portalOrigin)
                                    : IncidentEmailTemplate.renderMinimal(portalOrigin);
                        } else {
                            rendered = IncidentEmailTemplate.render(event, approved, portalOrigin);
                        }
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
    private void deliverVerified(String incidentNumber, boolean dev, boolean production) {
        if (verifiedRouting == null) return;
        var candidates = verifiedRouting.recipients(incidentNumber);
        if (candidates.isEmpty()) return;
        var allowlist = dev ? addresses(settings.devAllowlist()) : Set.<String>of();
        String from = address(settings.from());
        JavaMailSender sender = senders.getIfUnique();
        if (sender == null || (production && (!APPROVED_PRODUCTION_SENDER.equals(from) || !approvedPostfix(sender)))) return;
        String origin = environment.getProperty("app.notifications.email.portal-origin", "");
        var content = IncidentEmailTemplate.renderMinimal(origin);
        for (String recipient : candidates) {
            if (dev && !allowlist.contains(recipient)) continue;
            if (!environment.getProperty("app.notifications.email.enabled", Boolean.class, settings.enabled())
                    || !verifiedRouting.recipients(incidentNumber).contains(recipient)) continue;
            try {
                var message = sender.createMimeMessage();
                var helper = new org.springframework.mail.javamail.MimeMessageHelper(message, true, "UTF-8");
                helper.setFrom(from);
                helper.setTo(recipient);
                helper.setSubject(content.subject());
                helper.setText(content.plainText(), content.html());
                sender.send(message);
            } catch (Exception failure) {
                LOG.warn("Incident email delivery failed.");
            }
        }
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
    static Set<String> addresses(String value) {
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
