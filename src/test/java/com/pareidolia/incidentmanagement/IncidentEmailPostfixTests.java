package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.notification.*;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IncidentEmailPostfixTests {
    @org.springframework.context.annotation.Configuration(proxyBeanMethods=false)
    @org.springframework.transaction.annotation.EnableTransactionManagement
    static class TransactionEvents { }
    private static final String NUMBER="INC-2026-20261104-120000-ABCDEF12";
    private final JavaMailSenderImpl mail=mock(JavaMailSenderImpl.class);
    @SuppressWarnings("unchecked") private final ObjectProvider<JavaMailSender> providers=mock(ObjectProvider.class);
    private MockEnvironment profiles(String... profiles) { var env=new MockEnvironment();env.setActiveProfiles(profiles);env.setProperty("app.notifications.email.local-postfix-enabled","true");return env; }
    private void approvedMail() {
        when(providers.getIfUnique()).thenReturn(mail);when(mail.getHost()).thenReturn("localhost");when(mail.getPort()).thenReturn(25);
        when(mail.getJavaMailProperties()).thenReturn(new Properties());
    }
    private void send(String from,String it,String hr,String... profiles) {
        var settings=new IncidentEmailNotifications.Settings(true,from,it,hr,"");
        IncidentEmailTestSupport.trustedItNotifier(settings,profiles(profiles),providers,Runnable::run).created(IncidentEmailTestSupport.itEvent(NUMBER));
    }
    private ApplicationContextRunner production() {
        return new ApplicationContextRunner().withInitializer(c -> c.getEnvironment().setActiveProfiles("default"))
                .withUserConfiguration(IncidentEmailConfiguration.class)
                .withPropertyValues("app.notifications.email.enabled=true", "app.notifications.email.local-postfix-enabled=true", "app.notifications.email.smtp.host=localhost",
                    "app.notifications.email.smtp.port=25", "app.notifications.email.smtp.username=",
                    "app.notifications.email.smtp.password=", "app.notifications.email.smtp.starttls=false");
    }
    @Test void productionIsDisabledByDefault() {
        new ApplicationContextRunner().withInitializer(c -> c.getEnvironment().setActiveProfiles("default"))
                .withUserConfiguration(IncidentEmailConfiguration.class)
                .run(c -> assertThat(c).hasNotFailed().doesNotHaveBean(JavaMailSender.class));
    }
    @Test void implicitDefaultProfileRequiresBothExplicitOptIns() {
        var base = new ApplicationContextRunner().withUserConfiguration(IncidentEmailConfiguration.class);
        base.run(c -> assertThat(c).hasNotFailed().doesNotHaveBean(JavaMailSender.class));
        base.withPropertyValues("app.notifications.email.enabled=true").run(c -> assertThat(c).hasNotFailed().doesNotHaveBean(JavaMailSender.class));
        base.withPropertyValues("app.notifications.email.local-postfix-enabled=true").run(c -> assertThat(c).hasNotFailed().doesNotHaveBean(JavaMailSender.class));
        base.withPropertyValues("app.notifications.email.enabled=true", "app.notifications.email.local-postfix-enabled=true",
                "app.notifications.email.smtp.host=localhost", "app.notifications.email.smtp.port=25")
            .run(c -> assertThat(c).hasNotFailed().hasSingleBean(JavaMailSender.class));
    }
    @Test void approvedSettingsCreateLocalUnauthenticatedTransport() {
        production().run(c -> {
            assertThat(c).hasNotFailed().hasSingleBean(JavaMailSender.class);
            var sender=(JavaMailSenderImpl)c.getBean(JavaMailSender.class);
            assertThat(sender.getHost()).isEqualTo("localhost");assertThat(sender.getPort()).isEqualTo(25);
            assertThat(sender.getUsername()).isNullOrEmpty();assertThat(sender.getPassword()).isNullOrEmpty();
            assertThat(sender.getJavaMailProperties()).containsEntry("mail.smtp.auth","false")
                    .containsEntry("mail.smtp.starttls.enable","false").containsEntry("mail.smtp.starttls.required","false");
        });
    }
    @Test void incorrectTransportSettingsFailAtStartup() {
        for(String invalid:new String[]{"app.notifications.email.smtp.host=relay.example.test","app.notifications.email.smtp.port=2525",
                "app.notifications.email.smtp.username=synthetic","app.notifications.email.smtp.password=synthetic",
                "app.notifications.email.smtp.starttls=true"})
            production().withPropertyValues(invalid).run(c -> assertThat(c).hasFailed());
    }
    @Test void defaultProfileWithoutLocalPostfixOptInCannotSendEvenWithSenderPresent() {
        approvedMail();
        var env = new MockEnvironment();
        var settings = new IncidentEmailNotifications.Settings(true, "alerts@pareidolia.in", "first@example.test", "", "");
        IncidentEmailTestSupport.trustedItNotifier(settings, env, providers, Runnable::run).created(IncidentEmailTestSupport.itEvent(NUMBER));
        verify(mail, never()).send(any(SimpleMailMessage.class));
    }
    @Test void productionUsesOnlyConfiguredRecipientsAndApprovedSender() {
        approvedMail();send("alerts@pareidolia.in","first@example.test","FIRST@example.test,second@example.test","default");
        var messages=org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);verify(mail,times(2)).send(messages.capture());
        assertThat(messages.getAllValues()).extracting(m->m.getTo()[0]).containsExactly("first@example.test","second@example.test");
        for(var message:messages.getAllValues()) {
            assertThat(message.getFrom()).isEqualTo("alerts@pareidolia.in");assertThat(message.getCc()).isNull();assertThat(message.getBcc()).isNull();
            assertThat(message.getSubject()).isEqualTo("New incident created");
            assertThat(message.getText()).isEqualTo("A new incident was created: "+NUMBER+".\nSign in to the incident management portal to review it.");
        }
    }
    @Test void wrongSenderMixedProfilesAndUnknownProfilesCannotSend() {
        approvedMail();send("other@example.test","first@example.test","","default");
        send("alerts@pareidolia.in","first@example.test","","dev","prod");
        send("alerts@pareidolia.in","first@example.test","","test");
        verify(mail,never()).send(any(SimpleMailMessage.class));
    }
    @Test void unsafeOrThirdPartyMailSenderCannotDeliver() {
        approvedMail();when(mail.getHost()).thenReturn("external.example.test");
        send("alerts@pareidolia.in","first@example.test","","default");
        verify(mail,never()).send(any(SimpleMailMessage.class));
        when(mail.getHost()).thenReturn("localhost");var props=new Properties();props.setProperty("mail.smtp.auth","true");when(mail.getJavaMailProperties()).thenReturn(props);
        send("alerts@pareidolia.in","first@example.test","","default");verify(mail,never()).send(any(SimpleMailMessage.class));
    }
    @Test void productionEventIsQueuedOnlyAfterCommitAndNotAfterRollback() {
        approvedMail();
        var dataSource=new org.springframework.jdbc.datasource.DriverManagerDataSource("jdbc:h2:mem:postfix_events;DB_CLOSE_DELAY=-1","sa","");
        production().withUserConfiguration(TransactionEvents.class, IncidentEmailTestSupport.TrustedItConfiguration.class)
            .withBean(org.springframework.transaction.PlatformTransactionManager.class,()->new org.springframework.jdbc.datasource.DataSourceTransactionManager(dataSource))
            .withBean("syntheticMail",JavaMailSender.class,()->mail,definition->definition.setPrimary(true))
            .withPropertyValues("app.notifications.email.from=alerts@pareidolia.in","app.notifications.email.it-recipients=first@example.test")
            .run(context -> {
                assertThat(context).hasNotFailed();var transactions=new org.springframework.transaction.support.TransactionTemplate(context.getBean(org.springframework.transaction.PlatformTransactionManager.class));
                transactions.executeWithoutResult(status->{context.publishEvent(IncidentEmailTestSupport.itEvent(NUMBER));verify(mail,never()).send(any(SimpleMailMessage.class));});
                drain(context);verify(mail,times(1)).send(any(SimpleMailMessage.class));
                transactions.executeWithoutResult(status->{context.publishEvent(IncidentEmailTestSupport.itEvent(NUMBER));status.setRollbackOnly();});
                drain(context);verify(mail,times(1)).send(any(SimpleMailMessage.class));
            });
    }
    @Test
    void configuredPostfixWithNoAuthorityWithholdsBothLegacyAndV2AfterCommit() {
        approvedMail();
        for (boolean v2 : new boolean[]{false, true}) {
            var dataSource = new org.springframework.jdbc.datasource.DriverManagerDataSource(
                    "jdbc:h2:mem:postfix_without_authority", "sa", "");
            production().withUserConfiguration(TransactionEvents.class)
                    .withBean(org.springframework.transaction.PlatformTransactionManager.class,
                            () -> new org.springframework.jdbc.datasource.DataSourceTransactionManager(dataSource))
                    .withBean("syntheticMail", JavaMailSender.class, () -> mail, definition -> definition.setPrimary(true))
                    .withPropertyValues("app.notifications.email.from=alerts@pareidolia.in",
                            "app.notifications.email.it-recipients=first@example.test",
                            "app.notifications.email.hr-recipients=hr@example.test",
                            "app.notifications.email.v2.enabled=" + v2,
                            "app.notifications.email.v2.details-enabled=true",
                            "app.notifications.email.portal-origin=https://portal.example.test",
                            "app.notifications.email.v2.department-recipients=Operations=ops@example.test")
                    .run(context -> {
                        assertThat(context).hasNotFailed().doesNotHaveBean(IncidentEmailDetailAuthority.class);
                        var transactions = new org.springframework.transaction.support.TransactionTemplate(
                                context.getBean(org.springframework.transaction.PlatformTransactionManager.class));
                        transactions.executeWithoutResult(status -> context.publishEvent(new IncidentCreated(
                                NUMBER, "Synthetic confidential case", null, "Operations",
                                com.pareidolia.incidentmanagement.enums.IssueType.IT_ISSUE, null, null, null)));
                        drain(context);
                        verifyNoInteractions(mail);
                    });
        }
    }

    private static void drain(org.springframework.context.ApplicationContext context) {
        try {context.getBean("incidentEmailExecutor",org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor.class).getThreadPoolExecutor().submit(()->{}).get(5,java.util.concurrent.TimeUnit.SECONDS);}
        catch(Exception failure){throw new AssertionError("Email worker did not finish",failure);}
    }
}
