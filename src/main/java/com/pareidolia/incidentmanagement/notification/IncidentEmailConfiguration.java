package com.pareidolia.incidentmanagement.notification;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

@Configuration(proxyBeanMethods=false)
public class IncidentEmailConfiguration {
    @Bean IncidentEmailNotifications.Settings incidentEmailSettings(Environment env) {
        String prefix="app.notifications.email.";
        IncidentEmailPortalLink.url(env.getProperty(prefix+"portal-origin",""));
        return new IncidentEmailNotifications.Settings(env.getProperty(prefix+"enabled",Boolean.class,false),
                env.getProperty(prefix+"from",""),env.getProperty(prefix+"it-recipients",""),
                env.getProperty(prefix+"hr-recipients",""),env.getProperty(prefix+"dev-allowlist",""));
    }
    @Bean ThreadPoolTaskExecutor incidentEmailExecutor() {
        var executor=new ThreadPoolTaskExecutor();executor.setCorePoolSize(1);executor.setMaxPoolSize(1);
        executor.setQueueCapacity(100);executor.setThreadNamePrefix("incident-email-");
        return executor;
    }
    @Bean
    @Profile("dev & !prod & !production")
    @ConditionalOnProperty(name="app.notifications.email.enabled",havingValue="true")
    JavaMailSender incidentDevMailSender(Environment env) {
        String p="app.notifications.email.smtp.";
        var sender=new JavaMailSenderImpl();sender.setHost(env.getProperty(p+"host","127.0.0.1"));
        sender.setPort(env.getProperty(p+"port",Integer.class,1025));
        String username=env.getProperty(p+"username","");sender.setUsername(username);
        sender.setPassword(env.getProperty(p+"password",""));
        var properties=sender.getJavaMailProperties();properties.setProperty("mail.smtp.auth",Boolean.toString(!username.isBlank()));
        properties.setProperty("mail.smtp.starttls.enable",env.getProperty(p+"starttls","false"));
        properties.setProperty("mail.smtp.starttls.required",env.getProperty(p+"starttls","false"));
        properties.setProperty("mail.smtp.ssl.checkserveridentity","true");
        properties.setProperty("mail.smtp.connectiontimeout","3000");properties.setProperty("mail.smtp.timeout","3000");
        properties.setProperty("mail.smtp.writetimeout","3000");
        return sender;
    }
    @Bean
    @Profile("default & !dev & !prod & !production")
    @ConditionalOnProperty(name={"app.notifications.email.enabled","app.notifications.email.local-postfix-enabled"},havingValue="true")
    JavaMailSender incidentPostfixMailSender(Environment env) {
        String p="app.notifications.email.smtp.";
        String host=env.getProperty(p+"host","").trim();
        Integer port=env.getProperty(p+"port",Integer.class,0);
        String username=env.getProperty(p+"username","");
        String password=env.getProperty(p+"password","");
        Boolean starttls=env.getProperty(p+"starttls",Boolean.class,false);
        if(!"localhost".equalsIgnoreCase(host) || port!=25 || !username.isBlank() || !password.isBlank() || starttls)
            throw new IllegalStateException("Incident email requires the approved local Postfix configuration.");
        var sender=new JavaMailSenderImpl();sender.setHost("localhost");sender.setPort(25);
        var properties=sender.getJavaMailProperties();properties.setProperty("mail.smtp.auth","false");
        properties.setProperty("mail.smtp.starttls.enable","false");properties.setProperty("mail.smtp.starttls.required","false");
        properties.setProperty("mail.smtp.connectiontimeout","3000");properties.setProperty("mail.smtp.timeout","3000");
        properties.setProperty("mail.smtp.writetimeout","3000");
        return sender;
    }
    @Bean IncidentEmailNotifications incidentEmailNotifications(IncidentEmailNotifications.Settings settings,
            Environment env,org.springframework.beans.factory.ObjectProvider<JavaMailSender> senders,
            org.springframework.beans.factory.ObjectProvider<IncidentEmailDetailAuthority> authorities,
            @org.springframework.beans.factory.annotation.Qualifier("incidentEmailExecutor") java.util.concurrent.Executor executor) {
        return new IncidentEmailNotifications(settings, env, senders, executor,
                new IncidentEmailDetailPolicy(env, authorities::stream));
    }
}
