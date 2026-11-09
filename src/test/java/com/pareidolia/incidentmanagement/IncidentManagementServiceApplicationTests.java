package com.pareidolia.incidentmanagement;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class IncidentManagementServiceApplicationTests {
    @org.springframework.test.context.bean.override.mockito.MockitoBean
    org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager authorizedClientManager;

    @org.springframework.test.context.bean.override.mockito.MockitoBean
    org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient<org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest> tokenClient;

    @org.springframework.beans.factory.annotation.Autowired
    org.springframework.context.ApplicationContext context;

    @Test
    void securityFoundationLoadsWithoutEnablingAdministrationOrAccess() {
        org.assertj.core.api.Assertions.assertThat(context.getBean(
                com.pareidolia.incidentmanagement.security.IncidentAccessActivationGuard.class)).isNotNull();
        var gate = context.getBean(com.pareidolia.incidentmanagement.security.IncidentSecurityGate.class);
        gate.read();
        gate.write();
        org.assertj.core.api.Assertions.assertThat(gate.held()).isFalse();

        var policy = context.getBean(com.pareidolia.incidentmanagement.security.IncidentAccessPolicy.class);
        org.assertj.core.api.Assertions.assertThat(policy.isEnabled()).isFalse();
        for (String name : java.util.List.of("incidentAssignmentService",
                "employeeDirectoryService", "incidentSecurityAdministrationService",
                "incidentCapabilityAdministrationService", "departmentMembershipAdminService", "departmentMembershipAdminController")) {
            org.assertj.core.api.Assertions.assertThat(context.containsBean(name)).as(name).isFalse();
        }
    }


    @Test
    void explicitIncidentAccessActivationIsRejected() {
        org.assertj.core.api.Assertions.assertThatIllegalStateException().isThrownBy(() ->
                new com.pareidolia.incidentmanagement.security.IncidentAccessActivationGuard(true));
    }

    @Test
    void membershipAdministrationRequiresTheSecurityGateEvenWhenIncidentAccessIsOff() {
        new org.springframework.boot.test.context.runner.ApplicationContextRunner()
                .withBean(jakarta.persistence.EntityManager.class,
                        () -> org.mockito.Mockito.mock(jakarta.persistence.EntityManager.class))
                .withUserConfiguration(com.pareidolia.incidentmanagement.security.IncidentSecurityGate.class)
                .withPropertyValues("app.incident-access.enabled=false", "app.department-membership-admin.enabled=true")
                .run(isolated -> org.assertj.core.api.Assertions.assertThatIllegalStateException()
                        .isThrownBy(isolated.getBean(com.pareidolia.incidentmanagement.security.IncidentSecurityGate.class)::write)
                        .withMessageContaining("read-write transaction"));
    }

	@Test
	void contextLoads() {
	}

}
