package com.pareidolia.incidentmanagement.assignment;

import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.*;

class AssignmentAuthorizationPolicyTests {
    @Test void classificationRequiresIndependentCapabilityReasonAndElevatedDowngrade() {
        assertThat(canClassify(true,Set.of(Capability.ASSIGNMENT_ADMIN),Classification.UNCLASSIFIED,Classification.STANDARD,true)).isFalse();
        assertThat(canClassify(true,Set.of(Capability.INCIDENT_CLASSIFIER),Classification.UNCLASSIFIED,Classification.STANDARD,true)).isTrue();
        assertThat(canClassify(true,Set.of(Capability.INCIDENT_CLASSIFIER),Classification.RESTRICTED,Classification.STANDARD,true)).isFalse();
        assertThat(canClassify(true,Set.of(Capability.INCIDENT_CLASSIFIER,Capability.RESTRICTED_DOWNGRADE),Classification.RESTRICTED,Classification.STANDARD,true)).isTrue();
        assertThat(canClassify(true,Set.of(Capability.INCIDENT_CLASSIFIER),Classification.UNCLASSIFIED,Classification.STANDARD,false)).isFalse();
    }
    @Test void standardRequiresExplicitCapabilityEligibleActiveHandlerScopeAndReason() {
        var admin=Set.of(Capability.ASSIGNMENT_ADMIN);
        assertThat(canAssign(true,admin,Classification.STANDARD,true,true,true,null,null,true)).isTrue();
        assertThat(canAssign(true,Set.of(Capability.INCIDENT_CLASSIFIER),Classification.STANDARD,true,true,true,null,null,true)).isFalse();
        assertThat(canAssign(true,admin,Classification.UNCLASSIFIED,true,true,true,null,null,true)).isFalse();
        assertThat(canAssign(true,admin,Classification.STANDARD,false,true,true,null,null,true)).isFalse();
        assertThat(canAssign(true,admin,Classification.STANDARD,true,false,true,null,null,true)).isFalse();
        assertThat(canAssign(true,admin,Classification.STANDARD,true,true,false,null,null,true)).isFalse();
        assertThat(canAssign(true,admin,Classification.STANDARD,true,true,true,null,null,false)).isFalse();
    }
    @Test void restrictedRequiresActorAndHandlerSpecificGrants() {
        var admin=Set.of(Capability.ASSIGNMENT_ADMIN);
        assertThat(canAssign(true,admin,Classification.RESTRICTED,true,true,true,Set.of(CasePermission.ASSIGN),Set.of(CasePermission.HANDLE),true)).isTrue();
        assertThat(canAssign(true,admin,Classification.RESTRICTED,true,true,true,Set.of(),Set.of(CasePermission.HANDLE),true)).isFalse();
        assertThat(canAssign(true,admin,Classification.RESTRICTED,true,true,true,Set.of(CasePermission.ASSIGN),Set.of(),true)).isFalse();
    }
    @Test void caseAccessAdministrationIsSeparateAndNeverSelfGranted() {
        assertThat(canManageCaseAccess(true,Set.of(Capability.CASE_ACCESS_ADMIN),1,2,true)).isTrue();
        assertThat(canManageCaseAccess(true,Set.of(Capability.ASSIGNMENT_ADMIN),1,2,true)).isFalse();
        assertThat(canManageCaseAccess(true,Set.of(Capability.CASE_ACCESS_ADMIN),1,1,true)).isFalse();
        assertThat(canManageCaseAccess(true,Set.of(Capability.CASE_ACCESS_ADMIN),1,2,false)).isFalse();
    }
}
