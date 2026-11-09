package com.pareidolia.incidentmanagement.assignment;

import java.util.Set;

/** Pure policy building block. Callers must load current trusted data under locks. */
public final class AssignmentAuthorizationPolicy {
    private AssignmentAuthorizationPolicy() { }
    public enum Classification { UNCLASSIFIED, STANDARD, RESTRICTED }
    public enum Capability { INCIDENT_CLASSIFIER, RESTRICTED_DOWNGRADE, ASSIGNMENT_ADMIN, CASE_ACCESS_ADMIN }
    public enum CasePermission { ASSIGN, HANDLE }

    public static boolean canClassify(boolean activeActor, Set<Capability> capabilities,
                                      Classification current, Classification requested, boolean hasReason) {
        if (!activeActor || capabilities == null || current == null || requested == null || !hasReason
                || current == requested || requested == Classification.UNCLASSIFIED
                || !capabilities.contains(Capability.INCIDENT_CLASSIFIER)) return false;
        return current != Classification.RESTRICTED || requested != Classification.STANDARD
                || capabilities.contains(Capability.RESTRICTED_DOWNGRADE);
    }

    /** Granting/revoking case access alone never grants classification or assignment. */
    public static boolean canManageCaseAccess(boolean activeActor, Set<Capability> capabilities,
                                               long actorId, long targetId, boolean hasReason) {
        return activeActor && capabilities != null && capabilities.contains(Capability.CASE_ACCESS_ADMIN)
                && actorId > 0 && targetId > 0 && actorId != targetId && hasReason;
    }

    /** A STANDARD assignment requires configured scope; restricted also needs both case permissions. */
    public static boolean canAssign(boolean activeActor, Set<Capability> capabilities,
                                    Classification classification, boolean activeHandler,
                                    boolean explicitHandlerEligibility, boolean scopeAllowed,
                                    Set<CasePermission> actorCasePermissions,
                                    Set<CasePermission> handlerCasePermissions, boolean hasReason) {
        if (!activeActor || capabilities == null || !capabilities.contains(Capability.ASSIGNMENT_ADMIN)
                || classification == null || classification == Classification.UNCLASSIFIED
                || !activeHandler || !explicitHandlerEligibility || !scopeAllowed || !hasReason) return false;
        if (classification == Classification.STANDARD) return true;
        return actorCasePermissions != null && actorCasePermissions.contains(CasePermission.ASSIGN)
                && handlerCasePermissions != null && handlerCasePermissions.contains(CasePermission.HANDLE);
    }
}
