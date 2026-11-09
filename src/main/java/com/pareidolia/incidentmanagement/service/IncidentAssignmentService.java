package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.IncidentResponseDto;
import com.pareidolia.incidentmanagement.dto.IncidentTransferRequest;
import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.*;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static com.pareidolia.incidentmanagement.service.EligibleHandlerDirectory.Employee;

/** Stable-ID assignment. No operation here creates a capability, eligibility or incident-access grant. */
@Service
@ConditionalOnProperty(name={"app.incident-assignment.enabled","app.incident-access.enabled","app.employee-management.enabled"},havingValue="true")
public class IncidentAssignmentService {
    public record State(long incidentId,String classification,long classificationVersion,long version,Employee handler,Employee proposal,boolean canAssign) { }
    public record QueueItem(long incidentId,String incidentNumber,String classification) { }
    public record TriageDetail(IncidentResponseDto incident,State assignment) { }
    public record Audit(long version,long actorId,Long previousHandlerId,Long newHandlerId,String action,String reason,String changedAt) { }
    private final EntityManager em;private final AppUserService users;private final IncidentRepository incidents;
    private final IncidentHistoryRepository history;private final IncidentMapper mapper;private final IncidentAccessPolicy policy;
    private final IncidentSecurityGate gate;private final IncidentReadSnapshot snapshot;private final EligibleHandlerDirectory directory;
    public record TransferResult(long incidentId, long responsibleDepartmentId, long handlerUserId, long version,
                                 long classificationVersion) { }
    public record TransferDiscoveryState(long incidentId, long sourceDepartmentId, long assignmentVersion,
                                         long classificationVersion) { }
    public record TransferDestination(long departmentId, String displayName) { }
    public record TransferOptions(TransferDiscoveryState state, List<TransferDestination> destinations) { }
    public record TransferHandlers(TransferDiscoveryState state, long destinationDepartmentId, List<Employee> handlers) { }
    private record TransferDiscovery(AppUser actor, Incident incident, String classification, TransferDiscoveryState state) { }

    private final Set<String> allowedPairs;
    private final Set<String> transferScopes;
    private final boolean transferHandoffApproved;
    @Value("${app.incident-transfer.allowed-handoff-reviewer-routes:}")
    private String handoffReviewerRoutes;
    public IncidentAssignmentService(EntityManager em,AppUserService users,IncidentRepository incidents,IncidentHistoryRepository history,IncidentMapper mapper,IncidentAccessPolicy policy,IncidentSecurityGate gate,IncidentReadSnapshot snapshot,EligibleHandlerDirectory directory,
            @Value("${app.incident-assignment.allowed-actor-handler-pairs:}") String pairs,
            @Value("${app.incident-transfer.allowed-coordinator-routes:}") String coordinatorRoutes,
            @Value("${app.incident-transfer.handoff-approved:false}") boolean transferHandoffApproved){
        this.em=em;this.users=users;this.incidents=incidents;this.history=history;this.mapper=mapper;this.policy=policy;this.gate=gate;this.snapshot=snapshot;this.directory=directory;
        var parsed=new HashSet<String>();for(String pair:pairs.split(",")){pair=pair.trim();if(pair.isEmpty())continue;if(!pair.matches("[1-9][0-9]*:[1-9][0-9]*"))throw new IllegalArgumentException("Invalid assignment scope pair.");parsed.add(pair);}this.allowedPairs=Set.copyOf(parsed);
        var routes = new HashSet<String>();
        for (String route : coordinatorRoutes.split(",")) {
            route = route.trim();
            if (route.isEmpty()) continue;
            if (!route.matches("[1-9][0-9]*:[1-9][0-9]*:[1-9][0-9]*")) {
                throw new IllegalArgumentException("Invalid incident transfer coordinator route.");
            }
            routes.add(route);
        }
        this.transferScopes = Set.copyOf(routes);
        this.transferHandoffApproved = transferHandoffApproved;
    }
    private AppUser actor(){
        if(!policy.isEnabled())throw denied();
        var auth=SecurityContextHolder.getContext().getAuthentication();
        if(auth==null || !auth.isAuthenticated() || !(auth.getPrincipal() instanceof OidcUser oidc) || !Boolean.TRUE.equals(oidc.getEmailVerified()) || oidc.getEmail()==null)throw denied();
        var actor=users.getAuthenticatedUser();if(em.contains(actor))em.refresh(actor);
        var rows=em.createNativeQuery("select active,email from app_users where id=?1").setParameter(1,actor.getId()).getResultList();
        if(rows.size()!=1)throw denied();Object[] row=(Object[])rows.get(0);
        if(!active(row[0]) || !AppUserService.normalizeEmail((String)row[1]).equals(AppUserService.normalizeEmail(oidc.getEmail())))throw denied();return actor;
    }
    private boolean capability(AppUser actor,String cap){var rows=em.createNativeQuery("select active from assignment_admin_capabilities where user_id=?1 and capability=?2").setParameter(1,actor.getId()).setParameter(2,cap).getResultList();return rows.size()==1 && active(rows.get(0));}
    private Incident incident(Long id){if(id==null || id<=0)throw missing();return incidents.findById(id).orElseThrow(IncidentAssignmentService::missing);}
    private boolean canView(AppUser actor,Incident incident){
        return !(actor.getRole()==AppUserRole.REPORTER && !actor.getEmail().equalsIgnoreCase(incident.getReportedBy()))
            && policy.can(actor,incident,IncidentAccessPolicy.Permission.VIEW);
    }
    private void view(AppUser actor,Incident incident){if(!canView(actor,incident))throw missing();}
    private void lockAccounts(Long... ids){for(Long id:new TreeSet<>(Arrays.asList(ids)))if(em.createNativeQuery("select id from app_users where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw denied();}
    private Incident lockedIncident(Long id){if(id==null || id<=0 || em.createNativeQuery("select id from incidents where id=?1 for update").setParameter(1,id).getResultList().size()!=1)throw missing();var incident=incident(id);em.refresh(incident,jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);return incident;}
    private Object[] classification(Long id){var rows=em.createNativeQuery("select classification,version from incident_security_classification where incident_id=?1").setParameter(1,id).getResultList();return rows.isEmpty()?new Object[]{"UNCLASSIFIED",0L}:(Object[])rows.get(0);}
    private boolean grant(Long incident,Long user,String permission){var rows=em.createNativeQuery("select active from incident_security_grants where incident_id=?1 and user_id=?2 and permission=?3").setParameter(1,incident).setParameter(2,user).setParameter(3,permission).getResultList();return rows.size()==1 && active(rows.get(0));}
    private boolean assignable(AppUser actor,Incident incident,String classification){return policy.allowsHrOperations(actor, incident) && directory.activeDepartment(incident.getResponsibleDepartmentId())
            && (!IncidentConfidentiality.requiresRestriction(incident, incidents) || classification.equals("RESTRICTED"))
            && Set.of("STANDARD","RESTRICTED").contains(classification) && incident.getStatus()!=IncidentStatus.CLOSED && capability(actor,"ASSIGNMENT_ADMIN") && canView(actor,incident) && (!classification.equals("RESTRICTED") || grant(incident.getId(),actor.getId(),"ASSIGN"));}
    private boolean handlerAllowed(AppUser actor, Incident incident, Employee handler) {
        return handlerAllowed(actor, incident.getId(), incident.getResponsibleDepartmentId(), handler);
    }
    private boolean handlerAllowed(AppUser actor, Long incidentId, Long departmentId, Employee handler) {
        AppUser handlerAccount = em.find(AppUser.class, handler.id());
        return policy.allowsHrOperations(handlerAccount, incident(incidentId))
                && policy.allowsHrDestination(handlerAccount, departmentId, incidents.findActiveResponsibleDepartmentName(departmentId).orElse(null))
                && directory.activeMember(departmentId, handler.id())
                && allowedPairs.contains(actor.getId()+":"+handler.id())
                && grant(incidentId,handler.id(),"VIEW") && grant(incidentId,handler.id(),"HANDLE");
    }
    private State state(AppUser actor,Incident incident){
        Object[] c=classification(incident.getId());var rows=em.createNativeQuery("select handler_user_id,proposed_handler_user_id,assignment_version from incident_assignment_state where incident_id=?1").setParameter(1,incident.getId()).getResultList();
        Long handler=null,proposal=null;long version=0;if(!rows.isEmpty()){Object[] r=(Object[])rows.get(0);handler=nullable(r[0]);proposal=nullable(r[1]);version=number(r[2]);}
        return new State(incident.getId(),(String)c[0],number(c[1]),version,directory.identity(handler),directory.identity(proposal),assignable(actor,incident,(String)c[0]));
    }
    @Transactional(readOnly=true)
    public List<Employee> search(String search,Long incidentId){return snapshot.read(()->{
        var actor=actor();if(incidentId==null){if(!Set.of(AppUserRole.REPORTER,AppUserRole.ADMIN).contains(actor.getRole()))throw denied();return directory.search(search).stream().limit(10).toList();}
        var incident=incident(incidentId);view(actor,incident);String c=(String)classification(incidentId)[0];if(!assignable(actor,incident,c))throw denied();
        return directory.search(search).stream().filter(e->handlerAllowed(actor,incident,e)).limit(10).toList();
    });}
    @Transactional(readOnly=true)
    public State get(Long id){return snapshot.read(()->{var actor=actor();var incident=incident(id);
        if (!policy.useGlobalView(actor, List.of(incident), IncidentAccessPolicy.ReadOperation.ASSIGNMENT_STATE)) view(actor,incident);
        return state(actor,incident);});}
    @Transactional(readOnly=true)
    public List<Audit> history(Long id){return snapshot.read(()->{var actor=actor();var incident=incident(id);
        if (!policy.useGlobalView(actor, List.of(incident), IncidentAccessPolicy.ReadOperation.ASSIGNMENT_HISTORY)) view(actor,incident);
        @SuppressWarnings("unchecked") List<Object[]> rows=em.createNativeQuery("select assignment_version,actor_user_id,previous_handler_user_id,new_handler_user_id,action_type,reason,changed_at from incident_assignment_audit where incident_id=?1 order by assignment_version desc").setParameter(1,id).setMaxResults(200).getResultList();
        return rows.stream().map(r->new Audit(number(r[0]),number(r[1]),nullable(r[2]),nullable(r[3]),(String)r[4],(String)r[5],String.valueOf(r[6]))).toList();
    });}
    @Transactional(readOnly=true)
    public List<QueueItem> triage(){return snapshot.read(()->{
        var actor=actor();boolean classifier=capability(actor,"INCIDENT_CLASSIFIER"),assigner=capability(actor,"ASSIGNMENT_ADMIN");if(!classifier && !assigner)throw denied();
        var candidates=incidents.findAllByOrderByCreatedAtDescIdDesc(org.springframework.data.domain.PageRequest.of(0,100));var result=new ArrayList<QueueItem>();
        for(var incident:candidates){if (!policy.allowsHrScope(actor, incident)) continue; String c=(String)classification(incident.getId())[0];if(c.equals("UNCLASSIFIED") && classifier || c.equals("STANDARD") && assigner && canView(actor,incident))result.add(new QueueItem(incident.getId(),incident.getIncidentNumber(),c));}return List.copyOf(result);
    });}
    @Transactional(readOnly=true)
    public TriageDetail triageDetail(Long id){return snapshot.read(()->{
        var actor=actor();var incident=incident(id);if (!policy.allowsHrScope(actor, incident)) throw missing();String c=(String)classification(id)[0];
        if(c.equals("UNCLASSIFIED")){if(!capability(actor,"INCIDENT_CLASSIFIER"))throw missing();}
        else {if(!capability(actor,"ASSIGNMENT_ADMIN") && !capability(actor,"INCIDENT_CLASSIFIER"))throw missing();view(actor,incident);}
        return new TriageDetail(mapper.toResponseDto(incident),state(actor,incident));
    });}
    /** Called in the creation transaction; proposal is inert, including when no handler was selected. */
    @Transactional
    public void initialize(Incident incident,Long proposedHandler){
        gate.write();var actor=actor();if(!Set.of(AppUserRole.REPORTER,AppUserRole.ADMIN).contains(actor.getRole()) || !actor.getEmail().equalsIgnoreCase(incident.getReportedBy()))throw denied();
        if (proposedHandler != null) {
            lockAccounts(actor.getId(), proposedHandler);
            directory.requireEligible(proposedHandler);
            if (!directory.activeMember(incident.getResponsibleDepartmentId(), proposedHandler)) throw denied();
        }
        em.createNativeQuery("insert into incident_security_classification(incident_id,classification,version) values (?1,'UNCLASSIFIED',0)").setParameter(1,incident.getId()).executeUpdate();
        em.createNativeQuery("insert into incident_assignment_state(incident_id,handler_user_id,proposed_handler_user_id,assignment_version) values (?1,null,?2,0)").setParameter(1,incident.getId()).setParameter(2,proposedHandler).executeUpdate();
    }
    @Transactional
    public State assign(Long id,Long handlerId,Long expectedVersion,Long expectedClassificationVersion,String reason){
        gate.write();if(handlerId==null || handlerId<=0 || expectedVersion==null || expectedVersion<0 || expectedClassificationVersion==null || expectedClassificationVersion<0 || reason==null || reason.isBlank() || reason.length()>500)throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Handler, versions and reason are required.");
        var actor=actor();lockAccounts(actor.getId(),handlerId);var incident=lockedIncident(id);actor=actor();view(actor,incident);
        var c=classification(id);if(!assignable(actor,incident,(String)c[0]))throw denied();if(number(c[1])!=expectedClassificationVersion)throw conflict();
        var handler=directory.requireEligible(handlerId);
        var capabilities=capability(actor,"ASSIGNMENT_ADMIN")?Set.of(com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.Capability.ASSIGNMENT_ADMIN):Set.<com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.Capability>of();
        var actorPermissions=grant(id,actor.getId(),"ASSIGN")?Set.of(com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.CasePermission.ASSIGN):Set.<com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.CasePermission>of();
        var handlerPermissions=grant(id,handlerId,"HANDLE")?Set.of(com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.CasePermission.HANDLE):Set.<com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.CasePermission>of();
        if(!handlerAllowed(actor,incident,handler) || !com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.canAssign(true,capabilities,
                com.pareidolia.incidentmanagement.assignment.AssignmentAuthorizationPolicy.Classification.valueOf((String)c[0]),true,true,allowedPairs.contains(actor.getId()+":"+handlerId),actorPermissions,handlerPermissions,true))throw denied();
        var rows=em.createNativeQuery("select handler_user_id,assignment_version from incident_assignment_state where incident_id=?1 for update").setParameter(1,id).getResultList();Long previous=null;long version=0;
        if(!rows.isEmpty()){Object[] r=(Object[])rows.get(0);previous=nullable(r[0]);version=number(r[1]);}if(version!=expectedVersion)throw conflict();if(Objects.equals(previous,handlerId))throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Select a different handler.");
        long next=Math.addExact(version,1);if(rows.isEmpty())em.createNativeQuery("insert into incident_assignment_state(incident_id,handler_user_id,assignment_version) values (?1,?2,?3)").setParameter(1,id).setParameter(2,handlerId).setParameter(3,next).executeUpdate();
        else if(em.createNativeQuery("update incident_assignment_state set handler_user_id=?2,assignment_version=?3 where incident_id=?1 and assignment_version=?4").setParameter(1,id).setParameter(2,handlerId).setParameter(3,next).setParameter(4,version).executeUpdate()!=1)throw conflict();
        if(em.createNativeQuery("insert into incident_assignment_audit(incident_id,actor_user_id,previous_handler_user_id,new_handler_user_id,assignment_version,action_type,reason) values (?1,?2,?3,?4,?5,?6,?7)").setParameter(1,id).setParameter(2,actor.getId()).setParameter(3,previous).setParameter(4,handlerId).setParameter(5,next).setParameter(6,previous==null?"INITIAL":"REASSIGN").setParameter(7,reason.trim()).executeUpdate()!=1)throw new IllegalStateException("Assignment audit failed.");
        var entry=new IncidentHistory();entry.setIncident(incident);entry.setActionType(HistoryActionType.OWNER_ASSIGNED);entry.setChangedBy(actor.getEmail());entry.setOldValue(incident.getAssignedOwner());entry.setNewValue(handler.email());entry.setRemarks(reason.trim());history.save(entry);
        incident.setAssignedOwner(handler.email()); // Display/report snapshot only. Stable state ID is authoritative.
        if(incident.getStatus()==IncidentStatus.OPEN){var status=new IncidentHistory();status.setIncident(incident);status.setActionType(HistoryActionType.STATUS_CHANGED);status.setChangedBy(actor.getEmail());status.setOldValue("OPEN");status.setNewValue("ASSIGNED");status.setRemarks(reason.trim());history.save(status);incident.setStatus(IncidentStatus.ASSIGNED);}
        incidents.saveAndFlush(incident);return state(actor,incident);
    }
    public TransferOptions transferOptions(Long id) {
        return snapshot.read(() -> {
            TransferDiscovery discovery = transferDiscovery(id);
            var destinations = incidents.findActiveResponsibleDepartments().stream()
                    .filter(department -> destinationAllowed(discovery, department.getId(), department.getDisplayName()))
                    .map(department -> new TransferDestination(department.getId(), department.getDisplayName()))
                    .toList();
            return new TransferOptions(discovery.state(), destinations);
        });
    }

    public TransferHandlers transferHandlers(Long id, Long destinationDepartmentId, String search) {
        return snapshot.read(() -> {
            TransferDiscovery discovery = transferDiscovery(id);
            if (!positive(destinationDepartmentId) || destinationDepartmentId.equals(discovery.state().sourceDepartmentId())
                    || !transferRouteAllowed(discovery.actor(), discovery.state().sourceDepartmentId(), destinationDepartmentId)) {
                throw denied();
            }
            String name = incidents.findActiveResponsibleDepartmentName(destinationDepartmentId)
                    .orElseThrow(IncidentAssignmentService::denied);
            if (!destinationAllowed(discovery, destinationDepartmentId, name)) throw denied();

            var handlers = directory.search(search).stream()
                    .filter(handler -> handlerAllowed(discovery.actor(), id, destinationDepartmentId, handler))
                    .limit(10).toList();
            return new TransferHandlers(discovery.state(), destinationDepartmentId, handlers);
        });
    }

    private TransferDiscovery transferDiscovery(Long id) {
        if (!transferHandoffApproved || !gate.held()) throw denied();
        AppUser actor = actor();
        if (!capability(actor, "ASSIGNMENT_ADMIN")) throw denied();

        Incident incident = incident(id);
        view(actor, incident);
        if (!grant(id, actor.getId(), "VIEW")) throw missing();
        if (!grant(id, actor.getId(), "ASSIGN")) throw denied();

        Long source = incident.getResponsibleDepartmentId();
        String routePrefix = actor.getId() + ":" + source + ":";
        if (source == null || transferScopes.stream().noneMatch(route ->
                route.startsWith(routePrefix) && !route.equals(routePrefix + source))) throw denied();

        Object[] classification = classification(id);
        String trust = (String) classification[0];
        if (!assignable(actor, incident, trust)) throw denied();

        var rows = em.createNativeQuery("""
                select handler_user_id, assignment_version from incident_assignment_state where incident_id = :id
                """).setParameter("id", id).getResultList();
        if (rows.size() != 1) throw conflict();
        Object[] current = (Object[]) rows.get(0);
        if (current[0] == null && incident.getAssignedOwner() != null) throw conflict();

        return new TransferDiscovery(actor, incident, trust,
                new TransferDiscoveryState(id, source, number(current[1]), number(classification[1])));
    }

    private boolean destinationAllowed(TransferDiscovery discovery, Long destinationId, String destinationName) {
        long source = discovery.state().sourceDepartmentId();
        return source != destinationId && transferRouteAllowed(discovery.actor(), source, destinationId)
                && policy.allowsHrDestination(discovery.actor(), destinationId, destinationName)
                && transferClassificationAllows(discovery.incident(), discovery.classification(), destinationId, destinationName);
    }

    private boolean transferRouteAllowed(AppUser actor, Long source, Long destination) {
        return transferScopes.contains(actor.getId() + ":" + source + ":" + destination);
    }

    private boolean transferClassificationAllows(Incident incident, String trust, Long destination, String destinationName) {
        String sourceName = incidents.findActiveResponsibleDepartmentName(incident.getResponsibleDepartmentId()).orElse(null);
        if (sourceName == null || (policy.isHrCase(incident, sourceName)
                && !policy.isHrCaseAtDepartment(incident, destination, destinationName))) return false;
        if (policy.isHrCaseAtDepartment(incident, destination, destinationName) && !"RESTRICTED".equals(trust)) return false;
        return IncidentConfidentiality.requiresRestriction(incident, destinationName) == "RESTRICTED".equals(trust);
    }

    @Transactional
    public TransferResult transfer(Long id, IncidentTransferRequest request) {
        validateTransfer(request);
        gate.write();
        AppUser actor = actor();
        Long source = request.expectedSourceDepartmentId();
        Long destination = request.destinationDepartmentId();
        Long handlerId = request.destinationHandlerUserId();
        if (!transferHandoffApproved || !transferRouteAllowed(actor, source, destination)
                || !capability(actor, "ASSIGNMENT_ADMIN")) {
            throw denied();
        }

        lockAccounts(actor.getId(), handlerId);
        Incident incident = lockedIncident(id);
        actor = actor();
        view(actor, incident);
        if (!grant(id, actor.getId(), "VIEW") || !grant(id, actor.getId(), "ASSIGN")) throw denied();
        if (!source.equals(incident.getResponsibleDepartmentId())) throw conflict();

        Object[] classification = classification(id);
        String trust = (String) classification[0];
        if (number(classification[1]) != request.expectedClassificationVersion()) throw conflict();
        if (!assignable(actor, incident, trust)) throw denied();

        Long first = Math.min(source, destination);
        Long second = Math.max(source, destination);
        String firstName = incidents.lockActiveResponsibleDepartmentName(first).orElseThrow(IncidentAssignmentService::denied);
        String secondName = incidents.lockActiveResponsibleDepartmentName(second).orElseThrow(IncidentAssignmentService::denied);
        String destinationName = destination.equals(first) ? firstName : secondName;
        // Reject a destination that would weaken the legacy confidentiality fallback or require stricter classification.
        if (!policy.allowsHrDestination(actor, destination, destinationName) || !transferClassificationAllows(incident, trust, destination, destinationName)) {
            throw denied();
        }

        Employee handler = directory.requireEligible(handlerId);
        if (!handlerAllowed(actor, id, destination, handler)) throw denied();

        var rows = em.createNativeQuery("""
                select handler_user_id, assignment_version from incident_assignment_state
                where incident_id = :id for update
                """).setParameter("id", id).getResultList();
        if (rows.size() != 1) throw conflict();
        Object[] current = (Object[]) rows.get(0);
        Long previousHandler = nullable(current[0]);
        long version = number(current[1]);
        if (version != request.expectedVersion() || (previousHandler == null && incident.getAssignedOwner() != null)) {
            throw conflict();
        }

        requireReconciledHandoff(actor, incident, previousHandler, handlerId, null);
        requireRecordedHandoffApproval(id, actor.getId(), request);
        long next = Math.addExact(version, 1);
        if (em.createNativeQuery("""
                update incident_assignment_state
                set handler_user_id = :handler, proposed_handler_user_id = null, assignment_version = :next
                where incident_id = :id and assignment_version = :version
                """).setParameter("handler", handlerId).setParameter("next", next).setParameter("id", id)
                .setParameter("version", version).executeUpdate() != 1) {
            throw conflict();
        }
        if (em.createNativeQuery("""
                insert into incident_department_transfer_audit
                    (incident_id, actor_user_id, source_department_id, destination_department_id,
                     previous_handler_user_id, new_handler_user_id, assignment_version, classification_version,
                     reason, handoff_approval_reference)
                values (:id, :actor, :source, :destination, :previous, :handler, :next, :classification, :reason, :approval)
                """).setParameter("id", id).setParameter("actor", actor.getId()).setParameter("source", source)
                .setParameter("destination", destination).setParameter("previous", previousHandler)
                .setParameter("handler", handlerId).setParameter("next", next)
                .setParameter("classification", request.expectedClassificationVersion())
                .setParameter("reason", request.reason().trim())
                .setParameter("approval", request.handoffApprovalReference()).executeUpdate() != 1) {
            throw new IllegalStateException("Incident transfer audit failed.");
        }

        if (!Objects.equals(incident.getAssignedOwner(), handler.email())) {
            recordTransferHistory(incident, actor, HistoryActionType.OWNER_ASSIGNED, incident.getAssignedOwner(), handler.email());
        }
        incident.setResponsibleDepartmentId(destination);
        incident.setAssignedOwner(handler.email());
        if (incident.getStatus() == IncidentStatus.OPEN) {
            recordTransferHistory(incident, actor, HistoryActionType.STATUS_CHANGED, "OPEN", "ASSIGNED");
            incident.setStatus(IncidentStatus.ASSIGNED);
        }
        incidents.saveAndFlush(incident);
        return new TransferResult(id, destination, handlerId, next, request.expectedClassificationVersion());
    }

    public record HandoffRequest(Long expectedSourceDepartmentId, Long destinationDepartmentId, Long destinationHandlerUserId,
                                 Long expectedVersion, Long expectedClassificationVersion, String reason) { }
    public record HandoffDecision(String action, Long expectedVersion, String reason) { }
    public record Handoff(String reference, long coordinatorId, long sourceDepartmentId, long destinationDepartmentId,
                          long handlerId, long assignmentVersion, long classificationVersion, String status, long version,
                          String requestReason, boolean canReview, boolean canRevoke, boolean canUse) { }
    public record HandoffAudit(long version, long actorId, String status, String reason, String changedAt) { }

    @Transactional
    public String requestHandoff(Long id, HandoffRequest request) {
        String reference = UUID.randomUUID().toString();
        var transfer = new IncidentTransferRequest(request.expectedSourceDepartmentId(), request.destinationDepartmentId(),
                request.destinationHandlerUserId(), request.expectedVersion(), request.expectedClassificationVersion(),
                request.reason(), reference);
        validateTransfer(transfer);
        gate.write();
        var discovery = transferDiscovery(id);
        var state = discovery.state();
        if (state.sourceDepartmentId() != transfer.expectedSourceDepartmentId()
                || state.assignmentVersion() != transfer.expectedVersion()
                || state.classificationVersion() != transfer.expectedClassificationVersion()) throw conflict();
        String destinationName = incidents.findActiveResponsibleDepartmentName(transfer.destinationDepartmentId())
                .orElseThrow(IncidentAssignmentService::denied);
        if (!destinationAllowed(discovery, transfer.destinationDepartmentId(), destinationName)
                || !handlerAllowed(discovery.actor(), id, transfer.destinationDepartmentId(),
                        directory.requireEligible(transfer.destinationHandlerUserId()))) throw denied();
        if (em.createNativeQuery("""
                insert into incident_transfer_handoff_approvals
                    (approval_reference, incident_id, coordinator_user_id, source_department_id, destination_department_id,
                     destination_handler_user_id, assignment_version, classification_version, decision_status, request_reason)
                values (:ref, :incident, :actor, :source, :destination, :handler, :version, :classification, 'PENDING', :reason)
                """).setParameter("ref", reference).setParameter("incident", id).setParameter("actor", discovery.actor().getId())
                .setParameter("source", state.sourceDepartmentId()).setParameter("destination", transfer.destinationDepartmentId())
                .setParameter("handler", transfer.destinationHandlerUserId()).setParameter("version", state.assignmentVersion())
                .setParameter("classification", state.classificationVersion()).setParameter("reason", transfer.reason().trim())
                .executeUpdate() != 1) throw conflict();
        auditHandoff(reference, 0, discovery.actor().getId(), "PENDING", transfer.reason().trim());
        return reference;
    }

    public List<Handoff> handoffs(Long id) {
        return snapshot.read(() -> {
            AppUser actor = handoffActor(id);
            var rows = em.createNativeQuery("""
                    select approval_reference, coordinator_user_id, source_department_id, destination_department_id,
                           destination_handler_user_id, assignment_version, classification_version,
                           case when decision_status='APPROVED' and expires_at <= current_timestamp then 'EXPIRED' else decision_status end,
                           decision_version, request_reason
                    from incident_transfer_handoff_approvals where incident_id=:incident
                    order by requested_at desc, approval_reference
                    """).setParameter("incident", id).setMaxResults(101).getResultList();
            if (rows.size() > 100) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Handoff history limit exceeded.");
            return rows.stream().map(row -> handoff(actor, (Object[]) row)).filter(Objects::nonNull).toList();
        });
    }

    public List<HandoffAudit> handoffHistory(Long id, String reference) {
        return snapshot.read(() -> {
            requireHandoff(handoffActor(id), id, reference);
            @SuppressWarnings("unchecked")
            List<Object[]> rows = em.createNativeQuery("""
                    select decision_version, actor_user_id, decision_status, reason, changed_at
                    from incident_transfer_handoff_audit where approval_reference=:ref order by decision_version
                    """).setParameter("ref", reference).getResultList();
            return rows.stream().map(row -> new HandoffAudit(number(row[0]), number(row[1]), (String) row[2],
                    (String) row[3], String.valueOf(row[4]))).toList();
        });
    }

    @Transactional
    public void decideHandoff(Long id, String reference, HandoffDecision decision) {
        if (decision.action() == null || !Set.of("APPROVED", "REJECTED", "REVOKED").contains(decision.action())
                || decision.expectedVersion() == null || decision.expectedVersion() < 0
                || decision.reason() == null || decision.reason().isBlank() || decision.reason().length() > 500) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A decision, version and reason are required.");
        }
        gate.write();
        AppUser reviewer = handoffActor(id);
        Handoff handoff = requireHandoff(reviewer, id, reference);
        boolean revoke = "REVOKED".equals(decision.action());
        boolean approve = "APPROVED".equals(decision.action());
        if (!(revoke ? handoff.canRevoke() : handoff.canReview())) throw denied();
        if (handoff.version() != decision.expectedVersion()) throw conflict();
        if (approve) {
            Incident current = incident(id);
            State state = state(reviewer, current);
            if (!Objects.equals(current.getResponsibleDepartmentId(), handoff.sourceDepartmentId())
                    || current.getStatus() == IncidentStatus.CLOSED || state.version() != handoff.assignmentVersion()
                    || state.classificationVersion() != handoff.classificationVersion()
                    || !transferScopes.contains(handoff.coordinatorId() + ":" + handoff.sourceDepartmentId() + ":" + handoff.destinationDepartmentId())) throw conflict();
            AppUser coordinator = em.find(AppUser.class, handoff.coordinatorId());
            var handler = directory.requireEligible(handoff.handlerId());
            String destinationName = incidents.findActiveResponsibleDepartmentName(handoff.destinationDepartmentId())
                    .orElseThrow(IncidentAssignmentService::denied);
            if (coordinator == null || !Boolean.TRUE.equals(coordinator.getActive()) || !capability(coordinator, "ASSIGNMENT_ADMIN")
                    || !policy.allowsHrOperations(coordinator, current)
                    || !policy.allowsHrDestination(reviewer, handoff.destinationDepartmentId(), destinationName)
                    || !policy.allowsHrDestination(coordinator, handoff.destinationDepartmentId(), destinationName)
                    || !grant(id, handoff.coordinatorId(), "VIEW") || !grant(id, handoff.coordinatorId(), "ASSIGN")
                    || !directory.activeDepartment(handoff.sourceDepartmentId())
                    || !transferClassificationAllows(current, state.classification(), handoff.destinationDepartmentId(), destinationName)
                    || !handlerAllowed(coordinator, id, handoff.destinationDepartmentId(), handler)) throw denied();
            var previous = em.createNativeQuery("select handler_user_id from incident_assignment_state where incident_id=:id")
                    .setParameter("id", id).getResultList();
            if (previous.size() != 1) throw conflict();
            requireReconciledHandoff(coordinator, current, nullable(previous.get(0)), handoff.handlerId(), reviewer.getId());
        }
        long next = Math.addExact(handoff.version(), 1);
        if (em.createNativeQuery("""
                update incident_transfer_handoff_approvals set decision_status=:action, decision_version=:next,
                    approved_by_user_id=case when :approve=1 then :actor else approved_by_user_id end,
                    approved_at=case when :approve=1 then current_timestamp else approved_at end,
                    expires_at=case when :approve=1 then timestampadd(hour, 24, current_timestamp) else expires_at end,
                    revoked_at=case when :revoke=1 then current_timestamp else revoked_at end
                where incident_id=:incident and approval_reference=:ref and decision_version=:version
                """).setParameter("action", decision.action()).setParameter("next", next).setParameter("actor", reviewer.getId())
                .setParameter("approve", approve ? 1 : 0).setParameter("revoke", revoke ? 1 : 0)
                .setParameter("incident", id).setParameter("ref", reference).setParameter("version", handoff.version())
                .executeUpdate() != 1) throw conflict();
        auditHandoff(reference, next, reviewer.getId(), decision.action(), decision.reason().trim());
    }

    private AppUser handoffActor(Long id) {
        if (!transferHandoffApproved || !gate.held()) throw denied();
        AppUser actor = actor();
        Incident item = incident(id);
        if (!policy.allowsHrOperations(actor, item)) throw missing();
        view(actor, item);
        if (!grant(id, actor.getId(), "VIEW")) throw missing();
        return actor;
    }

    private Handoff requireHandoff(AppUser actor, Long id, String reference) {
        var rows = em.createNativeQuery("""
                select approval_reference, coordinator_user_id, source_department_id, destination_department_id,
                       destination_handler_user_id, assignment_version, classification_version,
                       case when decision_status='APPROVED' and expires_at <= current_timestamp then 'EXPIRED' else decision_status end,
                           decision_version, request_reason
                from incident_transfer_handoff_approvals where incident_id=:incident and approval_reference=:ref
                """ + gate.sharedClause()).setParameter("incident", id).setParameter("ref", reference).getResultList();
        if (rows.size() != 1) throw missing();
        Handoff result = handoff(actor, (Object[]) rows.get(0));
        if (result == null || !result.reference().equals(reference)) throw missing();
        return result;
    }

    private Handoff handoff(AppUser actor, Object[] row) {
        long coordinator = number(row[1]), source = number(row[2]), destination = number(row[3]), handler = number(row[4]);
        String status = (String) row[7];
        boolean reviewer = actor.getId() != coordinator && actor.getId() != handler
                && handoffReviewerAllowed(actor.getId(), source, destination);
        if (actor.getId() != coordinator && !reviewer) return null;
        return new Handoff((String) row[0], coordinator, source, destination, handler, number(row[5]),
                number(row[6]), status, number(row[8]), (String) row[9],
                reviewer && "PENDING".equals(status), reviewer && "APPROVED".equals(status),
                actor.getId() == coordinator && "APPROVED".equals(status));
    }

    private boolean handoffReviewerAllowed(long reviewer, long source, long destination) {
        String scope = reviewer + ":" + source + ":" + destination;
        return Arrays.stream(handoffReviewerRoutes.split(",")).map(String::trim).anyMatch(scope::equals);
    }

    private void auditHandoff(String reference, long version, long actor, String status, String reason) {
        if (em.createNativeQuery("""
                insert into incident_transfer_handoff_audit (approval_reference, decision_version, actor_user_id, decision_status, reason)
                values (:ref, :version, :actor, :status, :reason)
                """).setParameter("ref", reference).setParameter("version", version).setParameter("actor", actor)
                .setParameter("status", status).setParameter("reason", reason).executeUpdate() != 1) {
            throw new IllegalStateException("Handoff audit failed.");
        }
    }

    private void requireRecordedHandoffApproval(Long incidentId, Long actorId, IncidentTransferRequest request) {
        var approvals = em.createNativeQuery("""
                select a.approval_reference, a.approved_by_user_id
                from incident_transfer_handoff_approvals a
                join app_users approver on approver.id = a.approved_by_user_id
                join incident_transfer_handoff_audit audit on audit.approval_reference = a.approval_reference
                    and audit.decision_version = a.decision_version and audit.actor_user_id = a.approved_by_user_id
                    and audit.decision_status = 'APPROVED'
                where a.approval_reference = :reference and a.incident_id = :incident
                  and a.coordinator_user_id = :actor and a.source_department_id = :source
                  and a.destination_department_id = :destination and a.destination_handler_user_id = :handler
                  and a.assignment_version = :assignment and a.classification_version = :classification
                  and a.decision_status = 'APPROVED' and a.revoked_at is null and a.expires_at > current_timestamp
                  and approver.active = 1
                """ + gate.sharedClause())
                .setParameter("reference", request.handoffApprovalReference()).setParameter("incident", incidentId)
                .setParameter("actor", actorId).setParameter("source", request.expectedSourceDepartmentId())
                .setParameter("destination", request.destinationDepartmentId())
                .setParameter("handler", request.destinationHandlerUserId())
                .setParameter("assignment", request.expectedVersion())
                .setParameter("classification", request.expectedClassificationVersion()).getResultList();
        Object[] approval = approvals.size() == 1 ? (Object[]) approvals.get(0) : null;
        if (approval == null || !request.handoffApprovalReference().equals(approval[0])
                || !handoffReviewerAllowed(number(approval[1]), request.expectedSourceDepartmentId(), request.destinationDepartmentId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Case access requires independent handoff review.");
        }
    }

    private void requireReconciledHandoff(AppUser actor, Incident incident, Long previousHandler, Long destinationHandler, Long reviewingUser) {
        @SuppressWarnings("unchecked")
        List<Object[]> grants = em.createNativeQuery("""
                select g.user_id, u.email, g.permission
                from incident_security_grants g join app_users u on u.id = g.user_id
                where g.incident_id = :id and g.active = 1
                """).setParameter("id", incident.getId()).getResultList();
        String reporter = AppUserService.normalizeEmail(incident.getReportedBy());
        for (Object[] row : grants) {
            long userId = number(row[0]);
            String permission = (String) row[2];
            boolean formerHandler = Objects.equals(previousHandler, userId) && userId != destinationHandler;
            boolean approved = (Objects.equals(reviewingUser, userId) && "VIEW".equals(permission))
                    || (userId == actor.getId() && Set.of("VIEW", "ASSIGN").contains(permission))
                    || (userId == destinationHandler && Set.of("VIEW", "HANDLE").contains(permission))
                    || (!reporter.isEmpty() && reporter.equals(AppUserService.normalizeEmail((String) row[1]))
                        && "VIEW".equals(permission));
            if (formerHandler || !approved) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Case access requires independent handoff review.");
            }
        }
    }

    private void recordTransferHistory(Incident incident, AppUser actor, HistoryActionType action, String before, String after) {
        var entry = new IncidentHistory();
        entry.setIncident(incident);
        entry.setActionType(action);
        entry.setChangedBy(actor.getEmail());
        entry.setOldValue(before);
        entry.setNewValue(after);
        // Keep transfer reasons and approval references in the restricted transfer audit.
        history.save(entry);
    }

    private static void validateTransfer(IncidentTransferRequest request) {
        if (request == null || !positive(request.expectedSourceDepartmentId()) || !positive(request.destinationDepartmentId())
                || request.expectedSourceDepartmentId().equals(request.destinationDepartmentId())
                || !positive(request.destinationHandlerUserId()) || request.expectedVersion() == null || request.expectedVersion() < 0
                || request.expectedClassificationVersion() == null || request.expectedClassificationVersion() < 0
                || request.reason() == null || request.reason().isBlank() || request.reason().length() > 500
                || request.handoffApprovalReference() == null
                || !request.handoffApprovalReference().matches(IncidentTransferRequest.APPROVAL_REFERENCE_PATTERN)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Distinct departments, a handler, current versions, a reason and a handoff approval reference are required.");
        }
    }

    private static boolean positive(Long id) {
        return id != null && id > 0;
    }

    private static long number(Object o){return ((Number)o).longValue();}private static Long nullable(Object o){return o==null?null:number(o);}
    private static boolean active(Object o){return Boolean.TRUE.equals(o) || o instanceof Number n && n.intValue()==1;}
    private static AccessDeniedException denied(){return new AccessDeniedException("Access denied.");}
    private static ResponseStatusException missing(){return new ResponseStatusException(HttpStatus.NOT_FOUND,"Incident not found.");}
    private static ResponseStatusException conflict(){return new ResponseStatusException(HttpStatus.CONFLICT,"Assignment or classification changed. Reload and confirm again.");}
}
