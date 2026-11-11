package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.controller.IncidentAttachmentController;
import com.pareidolia.incidentmanagement.dto.*;
import com.pareidolia.incidentmanagement.entity.IncidentHistory;
import com.pareidolia.incidentmanagement.enums.*;
import com.pareidolia.incidentmanagement.exception.GlobalExceptionHandler;
import com.pareidolia.incidentmanagement.exception.IncidentNotFoundException;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.*;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.*;
import java.io.ByteArrayOutputStream;
import java.sql.DriverManager;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jdbc.test.autoconfigure.AutoConfigureTestDatabase;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** One-shot opt-in proof against the UUID-pinned synthetic lifecycle schema. */
@EnabledIfEnvironmentVariable(named="INCIDENT_LIFECYCLE_MYSQL_PROOF",matches="true")
@DataJpaTest(properties={"spring.jpa.hibernate.ddl-auto=none","spring.sql.init.mode=never",
 "app.incident-access.enabled=true","app.incident-assignment.enabled=true","app.incident-security-admin.enabled=true","app.employee-management.enabled=true",
 "app.incident-access.hr-account-ids=1103,1106","app.incident-access.hr-department-ids=2",
 "app.incident-assignment.allowed-actor-handler-pairs=1103:1102,1103:1106",
 "app.auth.allowed-domain=example.test","app.auth.bootstrap-admin-emails=","app.auth.bootstrap-it-handler-emails=",
 "app.default-it-owner=unused@example.test","app.notifications.email.enabled=false"})
@AutoConfigureTestDatabase(replace=AutoConfigureTestDatabase.Replace.NONE)
@Import({IncidentSecurityGate.class,IncidentReadSnapshot.class,IncidentAccessPolicy.class,AppUserService.class,
 IncidentSecurityAdministrationService.class,IncidentServiceImpl.class,IncidentMapper.class,EligibleHandlerDirectory.class,
 IncidentAssignmentService.class,IncidentAttachmentServiceImpl.class,WorkLogServiceImpl.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class LifecycleMysqlProofTests {
 private static final String URL="jdbc:mysql://127.0.0.1:59455/incident_lifecycle_proof_20261111?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
 private static final String USER="lifecycle_test";
 private static final String UUID="a6563759-ddb5-11f1-9b7c-6e0023da6ea2";
 private static final Set<String> TABLES=Set.of("lifecycle_run_marker","app_users","employee_departments",
  "employee_department_memberships","handler_eligibility_grants","department_head_designations",
  "assignment_admin_capabilities","incident_security_lock","incidents","incident_security_classification",
  "incident_classification_audit","incident_security_grants","incident_security_grant_audit","incident_assignment_state",
  "incident_assignment_audit","incident_attachments","incident_history","work_log_entries");
 private static final Set<String> INSERTS=Set.of("incidents","incident_security_classification","incident_classification_audit",
  "incident_security_grants","incident_security_grant_audit","incident_assignment_state","incident_assignment_audit",
  "incident_attachments","incident_history","work_log_entries");
 private static final Map<String,String> UPDATES=Map.ofEntries(
  Map.entry("app_users","id"),Map.entry("employee_departments","id"),Map.entry("assignment_admin_capabilities","active"),
  Map.entry("incident_security_lock","id"),Map.entry("incident_security_classification","classification,version"),
  Map.entry("incident_security_grants","active,version"),Map.entry("incident_assignment_state","handler_user_id,assignment_version"),
  Map.entry("incidents","incident_number,reported_at,reported_by,reporter_department,responsible_department_id,desk_number,title,description,issue_type,category,affected_system,impacted_user_or_department,severity,priority,assigned_owner,status,investigation_details,root_cause,actions_taken,containment_action,corrective_action,escalation_required,escalation_details,resolution_details,resolved_at,validation_details,validated_by,validated_at,closure_confirmed_by,closed_at,review_details,reviewed_by,reviewed_at,evidence_reference,lessons_learned,preventive_action,updated_at"));
 @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
  String password=System.getenv("INCIDENT_LIFECYCLE_MYSQL_PASSWORD"), token=System.getenv("INCIDENT_LIFECYCLE_MYSQL_TOKEN");
  if(password==null || !password.matches("[a-f0-9]{64}") || token==null || !token.matches("[a-f0-9]{32}")) throw new IllegalStateException("Missing protected test credentials or marker.");
  verifyPreflight(password,token);
  registry.add("spring.datasource.url",()->URL);registry.add("spring.datasource.username",()->USER);registry.add("spring.datasource.password",()->password);
 }
 private static void verifyPreflight(String password,String token) {
  try(var c=DriverManager.getConnection(URL,USER,password);var s=c.createStatement()) {
   try(var r=s.executeQuery("select database(),@@server_uuid,version(),current_user(),current_role()")) {
    if(!r.next() || !"incident_lifecycle_proof_20261111".equals(r.getString(1)) || !UUID.equals(r.getString(2)) || !"8.4.11".equals(r.getString(3)) || !"lifecycle_test@172.22.0.1".equals(r.getString(4)) || !"NONE".equals(r.getString(5)) || r.next()) throw new IllegalStateException("Lifecycle database identity mismatch.");
   }
   try(var r=s.executeQuery("select token from lifecycle_run_marker")){if(!r.next() || !token.equals(r.getString(1)) || r.next())throw new IllegalStateException("Lifecycle run marker mismatch.");}
   try(var r=s.executeQuery("select (select count(*) from incident_security_lock),(select count(*) from incident_security_lock where id=1),(select count(*) from incidents),(select count(*) from app_users),(select count(*) from employee_departments),(select count(*) from employee_department_memberships),(select count(*) from handler_eligibility_grants),(select count(*) from assignment_admin_capabilities)")) {
    if(!r.next() || r.getInt(1)!=1 || r.getInt(2)!=1 || r.getInt(3)!=0 || r.getInt(4)!=7 || r.getInt(5)!=5 || r.getInt(6)!=2 || r.getInt(7)!=2 || r.getInt(8)!=4)throw new IllegalStateException("Lifecycle fixture is not fresh.");
   }
   Set<String> emails=new HashSet<>();try(var r=s.executeQuery("select email from app_users where active=1")){while(r.next())emails.add(r.getString(1));}
   if(!emails.equals(Set.of("lifecycle-reporter@example.test","lifecycle-handler@example.test","lifecycle-coordinator@example.test","lifecycle-reviewer@example.test","lifecycle-unrelated@example.test","lifecycle-hr-handler@example.test","lifecycle-hr-unrelated@example.test")))throw new IllegalStateException("Unexpected fixture identity.");
   String grantee="'lifecycle_test'@'172.22.0.1'";Set<String> tablePrivileges=new HashSet<>(),columnPrivileges=new HashSet<>(),global=new HashSet<>();
   try(var q=c.prepareStatement("select table_schema,table_name,privilege_type,is_grantable from information_schema.table_privileges where grantee=?")){q.setString(1,grantee);try(var r=q.executeQuery()){while(r.next()){if(!"incident_lifecycle_proof_20261111".equals(r.getString(1)) || !"NO".equals(r.getString(4)))throw new IllegalStateException("Unexpected table privilege.");tablePrivileges.add(r.getString(2)+":"+r.getString(3));}}}
   try(var q=c.prepareStatement("select table_schema,table_name,column_name,privilege_type,is_grantable from information_schema.column_privileges where grantee=?")){q.setString(1,grantee);try(var r=q.executeQuery()){while(r.next()){if(!"incident_lifecycle_proof_20261111".equals(r.getString(1)) || !"UPDATE".equals(r.getString(4)) || !"NO".equals(r.getString(5)))throw new IllegalStateException("Unexpected column privilege.");columnPrivileges.add(r.getString(2)+":"+r.getString(3));}}}
   try(var q=c.prepareStatement("select privilege_type,is_grantable from information_schema.user_privileges where grantee=?")){q.setString(1,grantee);try(var r=q.executeQuery()){while(r.next()){if(!"NO".equals(r.getString(2)))throw new IllegalStateException("Grant option is forbidden.");global.add(r.getString(1));}}}
   try(var q=c.prepareStatement("select count(*) from information_schema.schema_privileges where grantee=?")){q.setString(1,grantee);try(var r=q.executeQuery()){if(!r.next()||r.getInt(1)!=0)throw new IllegalStateException("Schema-wide privilege is forbidden.");}}
   Set<String> expectedTable=new HashSet<>(),expectedColumn=new HashSet<>();TABLES.forEach(t->expectedTable.add(t+":SELECT"));INSERTS.forEach(t->expectedTable.add(t+":INSERT"));UPDATES.forEach((t,cols)->Arrays.stream(cols.split(",")).forEach(col->expectedColumn.add(t+":"+col)));
   if(!global.equals(Set.of("USAGE")) || !tablePrivileges.equals(expectedTable) || !columnPrivileges.equals(expectedColumn))throw new IllegalStateException("Runtime privileges differ from the approved allowlist.");
   try(var r=s.executeQuery("show grants")){int count=0;while(r.next()){String line=r.getString(1);if(line.contains("WITH GRANT OPTION") || (!line.contains(" ON ") || (!line.contains("`incident_lifecycle_proof_20261111`.`") && !line.contains("USAGE ON *.*"))))throw new IllegalStateException("Unexpected effective grant.");count++;}if(count!=19)throw new IllegalStateException("Unexpected effective grant count.");}
  } catch(java.sql.SQLException ex){throw new IllegalStateException("Lifecycle preflight database verification failed.",ex);}
 }
 @Autowired JdbcTemplate db;@Autowired IncidentService service;@Autowired IncidentAssignmentService assignments;
 @Autowired IncidentSecurityAdministrationService administration;@Autowired IncidentAttachmentService attachments;
 @Autowired WorkLogService workLogs;@Autowired IncidentHistoryRepository history;
 private static void login(String email){var now=Instant.now();var token=new OidcIdToken("synthetic",now,now.plusSeconds(600),Map.of("sub","synthetic","email",email,"email_verified",true));var oidc=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_REPORTER")),token);SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(oidc,"",oidc.getAuthorities()));}
 private static CreateIncidentRequestDto request(long department,IssueType type){var r=new CreateIncidentRequestDto();r.setResponsibleDepartmentId(department);r.setTitle("Synthetic isolated lifecycle");r.setDescription("Synthetic lifecycle proof");r.setAffectedSystem("Synthetic system");r.setIssueType(type);r.setSeverity(Severity.LOW);r.setPriority(Priority.LOW);return r;}
 private static MockMultipartFile screenshot() throws Exception{var out=new ByteArrayOutputStream();ImageIO.write(new java.awt.image.BufferedImage(2,2,java.awt.image.BufferedImage.TYPE_INT_RGB),"png",out);return new MockMultipartFile("files","synthetic.png","image/png",out.toByteArray());}
 @Test void fullLifecycleAndAttachmentSecurityOnMysql() throws Exception {
  try {
   login("lifecycle-reporter@example.test");var created=service.createIncident(request(1,IssueType.IT_ISSUE));long id=created.getId();
   assertThat(created.getStatus()).isEqualTo(IncidentStatus.OPEN);assertThat(db.queryForObject("select responsible_department_id from incidents where id=?",Long.class,id)).isEqualTo(1L);
   var image=screenshot();var uploaded=attachments.upload(id,List.of(image));long attachment=uploaded.get(0).id();assertThat(attachments.content(id,attachment).data()).isEqualTo(image.getBytes());
   login("lifecycle-coordinator@example.test");administration.classify(id,"STANDARD",0L,"Synthetic classification");
   login("lifecycle-reviewer@example.test");administration.setGrant(id,1103L,"VIEW",true,0L,"Synthetic coordinator access");
   login("lifecycle-coordinator@example.test");administration.setGrant(id,1102L,"VIEW",true,0L,"Synthetic handler view");administration.setGrant(id,1102L,"HANDLE",true,0L,"Synthetic handler access");administration.setGrant(id,1104L,"VIEW",true,0L,"Synthetic reviewer view");administration.setGrant(id,1104L,"MODIFY",true,0L,"Synthetic reviewer access");administration.setGrant(id,1105L,"VIEW",true,0L,"Synthetic view only");
   login("lifecycle-unrelated@example.test");assertThatThrownBy(()->attachments.upload(id,List.of(image))).isInstanceOf(IncidentNotFoundException.class);
   login("lifecycle-coordinator@example.test");assignments.assign(id,1102L,0L,1L,"Synthetic assignment");assertThat(service.getIncident(id).getStatus()).isEqualTo(IncidentStatus.ASSIGNED);
   login("lifecycle-handler@example.test");assertThat(attachments.content(id,attachment).data()).isEqualTo(image.getBytes());assertThatThrownBy(()->attachments.upload(id,List.of(image))).isInstanceOf(IncidentNotFoundException.class);
   var investigation=new UpdateInvestigationRequestDto();investigation.setInvestigationDetails("Synthetic investigation");assertThat(service.updateInvestigation(id,investigation).getStatus()).isEqualTo(IncidentStatus.IN_PROGRESS);
   var work=new CreateWorkLogRequestDto();work.setWorkedAt(LocalDateTime.now());work.setCategory("OTHER");work.setSummary("Synthetic lifecycle work");assertThat(workLogs.createOwnEntry(work).id()).isNotNull();assertThat(workLogs.listOwnEntries()).hasSize(1);
   var resolution=new ResolveIncidentRequestDto();resolution.setResolutionDetails("Synthetic first resolution");assertThat(service.resolveIncident(id,resolution).getStatus()).isEqualTo(IncidentStatus.RESOLVED);
   login("lifecycle-reporter@example.test");var feedback=new ResolutionFeedbackRequestDto();feedback.setFeedback("Synthetic issue persists");assertThat(service.submitResolutionFeedback(id,feedback).getStatus()).isEqualTo(IncidentStatus.IN_PROGRESS);
   login("lifecycle-handler@example.test");resolution.setResolutionDetails("Synthetic second resolution");assertThat(service.resolveIncident(id,resolution).getStatus()).isEqualTo(IncidentStatus.RESOLVED);
   login("lifecycle-reporter@example.test");var validation=new ValidateIncidentRequestDto();validation.setValidationDetails("Synthetic validation");assertThat(service.validateIncident(id,validation).getStatus()).isEqualTo(IncidentStatus.VALIDATED);assertThat(service.closeIncident(id,new CloseIncidentRequestDto()).getStatus()).isEqualTo(IncidentStatus.CLOSED);
   login("lifecycle-reviewer@example.test");var review=new ReviewIncidentRequestDto();review.setReviewDetails("Synthetic review");assertThat(service.reviewIncident(id,review).getStatus()).isEqualTo(IncidentStatus.CLOSED);
   assertThat(history.findByIncidentIdOrderByChangedAtAscIdAsc(id)).extracting(IncidentHistory::getActionType).contains(HistoryActionType.INCIDENT_CREATED,HistoryActionType.ATTACHMENT_ADDED,HistoryActionType.OWNER_ASSIGNED,HistoryActionType.INVESTIGATION_UPDATED,HistoryActionType.INCIDENT_RESOLVED,HistoryActionType.RESOLUTION_NOT_ACCEPTED,HistoryActionType.INCIDENT_VALIDATED,HistoryActionType.INCIDENT_CLOSED,HistoryActionType.INCIDENT_REVIEWED);
   assertThat(db.queryForObject("select count(*) from incident_assignment_audit where incident_id=?",Long.class,id)).isEqualTo(1L);
   login("lifecycle-coordinator@example.test");administration.setGrant(id,1102L,"VIEW",false,1L,"Synthetic revocation");login("lifecycle-handler@example.test");assertThatThrownBy(()->attachments.content(id,attachment)).isInstanceOf(IncidentNotFoundException.class);
   login("lifecycle-reporter@example.test");var hr=service.createIncident(request(2,IssueType.HR_ISSUE));long hrId=hr.getId();var hrImage=attachments.upload(hrId,List.of(image)).get(0).id();
   login("lifecycle-coordinator@example.test");administration.classify(hrId,"RESTRICTED",0L,"Synthetic HR classification");administration.setGrant(hrId,1106L,"VIEW",true,0L,"Synthetic HR view");administration.setGrant(hrId,1101L,"VIEW",true,0L,"Synthetic reporter view");
   login("lifecycle-hr-handler@example.test");assertThat(attachments.content(hrId,hrImage).data()).isEqualTo(image.getBytes());
   login("lifecycle-hr-unrelated@example.test");assertThatThrownBy(()->attachments.content(hrId,hrImage)).isInstanceOf(IncidentNotFoundException.class);
   var mvc=MockMvcBuilders.standaloneSetup(new IncidentAttachmentController(attachments)).setControllerAdvice(new GlobalExceptionHandler()).build();mvc.perform(get("/api/incidents/{incidentId}/attachments/{attachmentId}",hrId,hrImage)).andExpect(status().isNotFound());
   System.out.println("Synthetic lifecycle incident IDs: "+id+", "+hrId);
  } finally {SecurityContextHolder.clearContext();}
 }
}
