package com.pareidolia.incidentmanagement;

import com.pareidolia.incidentmanagement.entity.*;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.mapper.IncidentMapper;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.security.IncidentAccessPolicy;
import com.pareidolia.incidentmanagement.service.*;
import com.pareidolia.incidentmanagement.service.impl.*;
import java.io.ByteArrayInputStream;
import java.time.LocalDateTime;
import java.util.List;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class IncidentAccessWiringTests {
    @Test void deniedIncidentsAreFilteredFromListAndLegacyAssignment() {
        var repo=mock(IncidentRepository.class);var history=mock(IncidentHistoryRepository.class);var mapper=mock(IncidentMapper.class);var users=mock(AppUserService.class);
        var actor=new AppUser();actor.setRole(AppUserRole.ADMIN);actor.setEmail("admin@example.test");
        var incident=new Incident();incident.setId(2L);incident.setReportedBy("other@example.test");
        when(users.getAuthenticatedUser()).thenReturn(actor);when(repo.findAllByOrderByCreatedAtDescIdDesc()).thenReturn(List.of(incident));when(repo.findById(2L)).thenReturn(java.util.Optional.of(incident));
        var policy=mock(IncidentAccessPolicy.class);
        var service=new IncidentServiceImpl(repo,history,mapper,users,"owner@example.test",mock(ApplicationEventPublisher.class));
        ReflectionTestUtils.setField(service,"incidentAccessEnabled",true);ReflectionTestUtils.setField(service,"accessPolicy",policy);
        assertThat(service.getAllIncidents()).isEmpty();
        assertThatThrownBy(() -> service.assignIncident(2L,new com.pareidolia.incidentmanagement.dto.AssignIncidentRequestDto())).isInstanceOf(com.pareidolia.incidentmanagement.exception.IncidentNotFoundException.class);
        verify(repo,never()).saveAndFlush(any());
    }
    @Test void attachmentDownloadDoesNotQueryAttachmentAfterIncidentDenial(){
        var incidentService=mock(IncidentService.class);var attachments=mock(IncidentAttachmentRepository.class);
        when(incidentService.getIncident(2L)).thenThrow(new AccessDeniedException("denied"));
        var service=new IncidentAttachmentServiceImpl(incidentService,mock(AppUserService.class),mock(IncidentRepository.class),attachments,mock(IncidentHistoryRepository.class));
        assertThatThrownBy(() -> service.content(2L,3L)).isInstanceOf(AccessDeniedException.class);
        verifyNoInteractions(attachments);
    }
    @Test void bothReportSheetsFilterUnauthorizedIncidents() throws Exception {
        var users=mock(AppUserService.class);var repo=mock(IncidentRepository.class);var history=mock(IncidentHistoryRepository.class);var appUsers=mock(AppUserRepository.class);
        var actor=new AppUser();actor.setRole(AppUserRole.ADMIN);actor.setEmail("admin@example.test");when(users.getAuthenticatedUser()).thenReturn(actor);
        var incident=new Incident();incident.setId(2L);incident.setReportedBy("other@example.test");incident.setReportedAt(LocalDateTime.of(2026,10,1,0,0));
        var event=new IncidentHistory();event.setIncident(incident);
        when(repo.findForReport(any(),any(),anyBoolean(),any(org.springframework.data.domain.Pageable.class))).thenReturn(List.of(incident));
        when(history.findForReport(any(),any(),anyBoolean(),any(org.springframework.data.domain.Pageable.class))).thenReturn(List.of(event));
        var policy=mock(IncidentAccessPolicy.class);
        var service=new IncidentReportServiceImpl(users,repo,history,appUsers);
        var snapshot=mock(com.pareidolia.incidentmanagement.security.IncidentReadSnapshot.class);
        when(snapshot.read(any())).thenAnswer(inv -> ((java.util.function.Supplier<?>)inv.getArgument(0)).get());
        ReflectionTestUtils.setField(service,"readSnapshot",snapshot);
        ReflectionTestUtils.setField(service,"incidentAccessEnabled",true);ReflectionTestUtils.setField(service,"accessPolicy",policy);
        try(var workbook=new XSSFWorkbook(new ByteArrayInputStream(service.monthly(2026,10)))){
            assertThat(workbook.getSheet("Incidents").getPhysicalNumberOfRows()).isEqualTo(1);
            assertThat(workbook.getSheet("Lifecycle History").getPhysicalNumberOfRows()).isEqualTo(1);
        }
    }
}
