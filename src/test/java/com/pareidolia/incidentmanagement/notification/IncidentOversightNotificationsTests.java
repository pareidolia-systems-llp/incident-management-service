package com.pareidolia.incidentmanagement.notification;

import com.pareidolia.incidentmanagement.controller.IncidentOversightNotificationController;
import com.pareidolia.incidentmanagement.dto.IncidentResponseDto;
import com.pareidolia.incidentmanagement.entity.AppUser;
import com.pareidolia.incidentmanagement.exception.IncidentNotFoundException;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class IncidentOversightNotificationsTests {
    @Test void recordsOneOpaqueNoticePerRecipientAndRollsBackWithIntake() {
        var dataSource = new DriverManagerDataSource("jdbc:h2:mem:" + UUID.randomUUID()
                + ";MODE=MySQL;DB_CLOSE_DELAY=-1", "sa", "");
        var jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table app_users (id bigint primary key, active boolean)");
        jdbc.update("insert into app_users values (11,true),(12,true),(13,true)");
        jdbc.execute("""
                create table incident_oversight_notification (
                    id char(36) primary key, incident_id bigint, recipient_user_id bigint,
                    created_at timestamp default current_timestamp, unique (incident_id, recipient_user_id))
                """);
        var notifications = new IncidentOversightNotifications(jdbc, 11, 12);
        var tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        tx.executeWithoutResult(status -> {
            notifications.record(30);
            status.setRollbackOnly();
        });
        assertThat(notifications.list(11)).isEmpty();
        assertThat(notifications.list(12)).isEmpty();

        tx.executeWithoutResult(status -> notifications.record(30));
        var it = notifications.list(11);
        var hr = notifications.list(12);
        tx.executeWithoutResult(status -> notifications.record(30));
        assertThat(it).hasSize(1);
        assertThat(hr).hasSize(1).doesNotContainAnyElementsOf(it);
        assertThat(notifications.list(11)).isEqualTo(it);
        assertThat(notifications.list(12)).isEqualTo(hr);
        assertThat(notifications.list(13)).isEmpty();
        assertThat(notifications.incidentId(it.get(0), 12)).isNull();
        assertThat(notifications.incidentId(it.get(0), 11)).isEqualTo(30L);
    }

    @Test void openingRequiresNotificationOwnershipAndCurrentCaseAccess() {
        var notifications = mock(IncidentOversightNotifications.class);
        var users = mock(AppUserService.class);
        var incidents = mock(IncidentService.class);
        var controller = new IncidentOversightNotificationController(notifications, users, incidents);
        var caller = new AppUser();
        caller.setId(11L);
        when(users.getAuthenticatedUser()).thenReturn(caller);
        var noticeId = UUID.randomUUID();
        when(notifications.incidentId(noticeId, 11)).thenReturn(null);
        assertThatThrownBy(() -> controller.open(noticeId)).isInstanceOf(IncidentNotFoundException.class);
        verifyNoInteractions(incidents);

        when(notifications.incidentId(noticeId, 11)).thenReturn(30L);
        when(incidents.getIncident(30L)).thenThrow(new IncidentNotFoundException("Incident not found."));
        assertThatThrownBy(() -> controller.open(noticeId)).isInstanceOf(IncidentNotFoundException.class);
        var allowed = new IncidentResponseDto();
        allowed.setId(30L);
        doReturn(allowed).when(incidents).getIncident(30L);
        assertThat(controller.open(noticeId).incidentId()).isEqualTo(30L);
    }
}
