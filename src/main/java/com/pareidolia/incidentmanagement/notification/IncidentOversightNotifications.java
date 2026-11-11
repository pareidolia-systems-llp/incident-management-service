package com.pareidolia.incidentmanagement.notification;

import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
@ConditionalOnProperty(name = {"app.incident-access.enabled", "app.notifications.oversight.enabled"}, havingValue = "true")
public class IncidentOversightNotifications {
    private final JdbcTemplate jdbc;
    private final List<Long> recipientIds;

    public IncidentOversightNotifications(JdbcTemplate jdbc,
            @Value("${app.notifications.oversight.it-user-id:0}") long itUserId,
            @Value("${app.notifications.oversight.hr-user-id:0}") long hrUserId) {
        if (itUserId <= 0 || hrUserId <= 0 || itUserId == hrUserId) {
            throw new IllegalArgumentException("Configure two distinct oversight accounts.");
        }
        this.jdbc = jdbc;
        this.recipientIds = List.of(itUserId, hrUserId);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(long incidentId) {
        for (long recipientId : recipientIds) {
            jdbc.update("""
                    insert into incident_oversight_notification (id, incident_id, recipient_user_id)
                    select ?, ?, id from app_users where id=? and active=true
                    on duplicate key update recipient_user_id=incident_oversight_notification.recipient_user_id
                    """, UUID.randomUUID().toString(), incidentId, recipientId);
        }
    }

    public List<UUID> list(long recipientId) {
        if (!recipientIds.contains(recipientId)) return List.of();
        return jdbc.query("""
                select id from incident_oversight_notification where recipient_user_id=?
                order by created_at desc, id limit 100
                """, (row, index) -> UUID.fromString(row.getString(1)), recipientId);
    }

    public Long incidentId(UUID notificationId, long recipientId) {
        if (!recipientIds.contains(recipientId)) return null;
        return jdbc.query("""
                select incident_id from incident_oversight_notification where id=? and recipient_user_id=?
                """, (row, index) -> row.getLong(1), notificationId.toString(), recipientId)
                .stream().findFirst().orElse(null);
    }
}
