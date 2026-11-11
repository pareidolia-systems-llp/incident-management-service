package com.pareidolia.incidentmanagement.notification;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Component
class DepartmentDetailMailReceipt {
    private final JdbcTemplate jdbc;

    DepartmentDetailMailReceipt(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void claim(long incidentId, long recipientId) {
        jdbc.update("""
                insert into incident_department_detail_email_receipt (incident_id, recipient_user_id, status)
                values (?, ?, 'CLAIMED')
                """, incidentId, recipientId);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void finish(long incidentId, long recipientId, boolean sent) {
        jdbc.update("""
                update incident_department_detail_email_receipt set status=?, finished_at=current_timestamp
                where incident_id=? and recipient_user_id=? and status='CLAIMED'
                """, sent ? "SENT" : "UNCERTAIN", incidentId, recipientId);
    }
}