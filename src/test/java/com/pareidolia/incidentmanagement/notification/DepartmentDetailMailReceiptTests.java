package com.pareidolia.incidentmanagement.notification;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DepartmentDetailMailReceiptTests {
    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"CLAIMED", "SENT", "UNCERTAIN"})
    void existingReceiptStateNeverAllowsAnAutomaticSecondClaim(String state) {
        var jdbc = new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:h2:mem:detail_state_" + state + ";DB_CLOSE_DELAY=-1", "sa", ""));
        jdbc.execute("""
                create table incident_department_detail_email_receipt
                (incident_id bigint, recipient_user_id bigint, status varchar(10), finished_at timestamp,
                 primary key (incident_id, recipient_user_id))
                """);
        jdbc.update("insert into incident_department_detail_email_receipt (incident_id, recipient_user_id, status) values (1, 2, ?)", state);
        var receipt = new DepartmentDetailMailReceipt(jdbc);
        assertThatThrownBy(() -> receipt.claim(1, 2)).isInstanceOf(DuplicateKeyException.class);
        assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt", String.class)).isEqualTo(state);
    }
    @Test
    void detailReceiptIsIndependentOfLegacyAndDoesNotReplayUncertainDelivery() {
        var jdbc = new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:h2:mem:detail_receipt_proof;DB_CLOSE_DELAY=-1", "sa", ""));
        jdbc.execute("""
                create table incident_department_head_email_receipt
                (incident_id bigint, recipient_user_id bigint, status varchar(10),
                 primary key (incident_id, recipient_user_id))
                """);
        jdbc.execute("""
                create table incident_department_detail_email_receipt
                (incident_id bigint, recipient_user_id bigint, status varchar(10), finished_at timestamp,
                 primary key (incident_id, recipient_user_id))
                """);
        jdbc.update("insert into incident_department_head_email_receipt values (1, 2, 'SENT')");
        var receipt = new DepartmentDetailMailReceipt(jdbc);
        receipt.claim(1, 2);
        receipt.finish(1, 2, false);
        assertThat(jdbc.queryForObject("select status from incident_department_detail_email_receipt", String.class))
                .isEqualTo("UNCERTAIN");
        assertThat(jdbc.queryForObject("select status from incident_department_head_email_receipt", String.class))
                .isEqualTo("SENT");
        assertThatThrownBy(() -> receipt.claim(1, 2)).isInstanceOf(DuplicateKeyException.class);
    }
}