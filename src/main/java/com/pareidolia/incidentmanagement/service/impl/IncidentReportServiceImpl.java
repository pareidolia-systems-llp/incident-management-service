package com.pareidolia.incidentmanagement.service.impl;

import com.pareidolia.incidentmanagement.entity.Incident;
import com.pareidolia.incidentmanagement.enums.AppUserRole;
import com.pareidolia.incidentmanagement.exception.InvalidRequestException;
import com.pareidolia.incidentmanagement.repository.*;
import com.pareidolia.incidentmanagement.service.*;
import lombok.RequiredArgsConstructor;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.YearMonth;
import java.util.*;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class IncidentReportServiceImpl implements IncidentReportService {
    private static final Logger log = LoggerFactory.getLogger(IncidentReportServiceImpl.class);
    private final AppUserService users;
    private final IncidentRepository incidents;
    private final IncidentHistoryRepository history;
    private final AppUserRepository appUsers;

    private record Column(String label, Function<Incident, Object> value) { }
    private static final List<Column> COLUMNS = List.of(
            new Column("Incident / Ticket Number", Incident::getIncidentNumber),
            new Column("Reported Date & Time", Incident::getReportedAt),
            new Column("Reporter Name (current directory)", i -> i.getReportedBy()),
            new Column("Reporter Email", Incident::getReportedBy),
            new Column("Department", Incident::getReporterDepartment),
            new Column("Desk Number", Incident::getDeskNumber),
            new Column("Title", Incident::getTitle),
            new Column("Description", Incident::getDescription),
            new Column("Category", Incident::getCategory),
            new Column("Incident Type", Incident::getIssueType),
            new Column("Affected System / Service", Incident::getAffectedSystem),
            new Column("Impacted User / Department", Incident::getImpactedUserOrDepartment),
            new Column("Severity", Incident::getSeverity),
            new Column("Priority", Incident::getPriority),
            new Column("Current Status", Incident::getStatus),
            new Column("Assigned Owner", Incident::getAssignedOwner),
            new Column("Investigation Details", Incident::getInvestigationDetails),
            new Column("Root Cause", Incident::getRootCause),
            new Column("Actions Taken", Incident::getActionsTaken),
            new Column("Containment Action", Incident::getContainmentAction),
            new Column("Corrective Action", Incident::getCorrectiveAction),
            new Column("Evidence Reference", Incident::getEvidenceReference),
            new Column("Escalation Required", Incident::getEscalationRequired),
            new Column("Escalation Details", Incident::getEscalationDetails),
            new Column("Resolution", Incident::getResolutionDetails),
            new Column("Resolution Date & Time", Incident::getResolvedAt),
            new Column("Validation Details", Incident::getValidationDetails),
            new Column("Validated By", Incident::getValidatedBy),
            new Column("Validation Date & Time", Incident::getValidatedAt),
            new Column("Closure Confirmed By", Incident::getClosureConfirmedBy),
            new Column("Closed Date & Time", Incident::getClosedAt),
            new Column("Post-Closure Review", Incident::getReviewDetails),
            new Column("Reviewed By", Incident::getReviewedBy),
            new Column("Review Date & Time", Incident::getReviewedAt),
            new Column("Lessons Learned", Incident::getLessonsLearned),
            new Column("Preventive Action", Incident::getPreventiveAction),
            new Column("Created At", Incident::getCreatedAt),
            new Column("Updated At", Incident::getUpdatedAt));

    @Override
    @Transactional(readOnly = true)
    public byte[] monthly(int year, int month) {
        return report(year, month, null, null, null, null);
    }

    @Override
    @Transactional(readOnly = true)
    public byte[] report(Integer year, Integer month, LocalDate fromDate, LocalTime fromTime,
                         LocalDate toDate, LocalTime toTime) {
        var actor = users.getAuthenticatedUser();
        if (actor.getRole() != AppUserRole.IT_HANDLER && actor.getRole() != AppUserRole.ADMIN) {
            throw new AccessDeniedException("Access denied.");
        }
        LocalDateTime start, end;
        boolean includeEnd = false;
        boolean range = fromDate != null || toDate != null || fromTime != null || toTime != null;
        if (range) {
            if (year != null || month != null || fromDate == null || toDate == null) {
                throw new InvalidRequestException("Select either a month or both From Date and To Date. Times require dates.");
            }
            if (fromDate.getYear() < 1900 || fromDate.getYear() > 9998
                    || toDate.getYear() < 1900 || toDate.getYear() > 9998) {
                throw new InvalidRequestException("Select dates from 1900 to 9998.");
            }
            start = fromDate.atTime(fromTime == null ? LocalTime.MIDNIGHT : fromTime);
            // Whole end days use next-midnight exclusive: no fractional-second precision assumptions.
            // Explicit times are inclusive exact boundaries, not rounded to the end of the minute.
            end = toTime == null ? toDate.plusDays(1).atStartOfDay() : toDate.atTime(toTime);
            includeEnd = toTime != null;
            if (fromDate.isAfter(toDate) || start.isAfter(end) || (!includeEnd && start.equals(end))) {
                throw new InvalidRequestException("From date/time must be on or before To date/time.");
            }
        } else {
            if (year == null || month == null || year < 1900 || year > 9998 || month < 1 || month > 12) {
                throw new InvalidRequestException("Select a year from 1900 to 9998 and a month from 1 to 12.");
            }
            YearMonth period = YearMonth.of(year, month);
            start = period.atDay(1).atStartOfDay();
            end = period.plusMonths(1).atDay(1).atStartOfDay();
        }
        var rows = incidents.findForReport(start, end, includeEnd);
        Map<String, String> names = new HashMap<>();
        if (!rows.isEmpty()) {
            appUsers.findByEmailIn(rows.stream().map(Incident::getReportedBy).distinct().toList())
                    .forEach(user -> names.put(user.getEmail().toLowerCase(Locale.ROOT), user.getDisplayName()));
        }
        // One range query per sheet; no attachment entities or BLOBs are fetched.
        var events = history.findForReport(start, end, includeEnd);
        try (var workbook = new XSSFWorkbook(); var output = new ByteArrayOutputStream()) {
            var writer = new ReportWriter(workbook);
            Sheet sheet = writer.sheet("Incidents", COLUMNS.stream().map(Column::label).toList());
            for (Incident incident : rows) {
                Row row = sheet.createRow(sheet.getLastRowNum() + 1);
                for (int index = 0; index < COLUMNS.size(); index++) {
                    Object value = index == 2 ? names.get(incident.getReportedBy().toLowerCase(Locale.ROOT))
                            : COLUMNS.get(index).value().apply(incident);
                    writer.cell(row, index, value, incident.getIncidentNumber(), COLUMNS.get(index).label());
                }
            }
            Sheet audit = writer.sheet("Lifecycle History", List.of("Incident / Ticket Number", "Changed At",
                    "Action", "Changed By", "Old Value", "New Value", "Remarks"));
            for (var event : events) {
                Row row = audit.createRow(audit.getLastRowNum() + 1);
                Object[] values = {event.getIncident().getIncidentNumber(), event.getChangedAt(), event.getActionType(),
                        event.getChangedBy(), event.getOldValue(), event.getNewValue(), event.getRemarks()};
                for (int index = 0; index < values.length; index++) {
                    writer.cell(row, index, values[index], event.getIncident().getIncidentNumber(),
                            "History " + event.getId() + " / " + audit.getRow(0).getCell(index).getStringCellValue());
                }
            }
            workbook.write(output);
            log.info("INCIDENT_REPORT_EXPORTED actor={} start={} end={} includeEnd={}", actor.getEmail(), start, end, includeEnd);
            return output.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("Incident report could not be generated.", exception);
        }
    }

    private static class ReportWriter {
        private final Workbook workbook;
        private final CellStyle header, text, date;
        private Sheet longText;

        ReportWriter(Workbook workbook) {
            this.workbook = workbook;
            text = workbook.createCellStyle();
            text.setWrapText(true);
            text.setVerticalAlignment(VerticalAlignment.TOP);
            header = workbook.createCellStyle();
            header.cloneStyleFrom(text);
            Font font = workbook.createFont();
            font.setBold(true);
            header.setFont(font);
            date = workbook.createCellStyle();
            date.cloneStyleFrom(text);
            date.setDataFormat(workbook.createDataFormat().getFormat("yyyy-mm-dd hh:mm:ss"));
        }

        Sheet sheet(String name, List<String> columns) {
            Sheet sheet = workbook.createSheet(name);
            Row row = sheet.createRow(0);
            row.setHeightInPoints(32);
            for (int index = 0; index < columns.size(); index++) {
                Cell cell = row.createCell(index);
                cell.setCellValue(columns.get(index));
                cell.setCellStyle(header);
                sheet.setColumnWidth(index, (index == 0 ? 38 : 30) * 256);
            }
            sheet.createFreezePane(1, 1);
            sheet.setAutoFilter(new CellRangeAddress(0, 0, 0, columns.size() - 1));
            return sheet;
        }

        void cell(Row row, int index, Object value, String ticket, String field) {
            Cell cell = row.createCell(index);
            cell.setCellStyle(text);
            if (value == null) return;
            if (value instanceof LocalDateTime timestamp) {
                cell.setCellValue(timestamp);
                cell.setCellStyle(date);
            } else if (value instanceof Boolean bool) {
                cell.setCellValue(bool);
            } else {
                String content = value.toString();
                if (content.length() > 32767) {
                    if (longText == null) longText = sheet("Long Text", List.of("Incident / Ticket Number", "Field", "Part", "Text"));
                    for (int offset = 0, part = 1; offset < content.length(); offset += 32000, part++) {
                        Row extra = longText.createRow(longText.getLastRowNum() + 1);
                        cell(extra, 0, ticket, ticket, field);
                        cell(extra, 1, field, ticket, field);
                        cell(extra, 2, part, ticket, field);
                        cell(extra, 3, content.substring(offset, Math.min(offset + 32000, content.length())), ticket, field);
                    }
                    content = content.substring(0, 32000) + "\n[Full text is preserved in the Long Text sheet.]";
                }
                // Explicit string cells prevent spreadsheet formula injection from incident/user text.
                cell.setCellValue(content);
            }
        }
    }
}
