package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.HistoryActionType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
public class IncidentHistoryResponseDto {

    private Long id;
    private HistoryActionType actionType;
    private String oldValue;
    private String newValue;
    private String changedBy;
    private String remarks;
    private LocalDateTime changedAt;
}
