package com.pareidolia.incidentmanagement.service;

import com.pareidolia.incidentmanagement.dto.CreateWorkLogRequestDto;
import com.pareidolia.incidentmanagement.dto.WorkLogResponseDto;
import java.util.List;

public interface WorkLogService {
    List<WorkLogResponseDto> listOwnEntries();
    WorkLogResponseDto createOwnEntry(CreateWorkLogRequestDto request);
}
