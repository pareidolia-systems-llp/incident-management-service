package com.pareidolia.incidentmanagement.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AddWorkNoteRequestDto(@NotBlank @Size(max = 8000) String remarks) {}
