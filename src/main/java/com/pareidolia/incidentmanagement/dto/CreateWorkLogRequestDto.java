package com.pareidolia.incidentmanagement.dto;

import com.fasterxml.jackson.annotation.JsonAnySetter;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Getter
@Setter
public class CreateWorkLogRequestDto {
    @NotNull
    private LocalDateTime workedAt;
    @NotBlank
    @Size(max = 32)
    @Pattern(regexp = "USER_SUPPORT|MAINTENANCE|NETWORK|SERVER|SECURITY|ADMINISTRATION|OTHER",
            message = "Select a supported work category.")
    private String category;
    @NotBlank
    @Size(max = 255)
    private String summary;
    @Size(max = 8000)
    private String details;
    @Positive
    private Integer durationMinutes;

    // Reject overposting, including owner IDs/emails and server-generated fields.
    // Never include client-provided text in the exception message.
    @JsonAnySetter
    public void rejectUnknownField(String name, Object value) {
        throw new IllegalArgumentException("Unsupported work entry field.");
    }
}
