package com.pareidolia.incidentmanagement.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Table(name = "work_log_entries", indexes = {
        @Index(name = "idx_work_log_owner_worked_id", columnList = "owner_id, worked_at, id")
})
@Getter
@Setter
@NoArgsConstructor
public class WorkLogEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false, updatable = false,
            foreignKey = @ForeignKey(name = "fk_work_log_owner"))
    private AppUser owner;

    @NotNull
    @Column(name = "worked_at", nullable = false)
    private LocalDateTime workedAt;

    @NotBlank
    @Size(max = 32)
    @Pattern(regexp = "USER_SUPPORT|MAINTENANCE|NETWORK|SERVER|SECURITY|ADMINISTRATION|OTHER")
    @Column(nullable = false, length = 32)
    private String category;

    @NotBlank
    @Size(max = 255)
    @Column(nullable = false, length = 255)
    private String summary;

    @Size(max = 8000)
    @Column(columnDefinition = "TEXT")
    private String details;

    @Positive
    @Column(name = "duration_minutes")
    private Integer durationMinutes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void created() { createdAt = LocalDateTime.now(); }
}
