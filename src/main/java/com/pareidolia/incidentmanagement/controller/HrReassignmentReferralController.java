package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.service.HrReassignmentReferralService;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/incident-assignment/hr-referrals")
@ConditionalOnProperty(name = {"app.incident-assignment.enabled", "app.incident-access.enabled",
        "app.employee-management.enabled", "app.hr-reassignment-referrals.enabled"}, havingValue = "true")
public class HrReassignmentReferralController {
    public record Submission(String incidentReference) { }

    private final HrReassignmentReferralService referrals;

    public HrReassignmentReferralController(HrReassignmentReferralService referrals) {
        this.referrals = referrals;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void submit(@RequestBody(required = false) Submission submission) {
        referrals.submit(submission == null ? null : submission.incidentReference());
    }

    @GetMapping("/{referralId}")
    public HrReassignmentReferralService.Review review(@PathVariable UUID referralId) {
        return referrals.review(referralId);
    }

    @GetMapping
    public java.util.List<UUID> pending() {
        return referrals.pending();
    }

    @PutMapping("/{referralId}/decision")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void decide(@PathVariable UUID referralId, @Valid @RequestBody HrReassignmentReferralService.Decision decision) {
        referrals.decide(referralId, decision);
    }
}
