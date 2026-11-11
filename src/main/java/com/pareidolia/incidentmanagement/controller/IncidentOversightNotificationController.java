package com.pareidolia.incidentmanagement.controller;

import com.pareidolia.incidentmanagement.exception.IncidentNotFoundException;
import com.pareidolia.incidentmanagement.notification.IncidentOversightNotifications;
import com.pareidolia.incidentmanagement.service.AppUserService;
import com.pareidolia.incidentmanagement.service.IncidentService;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/incident-oversight-notifications")
@ConditionalOnProperty(name = {"app.incident-access.enabled", "app.notifications.oversight.enabled"}, havingValue = "true")
public class IncidentOversightNotificationController {
    private final IncidentOversightNotifications notifications;
    private final AppUserService users;
    private final IncidentService incidents;

    public IncidentOversightNotificationController(IncidentOversightNotifications notifications,
            AppUserService users, IncidentService incidents) {
        this.notifications = notifications;
        this.users = users;
        this.incidents = incidents;
    }

    public record OpenIncident(Long incidentId) { }

    @GetMapping
    public List<UUID> list() {
        return notifications.list(users.getAuthenticatedUser().getId());
    }

    @GetMapping("/{notificationId}/incident")
    public OpenIncident open(@PathVariable UUID notificationId) {
        Long incidentId = notifications.incidentId(notificationId, users.getAuthenticatedUser().getId());
        if (incidentId == null) throw new IncidentNotFoundException("Incident not found.");
        return new OpenIncident(incidents.getIncident(incidentId).getId());
    }
}
