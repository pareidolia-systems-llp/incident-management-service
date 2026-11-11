package com.pareidolia.incidentmanagement.notification;

import org.springframework.web.util.HtmlUtils;

/** Formatting is not an authorization decision. Caller must establish content permission. */
final class IncidentEmailTemplate {
    record Rendered(String subject, String plainText, String html) { }
    static Rendered render(IncidentCreated event, boolean approvedContent) {
        return render(event, approvedContent, null);
    }
    static Rendered render(IncidentCreated event, boolean approvedContent, String portalOrigin) {
        return render(event, approvedContent, portalOrigin, null);
    }

    static Rendered renderHrDetails(IncidentCreated event, String portalOrigin) {
        return render(event, true, portalOrigin, event.responsibleDepartmentName());
    }

    private static Rendered render(IncidentCreated event, boolean approvedContent, String portalOrigin,
            String responsibleDepartment) {
        String portalUrl = IncidentEmailPortalLink.url(portalOrigin);
        String number = event == null ? null : clean(event.incidentNumber(), 50);
        // Keep incident details out of the subject line.
        String subject = "New incident created";
        StringBuilder plain = new StringBuilder("A new incident was created.");
        StringBuilder rows = new StringBuilder();
        if (number != null) {
            plain.append("\nIncident number: ").append(number);
            rows.append(row("Incident number", number));
        }
        if (approvedContent) {
            String handler = clean(event.assignedHandler(), 255);
            String[][] values = {
                {"Incident title", clean(event.title(), 255)},
                {"Description", clean(event.description(), 4000)},
                {"Submitted by", clean(event.reporterName(), 255)},
                {"Assigned handler", "Not provided".equals(handler) ? "Pending assignment" : handler},
                {"Reported department", clean(event.reporterDepartment(), 255)},
                {"Status", clean(String.valueOf(event.status()), 255)},
                {"Issue type", clean(String.valueOf(event.issueType()), 255)},
                {"Category", clean(event.category(), 255)},
                {"Severity", clean(String.valueOf(event.severity()), 255)},
                {"Priority", clean(String.valueOf(event.priority()), 255)},
                {"Created at", clean(String.valueOf(event.createdAt()), 255)}
            };
            for (String[] value : values) {
                plain.append("\n").append(value[0]).append(": ").append(value[1]);
                rows.append(row(value[0], value[1]));
            }
            if (responsibleDepartment != null && !responsibleDepartment.isBlank()) {
                String department = clean(responsibleDepartment, 255);
                plain.append("\nResponsible department: ").append(department);
                rows.append(row("Responsible department", department));
            }
        }
        plain.append("\nSign in to the incident management portal to review it.");
        String portalLink = "";
        if (portalUrl != null) {
            plain.append("\nOpen Incident Management Portal: ").append(portalUrl);
            portalLink = "<p style=\"margin:20px 0 0;line-height:1.5\"><a href=\""
                    + HtmlUtils.htmlEscape(portalUrl)
                    + "\" style=\"color:#17385e;font-weight:bold;text-decoration:underline\">"
                    + "Open Incident Management Portal</a></p>";
        }
        String html="<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head>"
            +"<body style=\"margin:0;padding:0;background:#f2f5f8;font-family:Arial,sans-serif;color:#1b2735\">"
            +"<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;background:#f2f5f8\"><tr><td style=\"padding:24px 12px\">"
            +"<table role=\"presentation\" style=\"width:100%;max-width:600px;margin:0 auto;border-collapse:collapse;background:#ffffff\">"
            +"<tr><td style=\"background:#17385e;color:#ffffff;padding:20px 24px;font-weight:bold;font-size:16px\">Pareidolia Systems LLP</td></tr>"
            +"<tr><td style=\"padding:24px\"><h1 style=\"margin:0 0 16px;font-size:22px;line-height:1.3\">New incident created</h1>"
            +"<p style=\"margin:0 0 16px;line-height:1.5\">A new incident has been recorded.</p>"
            +"<table role=\"presentation\" style=\"width:100%;border-collapse:collapse;background:#f3f6f9\">"+rows+"</table>"
            +"<p style=\"margin:20px 0 0;line-height:1.5\">Sign in to the incident management portal to review it.</p>"
            +portalLink+"</td></tr></table></td></tr></table></body></html>";
        return new Rendered(subject,plain.toString(),html);
    }
    static Rendered renderDetailedIncident(IncidentCreated event, String portalOrigin, long incidentId) {
        String base = IncidentEmailPortalLink.url(portalOrigin);
        if (base == null || incidentId <= 0) throw new IllegalArgumentException("Valid portal and incident are required.");
        String direct = base + "incidents/" + incidentId;
        Rendered message = render(event, true, portalOrigin, event.responsibleDepartmentName());
        return new Rendered(message.subject(),
                message.plainText().replace("Open Incident Management Portal: " + base, "View Incident in Portal: " + direct),
                message.html().replace(HtmlUtils.htmlEscape(base), HtmlUtils.htmlEscape(direct))
                        .replace("Open Incident Management Portal", "View Incident in Portal"));
    }
    static Rendered renderMinimal(String portalOrigin) {
        return render(null, false, portalOrigin);
    }

    private static String row(String label,String value) {
        return "<tr><th scope=\"row\" style=\"padding:8px;text-align:left;vertical-align:top\">"+HtmlUtils.htmlEscape(label)
                +"</th><td style=\"padding:8px;overflow-wrap:anywhere\">"+HtmlUtils.htmlEscape(value)+"</td></tr>";
    }
    static String clean(String input,int limit) {
        if(input==null || "null".equals(input))return "Not provided";
        StringBuilder result=new StringBuilder();
        input.codePoints().forEach(cp -> {
            int type=Character.getType(cp);
            if(Character.isISOControl(cp) || type==Character.FORMAT || type==Character.LINE_SEPARATOR || type==Character.PARAGRAPH_SEPARATOR) result.append(' ');
            else result.appendCodePoint(cp);
        });
        String normalized=result.toString().replaceAll("\\s+"," ").trim();
        if(normalized.isEmpty())return "Not provided";
        int count=normalized.codePointCount(0,normalized.length());
        return count<=limit ? normalized : normalized.substring(0,normalized.offsetByCodePoints(0,limit));
    }
}
