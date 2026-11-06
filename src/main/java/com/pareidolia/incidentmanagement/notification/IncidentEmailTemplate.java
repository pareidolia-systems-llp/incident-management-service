package com.pareidolia.incidentmanagement.notification;

import org.springframework.web.util.HtmlUtils;

/** Formatting is not an authorization decision. Caller must establish content permission. */
final class IncidentEmailTemplate {
    record Rendered(String subject, String plainText, String html) { }
    static Rendered render(IncidentCreated event, boolean approvedContent) {
        return render(event, approvedContent, null);
    }
    static Rendered render(IncidentCreated event, boolean approvedContent, String portalOrigin) {
        String portalUrl = IncidentEmailPortalLink.url(portalOrigin);
        String number=clean(event.incidentNumber(),50);
        String title=clean(event.title(),120);
        String subject=approvedContent ? "[New Incident] "+title+" | "+number : "New incident created";
        StringBuilder plain=new StringBuilder("A new incident was created.\nIncident number: ").append(number);
        StringBuilder rows=new StringBuilder(row("Incident number",number));
        if (approvedContent) {
            String[][] values={{"Incident title",event.title()},{"Submitted by",event.reporterName()},
                {"Reported department",event.reporterDepartment()},{"Issue type",String.valueOf(event.issueType())},
                {"Severity",String.valueOf(event.severity())},{"Priority",String.valueOf(event.priority())},
                {"Reported at",String.valueOf(event.reportedAt())}};
            for (String[] value:values) {
                String safe=clean(value[1],255);
                plain.append("\n").append(value[0]).append(": ").append(safe);
                rows.append(row(value[0],safe));
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
