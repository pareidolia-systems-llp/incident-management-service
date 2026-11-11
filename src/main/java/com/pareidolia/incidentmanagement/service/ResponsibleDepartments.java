package com.pareidolia.incidentmanagement.service;

import java.util.Set;

public final class ResponsibleDepartments {
    private static final Set<String> NAMES = Set.of("IT", "HR", "Operations (Annotation)",
            "Operations (Perioperative Flow Analysis)", "R&D");

    private ResponsibleDepartments() { }

    public static boolean includes(String name) {
        return name != null && NAMES.contains(displayName(name));
    }

    public static String displayName(String name) {
        return "Human Resources".equals(name) ? "HR" : name;
    }
}
