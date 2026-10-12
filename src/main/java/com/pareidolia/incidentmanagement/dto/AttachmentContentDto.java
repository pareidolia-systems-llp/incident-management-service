package com.pareidolia.incidentmanagement.dto;

public record AttachmentContentDto(String filename, String contentType, byte[] data) { }
