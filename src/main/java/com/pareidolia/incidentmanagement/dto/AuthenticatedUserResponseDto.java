package com.pareidolia.incidentmanagement.dto;

import com.pareidolia.incidentmanagement.enums.AppUserRole;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AuthenticatedUserResponseDto {

    private String email;
    private String displayName;
    private AppUserRole role;
}
