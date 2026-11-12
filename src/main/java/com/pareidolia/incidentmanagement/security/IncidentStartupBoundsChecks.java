package com.pareidolia.incidentmanagement.security;

import com.zaxxer.hikari.HikariDataSource;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import org.springframework.jdbc.core.JdbcTemplate;

/** Checks configured bounds only; does not enforce an overall readiness deadline. */
public final class IncidentStartupBoundsChecks {
    private IncidentStartupBoundsChecks() { }
    public enum Result { CONFIGURED_FOR_FURTHER_CHECKS, UNSAFE_CONFIGURATION }
    public static Result inspect(HikariDataSource source, JdbcTemplate jdbc, long overallDeadlineMillis) {
        if (source == null || jdbc == null || jdbc.getDataSource() != source) return Result.UNSAFE_CONFIGURATION;
        try {
            long acquisition=source.getConnectionTimeout(), validation=source.getValidationTimeout();
            if (acquisition < 250 || acquisition > 5000 || validation < 250 || validation > acquisition
                    || jdbc.getQueryTimeout() <= 0 || jdbc.getQueryTimeout() > 5
                    || overallDeadlineMillis < 1000 || overallDeadlineMillis > 30000
                    || acquisition > overallDeadlineMillis || jdbc.getQueryTimeout() * 1000L > overallDeadlineMillis)
                return Result.UNSAFE_CONFIGURATION;
            String url=source.getJdbcUrl();
            if (url == null || !url.startsWith("jdbc:mysql://")) return Result.UNSAFE_CONFIGURATION;
            URI uri=URI.create(url.substring(5));
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null || uri.getRawQuery() == null)
                return Result.UNSAFE_CONFIGURATION;
            var params=new HashMap<String,String>();
            for (String entry:uri.getRawQuery().split("&",-1)) {
                String[] pair=entry.split("=",2);
                if (pair.length != 2) return Result.UNSAFE_CONFIGURATION;
                String key=URLDecoder.decode(pair[0],StandardCharsets.UTF_8);
                String value=URLDecoder.decode(pair[1],StandardCharsets.UTF_8);
                if (params.putIfAbsent(key,value) != null) return Result.UNSAFE_CONFIGURATION;
            }
            if (source.getDataSourceProperties().containsKey("connectTimeout") || source.getDataSourceProperties().containsKey("socketTimeout"))
                return Result.UNSAFE_CONFIGURATION;
            int connect=Integer.parseInt(params.getOrDefault("connectTimeout","0"));
            int socket=Integer.parseInt(params.getOrDefault("socketTimeout","0"));
            if (connect <= 0 || connect > 5000 || socket <= 0 || socket > 10000
                    || connect > overallDeadlineMillis || socket > overallDeadlineMillis) return Result.UNSAFE_CONFIGURATION;
            return Result.CONFIGURED_FOR_FURTHER_CHECKS;
        } catch (RuntimeException failure) { return Result.UNSAFE_CONFIGURATION; }
    }
}
