package com.agenticsast;

import com.agenticsast.model.AuditResult;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class GrcPolicyManager {

    private final Map<String, String> policyMap = new HashMap<>();
    private final List<WhitelistEntry> whitelist = new ArrayList<>();
    private final Gson gson = new Gson();

    private static class WhitelistEntry {
        String filePath;
        String vulnerabilityType;
    }

    @PostConstruct
    public void init() {
        try (Reader reader = new InputStreamReader(new ClassPathResource("cbot.policy.json").getInputStream(), StandardCharsets.UTF_8)) {
            Map<String, String> loadedPolicy = gson.fromJson(reader, new TypeToken<Map<String, String>>(){}.getType());
            if (loadedPolicy != null) policyMap.putAll(loadedPolicy);
        } catch (Exception e) {
            System.err.println("加载 cbot.policy.json 失败: " + e.getMessage());
        }

        try (Reader reader = new InputStreamReader(new ClassPathResource("cbot.whitelist.json").getInputStream(), StandardCharsets.UTF_8)) {
            JsonArray array = gson.fromJson(reader, JsonArray.class);
            if (array != null) {
                for (JsonElement elem : array) {
                    JsonObject obj = elem.getAsJsonObject();
                    WhitelistEntry entry = new WhitelistEntry();
                    if (obj.has("filePath")) entry.filePath = obj.get("filePath").getAsString();
                    if (obj.has("vulnerabilityType")) entry.vulnerabilityType = obj.get("vulnerabilityType").getAsString();
                    whitelist.add(entry);
                }
            }
        } catch (Exception e) {
            System.err.println("加载 cbot.whitelist.json 失败: " + e.getMessage());
        }
    }

    public void applyPolicy(AuditResult result) {
        // Check whitelist
        boolean isWhitelisted = whitelist.stream().anyMatch(entry -> {
            boolean pathMatches = entry.filePath == null || result.getFilePath().replace("\\", "/").endsWith(entry.filePath.replace("\\", "/"));
            boolean typeMatches = entry.vulnerabilityType == null || entry.vulnerabilityType.equals(result.getVulnerabilityType());
            return pathMatches && typeMatches;
        });

        if (isWhitelisted) {
            result.setStatus("IGNORED");
            return;
        }

        // Apply policy
        String type = result.getVulnerabilityType();
        String confidence = result.getConfidenceLevel();
        
        // policyMap can map vulnerabilityType (e.g. OWA-009) or confidence (e.g. High) to BLOCK/WARN
        String action = policyMap.getOrDefault(type, policyMap.getOrDefault(confidence, "WARN"));
        result.setStatus(action);
    }
}
