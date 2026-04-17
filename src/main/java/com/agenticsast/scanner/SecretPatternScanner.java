package com.agenticsast.scanner;

import com.agenticsast.model.ScanMatch;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class SecretPatternScanner implements CodeScanner {

    private static class PatternRule {
        String ruleId;
        String description;
        Pattern pattern;

        PatternRule(String ruleId, String description, Pattern pattern) {
            this.ruleId = ruleId;
            this.description = description;
            this.pattern = pattern;
        }
    }

    private final List<PatternRule> rules = new ArrayList<>();

    @PostConstruct
    public void init() {
        try {
            ClassPathResource resource = new ClassPathResource("scan-patterns.md");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.trim().isEmpty() || line.startsWith("#")) continue;
                    String[] parts = line.split("\\|", 3);
                    if (parts.length == 3) {
                        rules.add(new PatternRule(parts[0].trim(), parts[1].trim(), Pattern.compile(parts[2].trim())));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("无法加载 scan-patterns.md: " + e.getMessage());
        }
    }

    @Override
    public List<ScanMatch> scan(String filePath, String sourceCode) {
        List<ScanMatch> matches = new ArrayList<>();
        if (sourceCode == null || sourceCode.trim().isEmpty() || rules.isEmpty()) {
            return matches;
        }

        String[] lines = sourceCode.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String stripped = line.trim();
            
            if (stripped.length() <= 2 || stripped.startsWith("//") || stripped.startsWith("*") || stripped.startsWith("/*") || stripped.startsWith("@")) {
                continue;
            }

            for (PatternRule rule : rules) {
                if (rule.pattern.matcher(line).find()) {
                    matches.add(new ScanMatch(rule.ruleId, rule.description, extractLines(sourceCode, i + 1 - 2, i + 1 + 2)));
                }
            }
        }

        return deduplicateMatches(matches);
    }

    private String extractLines(String sourceCode, int startLine, int endLine) {
        String[] lines = sourceCode.split("\\r?\\n");
        StringBuilder sliceBuilder = new StringBuilder();
        int start = Math.max(0, startLine - 1);
        int end = Math.min(lines.length - 1, endLine - 1);
        for (int j = start; j <= end; j++) {
            sliceBuilder.append(j + 1).append(": ").append(lines[j]).append("\n");
        }
        return sliceBuilder.toString();
    }

    private List<ScanMatch> deduplicateMatches(List<ScanMatch> matches) {
        List<ScanMatch> uniqueMatches = new ArrayList<>();
        List<String> seenSlices = new ArrayList<>();
        for (ScanMatch match : matches) {
            if (!seenSlices.contains(match.codeSlice)) {
                seenSlices.add(match.codeSlice);
                uniqueMatches.add(match);
            }
        }
        return uniqueMatches;
    }
}
