package com.agenticsast.llm;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ollama LLM 客户端
 * 负责与本地部署的 Ollama 大模型进行 HTTP 通信
 */
@Component
public class OllamaClient {

    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    private static final int TIMEOUT_MS = 300000; // 5分钟超时
    private static final Pattern RESPONSE_PATTERN = Pattern.compile("\"response\":\"([^\"]*)\"");

    /**
     * 调用 Ollama 流式接口
     *
     * @param prompt     提示词
     * @param modelName  模型名称
     * @param emitter    SSE 发射器，用于将流式数据推送回前端
     */
    public void callStream(String prompt, String modelName, SseEmitter emitter) {
        try {
            String jsonPayload = String.format(
                "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":true}",
                modelName,
                escapeJson(prompt)
            );

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");

            conn.getOutputStream().write(jsonPayload.getBytes(StandardCharsets.UTF_8));

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // 每行是一个完整的 JSON 对象
                        String data = extractResponse(line);
                        if (data != null && !data.isEmpty()) {
                            emitter.send(SseEmitter.event().data(data));
                        }
                    }
                }
            } else {
                emitter.send(SseEmitter.event().name("error").data("LLM 服务返回错误: " + responseCode));
            }
            conn.disconnect();
            emitter.complete();
        } catch (Exception e) {
            emitter.completeWithError(e);
        }
    }

    /**
     * 调用 Ollama 并获取完整响应（非流式）
     */
    public String call(String prompt, String modelName) {
        try {
            String jsonPayload = String.format(
                "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":false}",
                modelName,
                escapeJson(prompt)
            );

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");

            conn.getOutputStream().write(jsonPayload.getBytes(StandardCharsets.UTF_8));

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
            }
            conn.disconnect();

            // 解析并返回 response 字段
            return extractResponse(response.toString());
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }

    private String escapeJson(String text) {
        return text.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }

    private String extractResponse(String json) {
        Matcher matcher = RESPONSE_PATTERN.matcher(json);
        if (matcher.find()) {
            String response = matcher.group(1);
            // 处理转义的字符
            return response
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
        }
        return null;
    }
}