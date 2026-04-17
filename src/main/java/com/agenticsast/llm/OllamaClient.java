package com.agenticsast.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Ollama LLM 客户端
 * 负责与本地部署的 Ollama 大模型进行 HTTP 通信
 */
@Component
public class OllamaClient {

    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    private static final int TIMEOUT_MS = 300000; // 5分钟超时
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 调用 Ollama 流式接口
     *
     * @param prompt     提示词
     * @param modelName  模型名称
     * @param emitter    SSE 发射器，用于将流式数据推送回前端
     */
    public void callStream(String prompt, String modelName, SseEmitter emitter) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode payload = mapper.createObjectNode();
            payload.put("model", modelName);
            payload.put("prompt", prompt);
            payload.put("stream", true);

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            // 强制直连，无视系统 VPN/代理
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");

            conn.getOutputStream().write(mapper.writeValueAsBytes(payload));

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        if (line.trim().isEmpty()) continue;
                        JsonNode node = mapper.readTree(line);
                        if (node.has("response")) {
                            String data = node.get("response").asText();
                            if (!data.isEmpty()) {
                                Map<String, String> event = new HashMap<>();
                                event.put("content", data);
                                emitter.send(SseEmitter.event().name("content").data(event));
                            }
                        }
                    }
                }
            } else {
                emitter.send(SseEmitter.event().name("error").data("Ollama 拒绝连接: HTTP " + responseCode));
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
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode payload = mapper.createObjectNode();
            payload.put("model", modelName);
            payload.put("prompt", prompt);
            payload.put("stream", false);

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json");

            conn.getOutputStream().write(mapper.writeValueAsBytes(payload));

            StringBuilder response = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
            }
            conn.disconnect();

            JsonNode node = mapper.readTree(response.toString());
            return node.path("response").asText("");
        } catch (Exception e) {
            Map<String, String> errorData = new HashMap<>();
            errorData.put("error", e.getMessage());
            try {
                return objectMapper.writeValueAsString(errorData);
            } catch (Exception jsonError) {
                return "{\"error\":\"解析失败\"}";
            }
        }
    }
}
