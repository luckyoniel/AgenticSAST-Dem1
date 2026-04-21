package com.agenticsast.llm;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.Proxy;
import java.nio.charset.StandardCharsets;

/**
 * Ollama LLM 客户端
 * 采用 Jackson 解析，并强制绕过系统代理直连本地大模型
 */
@Component
public class OllamaClient {

    // 某些环境或代理下 127.0.0.1 会报 403，改用 localhost 访问 Ollama
    private static final String OLLAMA_BASE_URL = "http://localhost:11434";
    // 如果由于环境问题依然存在代理或跨域拦截，可以考虑直接设置代理或者使用其他库
    // 不过在此我们保留原有的绕过代理设置。
    private static final int TIMEOUT_MS = 300000; // 5分钟超时

    /**
     * 调用 Ollama 流式接口
     */
    public void callStream(String prompt, String modelName, SseEmitter emitter) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode payload = mapper.createObjectNode();
            payload.put("model", modelName);
            payload.put("prompt", prompt);
            payload.put("stream", true);

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            // 【核心修复】：强制直连，无视系统 VPN/代理
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            // 某些 Ollama 版本强制要求 Content-Type 为 application/json 且不带有其他多余头部
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");

            // 删除多余的 User-Agent 等可能会被防火墙误判拦截的头
            
            conn.getOutputStream().write(mapper.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));

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
                                ObjectNode event = mapper.createObjectNode();
                                event.put("content", data);
                                emitter.send(SseEmitter.event().data(mapper.writeValueAsString(event) + "\n\n"));
                            }
                        } else if (node.has("error")) {
                            ObjectNode errorNode = mapper.createObjectNode();
                            errorNode.put("isError", true);
                            errorNode.put("content", "❌ " + node.get("error").asText());
                            emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errorNode) + "\n\n"));
                        }
                    }
                }
            } else {
                ObjectNode errorNode = mapper.createObjectNode();
                errorNode.put("isError", true);
                errorNode.put("content", "❌ Ollama 拒绝连接: HTTP " + responseCode + " (请检查代理或模型名称)");
                emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errorNode) + "\n\n"));
            }
            conn.disconnect();
            emitter.complete();
        } catch (Exception e) {
            emitter.completeWithError(e);
        }
    }

    /**
     * 调用 Ollama 并获取完整响应（非流式，同步加上免代理直连）
     */
    public String call(String prompt, String modelName) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode payload = mapper.createObjectNode();
            payload.put("model", modelName);
            payload.put("prompt", prompt);
            payload.put("stream", false);

            URL url = new URL(OLLAMA_BASE_URL + "/api/generate");
            // 【核心修复】：同步方法也强制直连
            HttpURLConnection conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Accept", "application/json");

            // 删除多余的 User-Agent
            
            conn.getOutputStream().write(mapper.writeValueAsString(payload).getBytes(StandardCharsets.UTF_8));

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
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
                return node.has("response") ? node.get("response").asText() : "";
            } else {
                return "{\"error\":\"HTTP " + responseCode + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\":\"" + e.getMessage() + "\"}";
        }
    }
}
