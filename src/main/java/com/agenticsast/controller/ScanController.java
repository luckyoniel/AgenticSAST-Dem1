package com.agenticsast.controller;

import com.agenticsast.AgenticAuditor;
import com.agenticsast.FileModifier;
import com.agenticsast.model.ApplyFixRequest;
import com.agenticsast.model.AuditResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 前端接口 (ScanController)
 */
@RestController
@RequestMapping("/api")
public class ScanController {

    private final AgenticAuditor agenticAuditor;
    private final FileModifier fileModifier;

    @Autowired
    public ScanController(AgenticAuditor agenticAuditor, FileModifier fileModifier) {
        this.agenticAuditor = agenticAuditor;
        this.fileModifier = fileModifier;
    }

    /**
     * 单文件流式审计接口（SSE）
     */
    @PostMapping(value = "/audit/full-stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter fullFileAuditStream(@RequestBody Map<String, String> payload) {
        String sourceCode = payload.get("sourceCode");
        String filePath = payload.getOrDefault("filePath", "unknown");
        if (sourceCode == null || sourceCode.isEmpty()) {
            throw new IllegalArgumentException("源码为空");
        }
        return agenticAuditor.fullFileAuditStream(filePath, sourceCode);
    }

    /**
     * 全量目录流式审计接口（SSE）
     * 后端读取本地目录，调用大模型进行全量审计
     */
    @PostMapping(value = "/audit/dir-stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter dirAuditStream(@RequestBody Map<String, String> payload) {
        String path = payload.get("path");
        if (path == null || path.isEmpty()) {
            throw new IllegalArgumentException("路径为空");
        }
        return agenticAuditor.fullDirectoryAuditStream(path);
    }

    /**
     * 接收前端传来的代码字符串，调用大模型进行审计
     *
     * @param payload 包含 "sourceCode" 的 JSON 对象
     * @return 审计结果列表
     */
    @PostMapping("/scan")
    public ResponseEntity<?> scanCode(@RequestBody Map<String, String> payload) {
        String sourceCode = payload.get("sourceCode");
        // Web 前端暂不涉及真实文件路径，传入一个虚拟的文件名标识
        String filePath = payload.getOrDefault("filePath", "WebEditor.java");
        
        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Source code cannot be empty");
        }

        try {
            List<AuditResult> results = agenticAuditor.auditCode(filePath, sourceCode);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error during code audit: " + e.getMessage());
        }
    }

    /**
     * 接收前端传来的本地目录路径，进行全目录批量扫描
     *
     * @param payload 包含 "path" 的 JSON 对象
     * @return 审计结果列表
     */
    @PostMapping("/scan-dir")
    public ResponseEntity<?> scanDirectory(@RequestBody Map<String, String> payload) {
        String path = payload.get("path");
        if (path == null || path.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Directory path cannot be empty");
        }

        try {
            List<AuditResult> results = agenticAuditor.scanDirectory(path);
            return ResponseEntity.ok(results);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error during directory scan: " + e.getMessage());
        }
    }

    /**
     * 接收前端传来的修复请求，一键将 AI 建议应用到源文件中
     *
     * @param request 修复请求参数
     * @return 操作结果
     */
    @PostMapping("/apply-fix")
    public ResponseEntity<?> applyFix(@RequestBody ApplyFixRequest request) {
        if (request.getFilePath() == null || request.getOldCode() == null || request.getNewCode() == null) {
            return ResponseEntity.badRequest().body("缺少必要的参数：filePath, oldCode 或 newCode");
        }

        try {
            boolean success = fileModifier.applyFixToFile(request.getFilePath(), request.getOldCode(), request.getNewCode());
            Map<String, Object> response = new HashMap<>();
            response.put("success", success);
            if (success) {
                response.put("message", "修复成功！已写入文件");
            } else {
                response.put("message", "替换失败：在源文件中找不到完全匹配的原代码切片，或文件不存在");
            }
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("替换过程中发生错误：" + e.getMessage());
        }
    }
}
