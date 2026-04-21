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
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 前端接口 (ScanController)
 * V2.1: 严格路径穿越防御 - 使用 Path.resolve() 和 startsWith() 双重校验
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {org.springframework.web.bind.annotation.RequestMethod.GET, org.springframework.web.bind.annotation.RequestMethod.POST, org.springframework.web.bind.annotation.RequestMethod.OPTIONS})
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
     */
    @PostMapping("/scan")
    public ResponseEntity<?> scanCode(@RequestBody Map<String, String> payload) {
        String sourceCode = payload.get("sourceCode");
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

    /**
     * 获取目录下的文件树（仅 .java, .cbl, .cpy 文件）
     */
    @GetMapping("/files/tree")
    public ResponseEntity<?> getFileTree(@RequestParam String path) {
        if (path == null || path.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("路径不能为空");
        }

        try {
            Path rootPath = Paths.get(path);
            if (!Files.exists(rootPath) || !Files.isDirectory(rootPath)) {
                return ResponseEntity.badRequest().body("目录不存在或不是有效目录: " + path);
            }

            try (Stream<Path> walk = Files.walk(rootPath)) {
                List<String> filePaths = walk
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.endsWith(".java") || name.endsWith(".cbl") || name.endsWith(".cpy");
                    })
                    .map(rootPath::relativize)
                    .map(Path::toString)
                    .sorted()
                    .collect(Collectors.toList());

                return ResponseEntity.ok(filePaths);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("遍历目录时发生错误：" + e.getMessage());
        }
    }

    /**
     * 读取指定文件的源码内容
     * V2.1: 严格路径穿越防御
     */
    @GetMapping("/files/content")
    public ResponseEntity<?> getFileContent(@RequestParam String rootPath, @RequestParam String relativePath) {
        if (rootPath == null || rootPath.trim().isEmpty() || relativePath == null || relativePath.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("参数不完整：rootPath 或 relativePath 不能为空");
        }

        try {
            // V2.1: 核心路径校验逻辑
            Path root = Paths.get(rootPath).normalize().toAbsolutePath();
            
            // V2.1: 显式拒绝包含 ".." 的路径
            if (relativePath.contains("..")) {
                throw new SecurityException("非法路径：relativePath 中不允许包含 '..'");
            }

            // V2.1: 使用 resolve() 而非直接拼接，确保路径安全
            Path file = root.resolve(relativePath).normalize().toAbsolutePath();

            // V2.1: 严格校验 - 文件必须在 root 目录内
            if (!file.startsWith(root)) {
                throw new SecurityException("非法路径：不允许访问目录外的文件");
            }

            if (!Files.exists(file)) {
                return ResponseEntity.badRequest().body("文件不存在: " + file);
            }

            // V2.1: 文件类型白名单检查
            String fileName = file.getFileName().toString().toLowerCase();
            if (!fileName.endsWith(".java") && !fileName.endsWith(".cbl") && !fileName.endsWith(".cpy")
                && !fileName.endsWith(".xml") && !fileName.endsWith(".json")) {
                return ResponseEntity.badRequest().body("不支持的文件类型: " + fileName);
            }

            String content = Files.readString(file, StandardCharsets.UTF_8);
            return ResponseEntity.ok(content);
        } catch (SecurityException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("读取文件失败：" + e.getMessage());
        }
    }

    /**
     * 保存文件内容到磁盘
     * V2.1: 严格路径穿越防御 - 核心安全接口
     */
    @PostMapping("/files/save")
    public ResponseEntity<?> saveFileContent(@RequestBody Map<String, String> payload) {
        String rootPath = payload.get("rootPath");
        String relativePath = payload.get("relativePath");
        String content = payload.get("content");

        if (rootPath == null || rootPath.trim().isEmpty() || relativePath == null || relativePath.trim().isEmpty() || content == null) {
            return ResponseEntity.badRequest().body("参数不完整：rootPath、relativePath 或 content 不能为空");
        }

        try {
            // V2.1: 核心路径校验逻辑
            Path root = Paths.get(rootPath).normalize().toAbsolutePath();
            
            // V2.1: 显式拒绝包含 ".." 的路径
            if (relativePath.contains("..")) {
                throw new SecurityException("非法路径：relativePath 中不允许包含 '..'");
            }

            // V2.1: 使用 resolve() 而非 Paths.get() 拼接
            // resolve() 会正确处理路径，防止通过相对路径绕过安全检查
            Path file = root.resolve(relativePath).normalize().toAbsolutePath();

            // V2.1: 严格校验 - 文件必须在 root 目录内
            // 这是防止路径穿越的最后防线
            if (!file.startsWith(root)) {
                throw new SecurityException("非法路径：不允许访问目录外的文件");
            }

            // V2.1: 文件类型白名单检查
            String fileName = file.getFileName().toString().toLowerCase();
            if (!fileName.endsWith(".java") && !fileName.endsWith(".cbl") && !fileName.endsWith(".cpy")
                && !fileName.endsWith(".xml") && !fileName.endsWith(".json") && !fileName.endsWith(".properties")) {
                return ResponseEntity.badRequest().body("不支持的文件类型: " + fileName);
            }

            // 确保父目录存在
            if (file.getParent() != null && !Files.exists(file.getParent())) {
                Files.createDirectories(file.getParent());
            }

            Files.writeString(file, content, StandardCharsets.UTF_8);
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "文件保存成功！");
            response.put("filePath", file.toString());
            return ResponseEntity.ok(response);
        } catch (SecurityException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("保存文件失败：" + e.getMessage());
        }
    }
}
