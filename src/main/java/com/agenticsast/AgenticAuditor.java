package com.agenticsast;

import com.agenticsast.llm.OllamaClient;
import com.agenticsast.model.AuditResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.agenticsast.scanner.CodeScanner;
import com.agenticsast.scanner.CobolLegacyScanner;
import com.agenticsast.scanner.JavaAstScanner;
import com.agenticsast.scanner.SecretPatternScanner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * 智能审计大脑 (AgenticAuditor)
 * V2.0: 上下文截断防护 & 多批次扫描模式
 */
@Service
public class AgenticAuditor {

    private static final String PRO_MODEL_NAME = "glm-5:cloud";
    
    // V2.0: 上下文限制常量
    private static final int MAX_TOKENS_APPROX = 32000; // 32k Token 上限
    private static final int TOKENS_PER_CHAR = 4; // 粗略估算：1 Token ≈ 4 字符
    private static final int MAX_CHARS = MAX_TOKENS_APPROX * TOKENS_PER_CHAR; // ≈ 128k 字符
    private static final int BATCH_SIZE_WARNING_THRESHOLD = 5000; // 单文件超过此行数触发警告

    private final OllamaClient ollamaClient;
    private final GrcPolicyManager grcPolicyManager;
    private final List<CodeScanner> scanners;

    @Autowired
    public AgenticAuditor(OllamaClient ollamaClient, GrcPolicyManager grcPolicyManager) {
        this.ollamaClient = ollamaClient;
        this.grcPolicyManager = grcPolicyManager;
        this.scanners = Arrays.asList(
            new JavaAstScanner(),
            new SecretPatternScanner(),
            new CobolLegacyScanner()
        );
    }

    /**
     * 审计单个代码字符串
     *
     * @param filePath 文件路径（用于标识）
     * @param sourceCode 源代码
     * @return 审计结果列表
     */
    public List<AuditResult> auditCode(String filePath, String sourceCode) {
        List<AuditResult> results = new ArrayList<>();

        // 1. 执行传统规则扫描
        String extension = getFileExtension(filePath);
        for (CodeScanner scanner : scanners) {
            if (isApplicable(scanner, extension)) {
                var matches = scanner.scan(filePath, sourceCode);
                for (var match : matches) {
                    AuditResult result = new AuditResult(
                        filePath,
                        match.codeSlice,
                        "WARN",
                        match.ruleId,
                        match.ruleDescription,
                        "Medium",
                        null
                    );
                    grcPolicyManager.applyPolicy(result);
                    results.add(result);
                }
            }
        }

        // 2. 如果有高危风险，调用 LLM 进行深度审计
        boolean needsLlama = results.stream().anyMatch(r -> "BLOCK".equals(r.getStatus()));
        if (needsLlama || results.isEmpty()) {
            String llmAnalysis = ollamaClient.call(
                "你是一个安全审计专家。请分析以下代码，找出潜在的安全漏洞和风险：\n" + sourceCode,
                PRO_MODEL_NAME
            );

            // 如果发现新的漏洞，添加到结果中
            if (llmAnalysis != null && !llmAnalysis.isEmpty() && !llmAnalysis.startsWith("{\"error\"")) {
                AuditResult llmResult = new AuditResult(
                    filePath,
                    sourceCode.length() > 500 ? sourceCode.substring(0, 500) + "..." : sourceCode,
                    "WARN",
                    "LLM-001",
                    "LLM 深度分析",
                    "High",
                    llmAnalysis
                );
                grcPolicyManager.applyPolicy(llmResult);
                results.add(llmResult);
            }
        }

        return results;
    }

    /**
     * 扫描目录中的所有文件并审计
     *
     * @param directoryPath 目录路径
     * @return 审计结果列表
     */
    public List<AuditResult> scanDirectory(String directoryPath) {
        Path path = Paths.get(directoryPath);
        if (!Files.exists(path) || !Files.isDirectory(path)) {
            throw new IllegalArgumentException("无效的目录路径: " + directoryPath);
        }

        List<AuditResult> allResults = new ArrayList<>();

        try {
            Files.walk(path)
                .filter(Files::isRegularFile)
                .filter(p -> isSourceFile(p.toString()))
                .forEach(filePath -> {
                    try {
                        String content = Files.readString(filePath);
                        String relativePath = path.relativize(filePath).toString();
                        List<AuditResult> results = auditCode(relativePath, content);
                        allResults.addAll(results);
                    } catch (IOException e) {
                        System.err.println("读取文件失败: " + filePath + " - " + e.getMessage());
                    }
                });
        } catch (IOException e) {
            System.err.println("遍历目录失败: " + e.getMessage());
        }

        return allResults;
    }

    private boolean isSourceFile(String filePath) {
        String lower = filePath.toLowerCase();
        return lower.endsWith(".java") || lower.endsWith(".py") ||
               lower.endsWith(".js") || lower.endsWith(".ts") ||
               lower.endsWith(".c") || lower.endsWith(".cpp") ||
               lower.endsWith(".cob") || lower.endsWith(".cbl") ||
               lower.endsWith(".go") || lower.endsWith(".rs");
    }

    private boolean isApplicable(CodeScanner scanner, String extension) {
        if (scanner instanceof JavaAstScanner) {
            return "java".equals(extension);
        }
        if (scanner instanceof CobolLegacyScanner) {
            return "cob".equals(extension) || "cbl".equals(extension);
        }
        return true;
    }

    private String getFileExtension(String filePath) {
        int lastDot = filePath.lastIndexOf('.');
        return lastDot > 0 ? filePath.substring(lastDot + 1).toLowerCase() : "";
    }

    /**
     * 全文件流式审计 (Pure Agentic)
     *
     * @param filePath 文件路径
     * @param fullSourceCode 完整源代码
     * @return SseEmitter 用于前端实时接收流式数据
     */
    public SseEmitter fullFileAuditStream(String filePath, String fullSourceCode) {
        SseEmitter emitter = new SseEmitter(0L);

        CompletableFuture.runAsync(() -> {
            ObjectMapper mapper = new ObjectMapper();
            try {
                String prompt = "你是一个顶级的企业级安全架构师与代码审计专家。请对以下完整的源代码文件（路径：" + filePath + "）进行全局深度审计。\n\n" +
                        "【完整源码】：\n" + fullSourceCode + "\n\n" +
                        "【任务要求】：\n" +
                        "1. 寻找代码中潜在的业务逻辑漏洞、硬编码风险（特别是金融计算、365天硬编码、闰年等问题）。\n" +
                        "2. 严禁输出 JSON 格式！请直接以 Markdown 格式输出。\n" +
                        "3. 当你提及代码位置时，必须使用方括号包裹完整相对路径，例如：`在 [src/main/java/com/example/Calculator.java] 的第 23 行...`。\n" +
                        "4. 必须首先输出一个 `<thought>` 标签。在这个标签内，用安全专家的口吻（如 '正在分析控制流...'、'发现高危计息基准漏洞...'）写下你的详细审计思路。\n" +
                        "5. 思考结束后输出 `</thought>`。\n" +
                        "6. 当你发现漏洞并提供修复代码时，**必须严格使用以下 XML 格式输出替换逻辑（不要使用 Markdown 代码块包裹 XML）**：\n" +
                        "   <replace>\n" +
                        "   <old>这里原封不动地输出有漏洞的旧代码片段。重要：必须至少包含 3 行完整的代码，确保能够唯一匹配源码中的位置。</old>\n" +
                        "   <new>这里输出修复后的新代码片段。必须与 <old> 中的代码行数保持一致。</new>\n" +
                        "   </replace>\n" +
                        "7. 最后输出【重构代码】，提供完整的、带有详细中文注释的修复后代码块。\n" +
                        "请直接开始输出，不要有任何客套话。";

                ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);

            } catch (Exception e) {
                System.err.println("[-] 全文件流式审计异常: " + e.getMessage());
                try {
                    ObjectNode errNode = mapper.createObjectNode();
                    errNode.put("isError", true);
                    errNode.put("content", "❌ 审计异常: " + e.getMessage());
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errNode) + "\n\n"));
                } catch (Exception sendError) {
                    // ignore
                }
                emitter.completeWithError(e);
            }
        });

        return emitter;
    }

    /**
     * 全量目录审计流式接口
     * V2.0: 上下文截断防护 - 检测内容大小并自动切换到多批次扫描模式
     */
    public SseEmitter fullDirectoryAuditStream(String directoryPath) {
        SseEmitter emitter = new SseEmitter(0L);

        CompletableFuture.runAsync(() -> {
            try {
                ObjectMapper mapper = new ObjectMapper();
                Path dirPath = Paths.get(directoryPath);
                if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                    ObjectNode errNode = mapper.createObjectNode();
                    errNode.put("isError", true);
                    errNode.put("content", "❌ 目录不存在或不是有效目录: " + directoryPath);
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errNode) + "\n\n"));
                    emitter.complete();
                    return;
                }

                // V2.0: 收集所有源码文件
                List<Path> sourceFiles = Files.walk(dirPath)
                        .filter(Files::isRegularFile)
                        .filter(p -> {
                            String name = p.getFileName().toString().toLowerCase();
                            return name.endsWith(".java") || name.endsWith(".cbl") || name.endsWith(".cpy")
                                    || name.endsWith(".xml") || name.endsWith(".json");
                        })
                        .toList();

                if (sourceFiles.isEmpty()) {
                    ObjectNode errNode = mapper.createObjectNode();
                    errNode.put("isError", true);
                    errNode.put("content", "❌ 在目录中未找到任何可审计的源码文件 (.java, .cbl, .cpy)");
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errNode) + "\n\n"));
                    emitter.complete();
                    return;
                }

                // V2.0: 计算总内容大小
                long totalBytes = 0;
                List<String> fileSizes = new ArrayList<>();
                for (Path filePath : sourceFiles) {
                    try {
                        long size = Files.size(filePath);
                        totalBytes += size;
                        if (size > 1024) { // 只记录大于 1KB 的文件
                            fileSizes.add(filePath.getFileName().toString() + "(" + (size/1024) + "KB)");
                        }
                    } catch (Exception e) {
                        // 忽略
                    }
                }

                // V2.0: 检测是否超过上下文限制
                boolean exceedsContextLimit = totalBytes > MAX_CHARS;
                boolean hasLargeFiles = sourceFiles.stream().anyMatch(p -> {
                    try {
                        return Files.size(p) > 50000; // 单文件 > 50KB
                    } catch (Exception e) {
                        return false;
                    }
                });

                // V2.0: 根据内容大小选择审计策略
                if (exceedsContextLimit || hasLargeFiles) {
                    // 多批次扫描模式
                    auditInBatches(dirPath, sourceFiles, mapper, emitter, totalBytes);
                } else {
                    // 标准模式：全部拼接
                    auditAllAtOnce(dirPath, sourceFiles, mapper, emitter);
                }

            } catch (Exception e) {
                System.err.println("[-] 全量目录审计异常: " + e.getMessage());
                try {
                    ObjectMapper mapper = new ObjectMapper();
                    ObjectNode errNode = mapper.createObjectNode();
                    errNode.put("isError", true);
                    errNode.put("content", "❌ 目录审计异常: " + e.getMessage());
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(errNode) + "\n\n"));
                } catch (Exception sendError) {
                    // ignore
                }
                emitter.completeWithError(e);
            }
        });

        return emitter;
    }

    /**
     * V2.0: 标准模式 - 一次性审计所有文件
     */
    private void auditAllAtOnce(Path dirPath, List<Path> sourceFiles, ObjectMapper mapper, SseEmitter emitter) throws Exception {
        StringBuilder allSource = new StringBuilder();
        int fileCount = 0;

        for (Path filePath : sourceFiles) {
            try {
                String content = Files.readString(filePath);
                String relativePath = dirPath.relativize(filePath).toString();
                allSource.append("=== 文件: ").append(relativePath).append(" ===\n");
                allSource.append(content).append("\n\n");
                fileCount++;
            } catch (Exception e) {
                // 跳过无法读取的文件
            }
        }

        // 发送开始信息
        ObjectNode startNode = mapper.createObjectNode();
        startNode.put("isStart", true);
        startNode.put("fileCount", fileCount);
        startNode.put("totalSize", allSource.length());
        startNode.put("mode", "standard");
        emitter.send(SseEmitter.event().data(mapper.writeValueAsString(startNode) + "\n\n"));

        // 构建 Prompt
        String prompt = buildAuditPrompt(dirPath.toString(), fileCount, allSource.toString(), false);
        ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);
    }

    /**
     * V2.0: 多批次扫描模式 - 处理大项目
     */
    private void auditInBatches(Path dirPath, List<Path> sourceFiles, ObjectMapper mapper, SseEmitter emitter, long totalBytes) throws Exception {
        // 发送多批次模式警告
        ObjectNode warnNode = mapper.createObjectNode();
        warnNode.put("isWarning", true);
        warnNode.put("content", "⚠️ 项目内容较大（约 " + (totalBytes / 1024) + " KB），系统将采用多批次扫描模式。\n" +
                "系统将优先分析核心业务逻辑文件，确保审计质量。");
        emitter.send(SseEmitter.event().data(mapper.writeValueAsString(warnNode) + "\n\n"));

        // 按优先级分组文件
        List<Path> priorityFiles = new ArrayList<>(); // 核心业务文件
        List<Path> normalFiles = new ArrayList<>();    // 普通文件

        for (Path file : sourceFiles) {
            String name = file.getFileName().toString().toLowerCase();
            // 高优先级：业务逻辑文件
            if (name.contains("service") || name.contains("controller") || 
                name.contains("model") || name.contains("business") ||
                name.contains("logic") || name.contains("core")) {
                priorityFiles.add(file);
            } else {
                normalFiles.add(file);
            }
        }

        // 批次大小估算
        int batchSize = 10; // 每批 10 个文件
        int currentBatch = 0;
        int totalBatches = (int) Math.ceil((double) sourceFiles.size() / batchSize);

        // V2.0: 分批次处理，监控上下文使用
        StringBuilder batchSource = new StringBuilder();
        int batchFileCount = 0;
        int processedFiles = 0;

        // 优先处理核心文件
        List<Path> allToProcess = new ArrayList<>();
        allToProcess.addAll(priorityFiles);
        allToProcess.addAll(normalFiles);

        for (Path filePath : allToProcess) {
            try {
                String content = Files.readString(filePath);
                String relativePath = dirPath.relativize(filePath).toString();
                
                // V2.0: 检查是否需要开始新批次
                if (batchSource.length() + content.length() > MAX_CHARS * 0.8) {
                    // 当前批次已满，发送并开始新批次
                    currentBatch++;
                    ObjectNode batchNode = mapper.createObjectNode();
                    batchNode.put("isBatchStart", true);
                    batchNode.put("batchNumber", currentBatch);
                    batchNode.put("totalBatches", totalBatches);
                    batchNode.put("fileCount", batchFileCount);
                    emitter.send(SseEmitter.event().data(mapper.writeValueAsString(batchNode) + "\n\n"));

                    String prompt = buildAuditPrompt(dirPath.toString(), batchFileCount, batchSource.toString(), true);
                    ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);

                    batchSource = new StringBuilder();
                    batchFileCount = 0;
                    
                    // 批次间短暂延迟，让模型有时间处理
                    Thread.sleep(500);
                }

                batchSource.append("=== 文件: ").append(relativePath).append(" ===\n");
                batchSource.append(content).append("\n\n");
                batchFileCount++;
                processedFiles++;

            } catch (Exception e) {
                // 跳过无法读取的文件
            }
        }

        // 发送最后批次
        if (batchSource.length() > 0) {
            currentBatch++;
            ObjectNode batchNode = mapper.createObjectNode();
            batchNode.put("isBatchStart", true);
            batchNode.put("batchNumber", currentBatch);
            batchNode.put("totalBatches", currentBatch);
            batchNode.put("fileCount", batchFileCount);
            batchNode.put("isLastBatch", true);
            emitter.send(SseEmitter.event().data(mapper.writeValueAsString(batchNode) + "\n\n"));

            String prompt = buildAuditPrompt(dirPath.toString(), batchFileCount, batchSource.toString(), true);
            ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);
        }

        // 发送完成信息
        ObjectNode doneNode = mapper.createObjectNode();
        doneNode.put("isDone", true);
        doneNode.put("processedFiles", processedFiles);
        doneNode.put("totalBatches", currentBatch);
        emitter.send(SseEmitter.event().data(mapper.writeValueAsString(doneNode) + "\n\n"));
    }

    /**
     * V2.0: 构建审计 Prompt
     * @param isBatchMode 是否为批次模式
     */
    private String buildAuditPrompt(String directoryPath, int fileCount, String allSource, boolean isBatchMode) {
        String modeHint = isBatchMode ? 
            "【重要】由于项目较大，本次为批次扫描。请重点关注本批次内的漏洞和代码质量问题。" :
            "";

        return "你是一个顶级的企业级安全架构师与代码审计专家。请对以下【全量目录源码】进行深度安全审计：\n" +
                "【目标目录】: " + directoryPath + "\n" +
                "【文件数量】: " + fileCount + " 个源码文件\n" +
                modeHint + "\n\n" +
                "【完整源码】:\n" + allSource + "\n\n" +
                "【强制输出格式 - 必须严格按顺序执行】：\n\n" +
                "<thought>\n" +
                "首先，在你正式开始输出之前，必须在这里用极客黑客的口吻写下你的审计思路。\n" +
                "例如你可以这样写：\n" +
                "• 正在解析依赖树，扫描潜在注入点...\n" +
                "• 追踪数据流：发现可疑的未校验外部输入...\n" +
                "• 内存安全扫描：发现可能的缓冲区边界溢出风险...\n" +
                "• 认证授权链路：检测到水平越权漏洞存在于 API 层...\n" +
                "• 加密算法审查：检测到使用了不安全的 DES 算法...\n" +
                "• 业务逻辑漏洞：订单金额计算未考虑并发竞争条件...\n" +
                "请结合实际代码，输出至少 5-8 条具体的技术洞察。\n" +
                "</thought>\n\n" +
                "## 深度审计发现\n" +
                "基于上述思考，列出所有发现的问题：\n" +
                "- 问题编号（如 OWA-001）\n" +
                "- 问题名称\n" +
                "- 代码位置（必须使用方括号包裹完整相对路径，例如：在 [src/main/java/com/example/Calculator.java] 的第 23 行...）\n" +
                "- 严重程度（BLOCK / WARN / INFO）\n" +
                "- 详细描述和业务危害\n\n" +
                "## 修复代码\n" +
                "针对 BLOCK 和 WARN 级别的问题，提供完整可直接使用的修复代码（带中文注释）。\n\n" +
                "【重要】当你发现漏洞并提供修复代码时，**必须严格使用以下 XML 格式输出替换逻辑（不要使用 Markdown 代码块包裹 XML）**：\n" +
                "   <replace>\n" +
                "   <old>这里原封不动地输出有漏洞的旧代码片段。重要：必须至少包含 3 行完整的代码，确保能够唯一匹配源码中的位置。保留原始缩进和格式。</old>\n" +
                "   <new>这里输出修复后的新代码片段。必须与 <old> 中的代码行数保持一致，保留相同的缩进风格。</new>\n" +
                "   </replace>\n\n" +
                "现在开始！不要输出任何客套话，直接开始思考！";
    }
}
