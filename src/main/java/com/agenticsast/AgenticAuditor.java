package com.agenticsast;

import com.agenticsast.llm.OllamaClient;
import com.agenticsast.model.AuditResult;
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
 * Pure Agentic 架构：直接注入全量源码，流式输出重构方案。
 */
@Service
public class AgenticAuditor {

    private static final String PRO_MODEL_NAME = "glm-5.1:cloud"; // 本地部署的超大参数模型

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
        return true; // SecretPatternScanner 适用于所有语言
    }

    private String getFileExtension(String filePath) {
        int lastDot = filePath.lastIndexOf('.');
        return lastDot > 0 ? filePath.substring(lastDot + 1).toLowerCase() : "";
    }

    /**
     * 全文件流式审计 (Pure Agentic)
     *
     * 接收完整源码，直接注入给超大模型，实时流式输出审计结果和重构代码。
     *
     * @param filePath 文件路径
     * @param fullSourceCode 完整源代码
     * @return SseEmitter 用于前端实时接收流式数据
     */
    public SseEmitter fullFileAuditStream(String filePath, String fullSourceCode) {
        SseEmitter emitter = new SseEmitter(0L);

        CompletableFuture.runAsync(() -> {
            try {
                // 核心：全量流式分析 Prompt (必须是 Markdown 和 thought，绝对不能要求 JSON)
                String prompt = "你是一个顶级的企业级安全架构师与代码审计专家。请对以下完整的源代码文件（路径：" + filePath + "）进行全局深度审计。\n\n" +
                        "【完整源码】：\n" + fullSourceCode + "\n\n" +
                        "【任务要求】：\n" +
                        "1. 寻找代码中潜在的业务逻辑漏洞、硬编码风险（特别是金融计算、365天硬编码、闰年等问题）。\n" +
                        "2. 严禁输出 JSON 格式！请直接以 Markdown 格式输出。\n" +
                        "3. 必须首先输出一个 `<thought>` 标签。在这个标签内，用安全专家的口吻（如 '正在分析控制流...'、'发现高危计息基准漏洞...'）写下你的详细审计思路。\n" +
                        "4. 思考结束后输出 `</thought>`。\n" +
                        "5. 最后输出【重构代码】，提供完整的、带有详细中文注释的修复后代码块。\n" +
                        "请直接开始输出，不要有任何客套话。";

                // 调用本地 Ollama 流式接口
                ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);

            } catch (Exception e) {
                System.err.println("[-] 全文件流式审计异常: " + e.getMessage());
                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data("审计异常: " + e.getMessage()));
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
     * 后端读取本地目录所有源码，拼接后调用大模型进行全量审计
     */
    public SseEmitter fullDirectoryAuditStream(String directoryPath) {
        SseEmitter emitter = new SseEmitter(0L);

        CompletableFuture.runAsync(() -> {
            try {
                // 1. 使用 Files.walk 遍历目录
                Path dirPath = Paths.get(directoryPath);
                if (!Files.exists(dirPath) || !Files.isDirectory(dirPath)) {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data("目录不存在或不是有效目录: " + directoryPath));
                    emitter.complete();
                    return;
                }

                // 2. 收集所有源码文件
                StringBuilder allSource = new StringBuilder();
                int fileCount = 0;

                List<Path> sourceFiles = Files.walk(dirPath)
                        .filter(Files::isRegularFile)
                        .filter(p -> {
                            String name = p.getFileName().toString().toLowerCase();
                            return name.endsWith(".java") || name.endsWith(".cbl") || name.endsWith(".cpy")
                                    || name.endsWith(".xml") || name.endsWith(".json");
                        })
                        .toList();

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

                if (fileCount == 0) {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data("在目录中未找到任何可审计的源码文件 (.java, .cbl, .cpy)"));
                    emitter.complete();
                    return;
                }

                // 3. 构建流式审计 Prompt
                String prompt = "你是一个顶级的企业级安全架构师与代码审计专家。请对以下【全量目录源码】进行深度安全审计：\n" +
                        "【目标目录】: " + directoryPath + "\n" +
                        "【文件数量】: " + fileCount + " 个源码文件\n" +
                        "【完整源码】:\n" + allSource.toString() + "\n\n" +
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
                        "- 代码位置\n" +
                        "- 严重程度（BLOCK / WARN / INFO）\n" +
                        "- 详细描述和业务危害\n\n" +
                        "## 修复代码\n" +
                        "针对 BLOCK 和 WARN 级别的问题，提供完整可直接使用的修复代码（带中文注释）。\n\n" +
                        "现在开始！不要输出任何客套话，直接开始思考！";

                // 4. 调用流式接口
                ollamaClient.callStream(prompt, PRO_MODEL_NAME, emitter);

            } catch (Exception e) {
                System.err.println("[-] 全量目录审计异常: " + e.getMessage());
                try {
                    emitter.send(SseEmitter.event()
                            .name("error")
                            .data("目录审计异常: " + e.getMessage()));
                } catch (Exception sendError) {
                    // ignore
                }
                emitter.completeWithError(e);
            }
        });

        return emitter;
    }
}