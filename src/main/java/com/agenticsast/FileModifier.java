package com.agenticsast;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 文件修改器：负责将 AI 的修复建议一键应用到本地源文件
 */
@Service
public class FileModifier {

    // 匹配 Markdown 代码块标记，例如 ```java 或 ```cobol 以及结尾的 ```
    private static final Pattern MARKDOWN_CODE_BLOCK_PATTERN = Pattern.compile("```[a-zA-Z]*\\s*\\n?([\\s\\S]*?)\\n?```");

    /**
     * 将 AI 修复代码应用到指定文件中
     *
     * @param filePath 目标文件绝对路径
     * @param oldCodeSlice 原本的漏洞代码切片（包含行号前缀）
     * @param newAiCode AI 返回的修复代码
     * @return 是否替换成功
     */
    public boolean applyFixToFile(String filePath, String oldCodeSlice, String newAiCode) {
        Path path = Paths.get(filePath);
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            System.err.println("[-] 替换失败：找不到文件 " + filePath);
            return false;
        }

        try {
            // 1. 读取原文件全部内容
            String originalFileContent = Files.readString(path);

            // 2. 清理 AI 返回代码中的 Markdown 标记
            String cleanNewCode = extractCleanCode(newAiCode);

            // 3. 清理原代码切片中的行号前缀（例如 "12: " 或 "123: "）
            // 因为源文件中并没有这些行号，我们需要用纯代码去匹配替换
            String cleanOldCode = removeLineNumbers(oldCodeSlice);

            // 4. 执行替换
            // 注意：考虑到空格和缩进可能因为格式化问题不完全一致，
            // 简单字符串替换要求严格匹配。如果遇到替换失败，可以考虑用更智能的基于 AST 或正则忽略空白字符的替换方案。
            // 这里为了 Demo 的可行性，我们先尝试直接替换。
            
            // 为了提高替换成功率，可以尝试规范化两边的换行符
            String normalizedOriginalContent = originalFileContent.replace("\r\n", "\n");
            String normalizedCleanOldCode = cleanOldCode.replace("\r\n", "\n").trim();
            
            // 如果原文件不包含这段代码（可能已经被改过了，或者空白字符不匹配）
            if (!normalizedOriginalContent.contains(normalizedCleanOldCode)) {
                System.err.println("[-] 替换失败：在源文件中找不到完全匹配的原代码切片。");
                System.err.println("--- 期望匹配的切片片段 (规范化后) ---");
                System.err.println(normalizedCleanOldCode);
                return false;
            }

            // 执行替换操作
            String updatedContent = normalizedOriginalContent.replace(normalizedCleanOldCode, cleanNewCode);

            // 5. 将修改后的内容写回文件
            Files.writeString(path, updatedContent);
            System.out.println("[+] 成功将修复代码应用到文件: " + filePath);
            return true;

        } catch (IOException e) {
            System.err.println("[-] 读写文件时发生异常: " + e.getMessage());
            return false;
        }
    }

    /**
     * 提取 Markdown 代码块中的纯代码
     */
    private String extractCleanCode(String aiCode) {
        if (aiCode == null) return "";
        Matcher matcher = MARKDOWN_CODE_BLOCK_PATTERN.matcher(aiCode);
        if (matcher.find()) {
            return matcher.group(1).trim(); // 提取正则中的第一个括号内容
        }
        // 如果没有 markdown 标记，就直接返回原串并去首尾空白
        return aiCode.replace("```", "").trim(); 
    }

    /**
     * 移除扫描切片中自带的行号前缀（例如 "15: "）
     */
    private String removeLineNumbers(String codeSlice) {
        if (codeSlice == null) return "";
        String[] lines = codeSlice.split("\\r?\\n");
        StringBuilder sb = new StringBuilder();
        
        Pattern linePrefixPattern = Pattern.compile("^\\d+:\\s*");
        
        for (String line : lines) {
            Matcher m = linePrefixPattern.matcher(line);
            if (m.find()) {
                // 替换掉行号前缀，然后追加换行
                sb.append(m.replaceFirst("")).append("\n");
            } else {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }
}
