package com.agenticsast.scanner;

import com.agenticsast.model.ScanMatch;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * COBOL 遗留系统安全扫描器 - 轻量级词法状态机 & 污点追踪引擎
 *
 * 采用【词法解析 → 符号表构建 → 污点传播分析 → 汇聚点检测】四阶段架构
 */
@Component
public class CobolLegacyScanner implements CodeScanner {

    // 白名单
    private static final Set<String> FOUNDATION_WHITELIST = Set.of(
            "LEAPYEAR.CPY", "LEAPYEAR.CBL", "LEAPYEAR-PARA.CPY",
            "DATE-UTIL.CPY", "DATE-UTIL.CBL", "LEAPYEAR-CHECK.CPY"
    );

    private static final Set<String> DANGEROUS_CONSTANTS = Set.of("365", "366", "28", "29");

    private static final Pattern MOVE_PATTERN = Pattern.compile(
            "(?i)MOVE\\s+(.+?)\\s+TO\\s+([A-Z0-9\\-]+)"
    );
    private static final Pattern COMPUTE_PATTERN = Pattern.compile(
            "(?i)COMPUTE\\s+([A-Z0-9\\-]+)\\s*=\\s*(.+)"
    );
    private static final Pattern MULTIPLY_PATTERN = Pattern.compile(
            "(?i)MULTIPLY\\s+([A-Z0-9\\-]+)\\s+(?:BY|INTO)\\s+([A-Z0-9\\-]+)"
    );
    private static final Pattern DIVIDE_PATTERN = Pattern.compile(
            "(?i)DIVIDE\\s+([A-Z0-9\\-]+)\\s+(?:BY|INTO)\\s+([A-Z0-9\\-]+)"
    );
    private static final Pattern VALUE_PATTERN = Pattern.compile(
            "(?i)([A-Z][A-Z0-9\\-]+)[^\\.]{1,50}?VALUE\\s+['\"]?(365|366|28|29)['\"]?"
    );
    private static final Pattern PERFORM_PATTERN = Pattern.compile(
            "(?i)PERFORM\\s+([A-Z0-9\\-]+)"
    );
    private static final Pattern PARAGRAPH_PATTERN = Pattern.compile(
            "^[A-Z][A-Z0-9\\-]*\\.$"
    );
    private static final Pattern COBOL_VAR_PATTERN = Pattern.compile(
            "\\b([A-Z][A-Z0-9\\-]{0,28})\\b"
    );
    private static final Pattern RESERVED_PATTERN = Pattern.compile(
            "^(?i)(MOVE|COMPUTE|IF|PERFORM|DIVIDE|MULTIPLY|ADD|SUBTRACT|DISPLAY|VALUE|PIC|PROCEDURE|DATA|WORKING|FILE|IDENTIFICATION|PROGRAM|DIVISION|SECTION|GOBACK|STOP|EXIT|GO|TO|THRU|UNTIL|WITH|TIMES|AFTER|BEFORE|VARYING|ON|OFF|AREAS|ARE|ASCENDING|DESCENDING|KEY|INDEXED|BY|OF|IS|NOT|GREATER|LESS|EQUAL|THAN|ZERO|SPACES|SPACE|ALPHABETIC|ALPHANUMERIC|NUMERIC|ONLY|OPEN|CLOSE|READ|WRITE|REWRITE|DELETE|INITIALIZE|INSPECT|STRING|UNSTRING|EXAMINE|TALLYING|REPLACING|SEQUENCE|ORDER|SORT|MERGE|USING|GIVING|OUTPUT|INPUT|IO|EXTEND|RETRY|INVALID|NOTINVALID|AT|END|END\\-|EOP|END\\-READ|END\\-WRITE|END\\-PERFORM|END\\-IF|END\\-EVALUATE|EVALUATE|WHEN|OTHER|WHEN\\-OTHER|TRUE|FALSE|CONTINUE|NEXT|SENTENCE|DECLARATIVES|END|DECLARATIVES)$"
    );

    // 内部类
    private enum TaintStatus { SAFE, TAINTED_365, TAINTED_28, TAINTED_UNKNOWN }

    private static class CobolProgram {
        List<CobolParagraph> paragraphs = new ArrayList<>();
        SymbolTable symbolTable = new SymbolTable();
    }

    private static class CobolParagraph {
        String name;
        int startLine;
        int endLine;
        List<CobolStatement> statements = new ArrayList<>();
    }

    private static class CobolStatement {
        int lineNumber;
        String rawContent;
        String type;
        String targetVar;
        List<String> sourceVars = new ArrayList<>();
        String sourceValue;
        boolean hasDangerousKeyword;
        CobolParagraph parent;
    }

    private static class SymbolTable {
        Map<String, TaintStatus> vars = new HashMap<>();

        void declare(String name, TaintStatus status) {
            if (name == null) return;
            vars.put(name.toUpperCase(), status);
        }

        TaintStatus get(String name) {
            if (name == null) return TaintStatus.SAFE;
            return vars.getOrDefault(name.toUpperCase(), TaintStatus.SAFE);
        }

        void setTainted(String name, TaintStatus status) {
            if (name == null) return;
            vars.put(name.toUpperCase(), status);
        }

        void clear(String name) {
            if (name == null) return;
            vars.put(name.toUpperCase(), TaintStatus.SAFE);
        }

        void clearAll() {
            vars.replaceAll((k, v) -> TaintStatus.SAFE);
        }

        Set<String> getAllTainted() {
            Set<String> result = new HashSet<>();
            vars.forEach((k, v) -> { if (v != TaintStatus.SAFE) result.add(k); });
            return result;
        }
    }

    private static class VulnerabilitySlice {
        CobolParagraph paragraph;
        CobolStatement trigger;
        Set<String> taintedVars;
    }

    @Override
    public List<ScanMatch> scan(String filePath, String sourceCode) {
        String lowerPath = filePath.toLowerCase();

        if (!(lowerPath.endsWith(".cbl") || lowerPath.endsWith(".cpy"))) {
            return Collections.emptyList();
        }

        if (sourceCode == null || sourceCode.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String fileName = extractFileName(lowerPath);
        if (FOUNDATION_WHITELIST.contains(fileName.toUpperCase())) {
            System.out.println("[=] 跳过白名单文件: " + filePath);
            return Collections.emptyList();
        }

        CobolProgram program = parseCobol(sourceCode);
        List<ScanMatch> matches = performTaintAnalysis(program);

        return deduplicateMatches(matches);
    }

    private String extractFileName(String path) {
        int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
        return lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
    }

    // ==================== 词法解析 ====================

    private CobolProgram parseCobol(String sourceCode) {
        CobolProgram program = new CobolProgram();
        String[] lines = sourceCode.split("\\r?\\n");

        // 【修复1】创建全局段落，确保无段落头的 .cpy 文件也能被解析
        CobolParagraph globalParagraph = new CobolParagraph();
        globalParagraph.name = "GLOBAL-DATA";
        globalParagraph.startLine = 1;
        program.paragraphs.add(globalParagraph);
        CobolParagraph currentParagraph = globalParagraph;

        StringBuilder currentSentence = new StringBuilder();
        int sentenceStartLine = 1;

        for (int i = 0; i < lines.length; i++) {
            String rawLine = lines[i];
            String line = rawLine.trim();

            if (line.startsWith("*") || line.startsWith("//")) {
                continue;
            }

            if (isParagraphHeader(line)) {
                if (currentParagraph != null) {
                    currentParagraph.endLine = i;
                    flushSentence(currentParagraph, currentSentence.toString(), sentenceStartLine, lines);
                }

                currentParagraph = new CobolParagraph();
                currentParagraph.name = extractParagraphName(line);
                currentParagraph.startLine = i + 1;
                program.paragraphs.add(currentParagraph);
                currentSentence = new StringBuilder();
                sentenceStartLine = i + 2;
                continue;
            }

            if (currentSentence.length() > 0) currentSentence.append(" ");
            currentSentence.append(line);

            if (line.endsWith(".")) {
                if (currentParagraph != null) {
                    flushSentence(currentParagraph, currentSentence.toString(), sentenceStartLine, lines);
                }
                currentSentence = new StringBuilder();
                sentenceStartLine = i + 2;
            }
        }

        if (currentParagraph != null && currentSentence.length() > 0) {
            flushSentence(currentParagraph, currentSentence.toString(), sentenceStartLine, lines);
        }

        initSymbolTable(sourceCode, program.symbolTable);

        System.out.println("[*] 词法解析完成: " + program.paragraphs.size() + " 个段落, " +
                          program.symbolTable.vars.size() + " 个变量");

        return program;
    }

    private boolean isParagraphHeader(String line) {
        if (line.trim().isEmpty() || line.startsWith("*")) return false;
        return PARAGRAPH_PATTERN.matcher(line.trim()).matches() &&
               !RESERVED_PATTERN.matcher(line.replace(".", "").trim()).matches();
    }

    private String extractParagraphName(String line) {
        String t = line.trim();
        return t.endsWith(".") ? t.substring(0, t.length() - 1).trim().toUpperCase() : t.toUpperCase();
    }

    private void flushSentence(CobolParagraph paragraph, String sentence, int startLine, String[] lines) {
        if (sentence == null || sentence.trim().isEmpty()) return;

        String[] parts = sentence.split("(?<=\\.)(?!\\s*\\.)");
        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;
            CobolStatement s = parseStatement(part, startLine);
            if (s != null) {
                s.parent = paragraph;
                paragraph.statements.add(s);
            }
            startLine++;
        }
    }

    private CobolStatement parseStatement(String stmt, int lineNumber) {
        if (stmt == null || stmt.trim().isEmpty()) return null;

        String upper = stmt.toUpperCase();
        CobolStatement s = new CobolStatement();
        s.lineNumber = lineNumber;
        s.rawContent = stmt;

        if (upper.startsWith("MOVE")) {
            s.type = "MOVE";
            Matcher m = MOVE_PATTERN.matcher(upper);
            if (m.find()) {
                s.sourceValue = extractValue(m.group(1));
                String var = normalizeVar(m.group(1));
                if (var != null) s.sourceVars.add(var);
                s.targetVar = normalizeVar(m.group(2));
            }
        } else if (upper.startsWith("COMPUTE")) {
            s.type = "COMPUTE";
            s.hasDangerousKeyword = true;
            Matcher m = COMPUTE_PATTERN.matcher(upper);
            if (m.find()) {
                s.targetVar = normalizeVar(m.group(1));
                extractVars(m.group(2), s.sourceVars);
            }
        } else if (upper.startsWith("MULTIPLY")) {
            s.type = "MULTIPLY";
            s.hasDangerousKeyword = true;
            Matcher m = MULTIPLY_PATTERN.matcher(upper);
            if (m.find()) {
                String var = normalizeVar(m.group(1));
                if (var != null) s.sourceVars.add(var);
                s.targetVar = normalizeVar(m.group(2));
            }
        } else if (upper.startsWith("DIVIDE")) {
            s.type = "DIVIDE";
            s.hasDangerousKeyword = true;
            Matcher m = DIVIDE_PATTERN.matcher(upper);
            if (m.find()) {
                String var = normalizeVar(m.group(1));
                if (var != null) s.sourceVars.add(var);
                s.targetVar = normalizeVar(m.group(2));
            }
        } else if (upper.startsWith("PERFORM")) {
            s.type = "PERFORM";
            Matcher m = PERFORM_PATTERN.matcher(upper);
            if (m.find()) {
                s.sourceValue = m.group(1);
            }
        } else if (upper.startsWith("IF")) {
            s.type = "IF";
        } else if (upper.contains("VALUE")) {
            s.type = "DECLARATION";
            Matcher m = VALUE_PATTERN.matcher(upper);
            if (m.find()) {
                s.targetVar = normalizeVar(m.group(1));
                s.sourceValue = m.group(2);
            }
        }

        return s;
    }

    private void extractVars(String expr, List<String> vars) {
        if (expr == null) return;
        Matcher m = COBOL_VAR_PATTERN.matcher(expr);
        while (m.find()) {
            String v = m.group(1);
            if (v != null && !isReserved(v)) vars.add(v);
        }
    }

    private String extractValue(String expr) {
        if (expr == null) return null;
        expr = expr.trim();
        if (expr.matches("\\d+")) return expr;
        Matcher m = COBOL_VAR_PATTERN.matcher(expr);
        return m.find() ? normalizeVar(m.group(1)) : expr;
    }

    private String normalizeVar(String v) {
        if (v == null) return null;
        return v.trim().toUpperCase();
    }

    private boolean isReserved(String word) {
        return RESERVED_PATTERN.matcher(word.toUpperCase()).matches();
    }

    private void initSymbolTable(String sourceCode, SymbolTable table) {
        Matcher m = VALUE_PATTERN.matcher(sourceCode.toUpperCase());
        while (m.find()) {
            String varName = normalizeVar(m.group(1));
            String value = m.group(2);
            TaintStatus status = ("365".equals(value) || "366".equals(value)) ?
                    TaintStatus.TAINTED_365 : TaintStatus.TAINTED_28;
            table.declare(varName, status);
        }
    }

    // ==================== 污点追踪分析 ====================

    private List<ScanMatch> performTaintAnalysis(CobolProgram program) {
        List<ScanMatch> matches = new ArrayList<>();
        SymbolTable table = program.symbolTable;
        List<VulnerabilitySlice> slices = new ArrayList<>();

        System.out.println("[*] 开始污点追踪分析...");

        for (CobolParagraph paragraph : program.paragraphs) {
            for (CobolStatement stmt : paragraph.statements) {
                analyze(stmt, table, paragraph, slices);
            }
        }

        for (VulnerabilitySlice slice : slices) {
            StringBuilder sb = new StringBuilder();
            for (CobolStatement st : slice.paragraph.statements) {
                sb.append(st.lineNumber).append(": ").append(st.rawContent).append("\n");
            }

            matches.add(new ScanMatch(
                    "LEG-DFI-002",
                    "污染数据流 - 变量 " + slice.taintedVars + " 流入危险计算",
                    sb.toString()
            ));
        }

        System.out.println("[*] 污点追踪完成: 发现 " + matches.size() + " 个漏洞切片");

        return matches;
    }

    private void analyze(CobolStatement stmt, SymbolTable table,
                        CobolParagraph paragraph, List<VulnerabilitySlice> slices) {
        if (stmt.type == null) return;

        // 【修复2】降维打击：只要语句中包含危险常量的独立数字，无视语法类型，直接抓取！
        if (stmt.rawContent.matches(".*\\b(365|366|28|29)\\b.*")) {
            VulnerabilitySlice slice = new VulnerabilitySlice();
            slice.paragraph = paragraph;
            slice.trigger = stmt;
            slice.taintedVars = new HashSet<>(Collections.singleton("HARDCODED_LITERAL"));
            slices.add(slice);
            System.out.println("[!] 漏洞切片(降维打击): " + stmt.rawContent);
            return; // 已经命中，直接返回
        }

        switch (stmt.type) {
            case "MOVE":
                handleMove(stmt, table, paragraph, slices);
                break;
            case "COMPUTE":
            case "MULTIPLY":
            case "DIVIDE":
                handleDangerous(stmt, table, paragraph, slices);
                break;
            case "PERFORM":
                handlePerform(stmt, table);
                break;
            case "DECLARATION":
                handleDecl(stmt, table);
                break;
            case "IF":
                handleIf(stmt, paragraph, slices);
                break;
        }
    }

    private void handleMove(CobolStatement stmt, SymbolTable table, CobolParagraph paragraph, List<VulnerabilitySlice> slices) {
        if (stmt.targetVar == null) return;

        TaintStatus newStatus = TaintStatus.SAFE;

        if (stmt.sourceValue != null && DANGEROUS_CONSTANTS.contains(stmt.sourceValue)) {
            newStatus = ("365".equals(stmt.sourceValue) || "366".equals(stmt.sourceValue)) ?
                    TaintStatus.TAINTED_365 : TaintStatus.TAINTED_28;
            System.out.println("[+] 污染源: MOVE " + stmt.sourceValue + " TO " + stmt.targetVar);

            // 【修复2】拦截"直接赋值"绕过：如果目标变量名包含 DAY/PERIOD/YEAR/DIFF，直接生成切片
            if (stmt.targetVar.contains("DAY") || stmt.targetVar.contains("PERIOD") ||
                stmt.targetVar.contains("YEAR") || stmt.targetVar.contains("DIFF")) {
                Set<String> taintedVars = new HashSet<>();
                taintedVars.add(stmt.sourceValue);
                VulnerabilitySlice slice = new VulnerabilitySlice();
                slice.paragraph = paragraph;
                slice.trigger = stmt;
                slice.taintedVars = taintedVars;
                slices.add(slice);
                System.out.println("[!] 漏洞切片(直接赋值): MOVE " + stmt.sourceValue + " TO " + stmt.targetVar);
            }
        } else if (!stmt.sourceVars.isEmpty() && stmt.sourceVars.get(0) != null) {
            TaintStatus src = table.get(stmt.sourceVars.get(0));
            if (src != TaintStatus.SAFE) {
                newStatus = src;
                System.out.println("[~] 污染传播: " + stmt.sourceVars.get(0) + " -> " + stmt.targetVar);
            }
        }

        table.setTainted(stmt.targetVar, newStatus);
    }

    private void handleDangerous(CobolStatement stmt, SymbolTable table,
                                CobolParagraph paragraph, List<VulnerabilitySlice> slices) {
        Set<String> usedTainted = new HashSet<>();

        // 终极修复：检查语句本身是否直接包含了硬编码的危险常量
        if (stmt.rawContent.contains("365") || stmt.rawContent.contains("28") ||
            stmt.rawContent.contains("'365'") || stmt.rawContent.contains("'28'")) {
            usedTainted.add("HARDCODED_LITERAL");
        }

        // 原逻辑：检查是否使用了被污染的间接变量
        for (String v : stmt.sourceVars) {
            if (v != null && table.get(v) != TaintStatus.SAFE) usedTainted.add(v);
        }

        if (stmt.targetVar != null && table.get(stmt.targetVar) != TaintStatus.SAFE) {
            usedTainted.add(stmt.targetVar);
        }

        // 如果发现危险（硬编码或变量污染），立刻抓取切片
        if (!usedTainted.isEmpty()) {
            VulnerabilitySlice slice = new VulnerabilitySlice();
            slice.paragraph = paragraph;
            slice.trigger = stmt;
            slice.taintedVars = usedTainted;
            slices.add(slice);
            System.out.println("[!] 漏洞切片: " + stmt.type + " 触发危险计算: " + stmt.rawContent);
        }
    }

    private void handlePerform(CobolStatement stmt, SymbolTable table) {
        if (stmt.sourceValue == null) return;

        String v = stmt.sourceValue.toUpperCase();
        if (v.contains("CHECK") || v.contains("LEAP") || v.contains("9000") || v.contains("LY")) {
            System.out.println("[=] 清洗器: PERFORM " + stmt.sourceValue);
            table.clearAll();
        }
    }

    private void handleDecl(CobolStatement stmt, SymbolTable table) {
        if (stmt.targetVar != null && stmt.sourceValue != null) {
            TaintStatus status = ("365".equals(stmt.sourceValue) || "366".equals(stmt.sourceValue)) ?
                    TaintStatus.TAINTED_365 : TaintStatus.TAINTED_28;
            table.setTainted(stmt.targetVar, status);
            System.out.println("[+] 声明污染: " + stmt.targetVar + " VALUE " + stmt.sourceValue);
        }
    }

    // 【修复3】拦截"控制流"绕过：检测 IF 语句中直接使用危险常量控制业务流
    private void handleIf(CobolStatement stmt, CobolParagraph paragraph, List<VulnerabilitySlice> slices) {
        if (stmt.rawContent == null) return;

        String content = stmt.rawContent.toUpperCase();
        // 检查 IF 条件中是否直接包含危险常量
        if (content.contains("28") || content.contains("29") ||
            content.contains("365") || content.contains("366")) {
            Set<String> taintedVars = new HashSet<>();
            taintedVars.add("IF_HARDCODED_CONDITION");
            VulnerabilitySlice slice = new VulnerabilitySlice();
            slice.paragraph = paragraph;
            slice.trigger = stmt;
            slice.taintedVars = taintedVars;
            slices.add(slice);
            System.out.println("[!] 漏洞切片(控制流): IF 语句包含危险常量: " + stmt.rawContent);
        }
    }

    // ==================== 辅助方法 ====================

    private List<ScanMatch> deduplicateMatches(List<ScanMatch> matches) {
        List<ScanMatch> unique = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (ScanMatch m : matches) {
            if (!seen.contains(m.codeSlice)) {
                seen.add(m.codeSlice);
                unique.add(m);
            }
        }

        return unique;
    }
}
