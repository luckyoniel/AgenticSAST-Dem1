package com.agenticsast.scanner;

import com.agenticsast.model.ScanMatch;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Component
public class JavaAstScanner implements CodeScanner {

    @Override
    public List<ScanMatch> scan(String filePath, String sourceCode) {
        List<ScanMatch> matches = new ArrayList<>();
        if (!filePath.toLowerCase().endsWith(".java") || sourceCode == null || sourceCode.trim().isEmpty()) {
            return matches;
        }

        try {
            CompilationUnit cu = StaticJavaParser.parse(sourceCode);
            cu.accept(new VoidVisitorAdapter<Void>() {
                @Override
                public void visit(BinaryExpr n, Void arg) {
                    super.visit(n, arg);
                    if (n.getOperator() == BinaryExpr.Operator.PLUS) {
                        String exprStr = n.toString().toUpperCase();
                        if (exprStr.contains("SELECT") || exprStr.contains("UPDATE") || 
                            exprStr.contains("INSERT") || exprStr.contains("DELETE")) {
                            extractMethodContext(sourceCode, n, "OWA-009", "SQL 注入 (硬编码字符串拼接)", matches);
                        }
                    }
                }

                @Override
                public void visit(MethodCallExpr n, Void arg) {
                    super.visit(n, arg);
                    String methodName = n.getNameAsString();
                    
                    if ("append".equals(methodName)) {
                        String callStr = n.toString().toUpperCase();
                        if (callStr.contains("SELECT") || callStr.contains("UPDATE") || 
                            callStr.contains("INSERT") || callStr.contains("DELETE")) {
                            extractMethodContext(sourceCode, n, "OWA-009", "SQL 注入 (StringBuilder 拼接)", matches);
                        }
                    } else if ("executeQuery".equals(methodName) || "executeUpdate".equals(methodName)) {
                        extractMethodContext(sourceCode, n, "OWA-009", "SQL 注入 (危险方法调用)", matches);
                    } else if ("exec".equals(methodName)) {
                        extractMethodContext(sourceCode, n, "OWA-003", "命令注入", matches);
                    }
                }
            }, null);
        } catch (Exception e) {
            System.err.println("AST 解析失败: " + e.getMessage());
        }

        return deduplicateMatches(matches);
    }

    private void extractMethodContext(String sourceCode, com.github.javaparser.ast.Node node, String ruleId, String desc, List<ScanMatch> matches) {
        Optional<MethodDeclaration> methodOpt = node.findAncestor(MethodDeclaration.class);
        if (methodOpt.isPresent()) {
            MethodDeclaration method = methodOpt.get();
            if (method.getBegin().isPresent() && method.getEnd().isPresent()) {
                int startLine = method.getBegin().get().line;
                int endLine = method.getEnd().get().line;
                matches.add(new ScanMatch(ruleId, desc, extractLines(sourceCode, startLine, endLine)));
                return;
            }
        }
        
        if (node.getBegin().isPresent()) {
            int line = node.getBegin().get().line;
            matches.add(new ScanMatch(ruleId, desc, extractLines(sourceCode, line - 5, line + 5)));
        }
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
