package com.agenticsast.model;

/**
 * 审计结果数据模型
 */
public class AuditResult {
    private String filePath;
    private String codeSlice;
    private String status;

    // 新增模型结构化字段
    private String vulnerabilityType;
    private String attackScenario;
    private String confidenceLevel;
    private String fixedCode;

    public AuditResult() {
    }

    public AuditResult(String filePath, String codeSlice, String status, 
                       String vulnerabilityType, String attackScenario, 
                       String confidenceLevel, String fixedCode) {
        this.filePath = filePath;
        this.codeSlice = codeSlice;
        this.status = status;
        this.vulnerabilityType = vulnerabilityType;
        this.attackScenario = attackScenario;
        this.confidenceLevel = confidenceLevel;
        this.fixedCode = fixedCode;
    }

    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }

    public String getCodeSlice() { return codeSlice; }
    public void setCodeSlice(String codeSlice) { this.codeSlice = codeSlice; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getVulnerabilityType() { return vulnerabilityType; }
    public void setVulnerabilityType(String vulnerabilityType) { this.vulnerabilityType = vulnerabilityType; }

    public String getAttackScenario() { return attackScenario; }
    public void setAttackScenario(String attackScenario) { this.attackScenario = attackScenario; }

    public String getConfidenceLevel() { return confidenceLevel; }
    public void setConfidenceLevel(String confidenceLevel) { this.confidenceLevel = confidenceLevel; }

    public String getFixedCode() { return fixedCode; }
    public void setFixedCode(String fixedCode) { this.fixedCode = fixedCode; }
}