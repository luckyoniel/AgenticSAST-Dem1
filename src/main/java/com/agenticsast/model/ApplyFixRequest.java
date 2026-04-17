package com.agenticsast.model;

/**
 * 接收前端传来的修复请求
 */
public class ApplyFixRequest {
    private String filePath;
    private String oldCode;
    private String newCode;

    public ApplyFixRequest() {
    }

    public ApplyFixRequest(String filePath, String oldCode, String newCode) {
        this.filePath = filePath;
        this.oldCode = oldCode;
        this.newCode = newCode;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getOldCode() {
        return oldCode;
    }

    public void setOldCode(String oldCode) {
        this.oldCode = oldCode;
    }

    public String getNewCode() {
        return newCode;
    }

    public void setNewCode(String newCode) {
        this.newCode = newCode;
    }
}
