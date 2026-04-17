package com.agenticsast.model;

public class ScanMatch {
    public String ruleId;
    public String ruleDescription;
    public String codeSlice;

    public ScanMatch(String ruleId, String ruleDescription, String codeSlice) {
        this.ruleId = ruleId;
        this.ruleDescription = ruleDescription;
        this.codeSlice = codeSlice;
    }
}
