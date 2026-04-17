package com.agenticsast.scanner;

import com.agenticsast.model.ScanMatch;
import java.util.List;

public interface CodeScanner {
    List<ScanMatch> scan(String filePath, String content);
}
