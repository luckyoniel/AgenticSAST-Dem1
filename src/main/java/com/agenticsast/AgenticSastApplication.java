package com.agenticsast;

import com.agenticsast.model.AuditResult;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import java.awt.Desktop;
import java.net.URI;
import java.util.List;

/**
 * Spring Boot 启动类
 */
@SpringBootApplication
public class AgenticSastApplication implements CommandLineRunner {

    @Autowired
    private AgenticAuditor agenticAuditor;

    public static void main(String[] args) {
        boolean isCli = false;
        for (String arg : args) {
            if (arg.startsWith("--cli-scan")) {
                isCli = true;
                break;
            }
        }

        if (isCli) {
            System.setProperty("java.awt.headless", "true");
            System.setProperty("spring.main.web-application-type", "none");
        } else {
            System.setProperty("java.awt.headless", "false");
        }

        SpringApplication.run(AgenticSastApplication.class, args);
        
        if (!isCli) {
            System.out.println("=================================================");
            System.out.println("🚀 Agentic SAST Web 服务已启动！");
            System.out.println("👉 访问 http://localhost:8081 体验可视化审计功能");
            System.out.println("=================================================");
        }
    }

    @Override
    public void run(String... args) throws Exception {
        String cliPath = null;
        for (int i = 0; i < args.length; i++) {
            if (args[i].startsWith("--cli-scan=")) {
                cliPath = args[i].substring("--cli-scan=".length());
            } else if ("--cli-scan".equals(args[i]) && i + 1 < args.length) {
                cliPath = args[i + 1];
            }
        }

        if (cliPath != null) {
            System.out.println("=================================================");
            System.out.println("🚀 启动 GRC 无头命令行扫描模式");
            System.out.println("📂 目标路径: " + cliPath);
            System.out.println("=================================================");

            List<AuditResult> results = agenticAuditor.scanDirectory(cliPath);
            
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            System.out.println("\n【扫描报告 JSON】");
            System.out.println(gson.toJson(results));

            boolean hasBlock = results.stream().anyMatch(r -> "BLOCK".equals(r.getStatus()));
            if (hasBlock) {
                System.err.println("\n❌ 发现 BLOCK 级别的高危漏洞！CI/CD 流水线将拦截。");
                System.exit(1);
            } else {
                System.out.println("\n✅ 扫描通过，未发现 BLOCK 级别漏洞。");
                System.exit(0);
            }
        }
    }

    /**
     * 监听 Spring Boot 启动完成事件，自动在系统默认浏览器中打开首页
     */
    @EventListener({ApplicationReadyEvent.class})
    public void openBrowserAfterStartup() {
        boolean isCli = Boolean.getBoolean("java.awt.headless");
        if (isCli) {
            return; // CLI 模式下不打开浏览器
        }

        String url = "http://localhost:8081";
        try {
            System.out.println("[*] 正在尝试自动打开浏览器...");
            
            // 1. 优先尝试使用 java.awt.Desktop
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(new URI(url));
                return;
            }
            
            // 2. 如果 Desktop 不支持，则根据操作系统执行相应的命令行（Fallback）
            String osName = System.getProperty("os.name").toLowerCase();
            Runtime runtime = Runtime.getRuntime();
            
            if (osName.contains("win")) {
                // Windows
                runtime.exec("rundll32 url.dll,FileProtocolHandler " + url);
            } else if (osName.contains("mac")) {
                // macOS
                runtime.exec("open " + url);
            } else if (osName.contains("nix") || osName.contains("nux")) {
                // Linux / Unix
                runtime.exec("xdg-open " + url);
            } else {
                System.out.println("[!] 未知操作系统，无法自动打开浏览器，请手动访问：" + url);
            }
            
        } catch (Exception e) {
            // 3. 捕获异常，防止应用崩溃
            System.out.println("[!] 自动打开浏览器失败，请手动访问: " + url);
            System.out.println("    异常信息: " + e.getMessage());
        }
    }
}
