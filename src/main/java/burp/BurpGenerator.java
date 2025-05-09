package burp;

import burp.ui.TemplatePanel;

import java.awt.Component;
import java.io.PrintWriter;
import javax.swing.*;

/**
 * BurpGenerator - Burp Suite extension for generating Nuclei templates
 * 此类作为Burp Suite扩展的入口点，将模板生成功能委托给专门的类。
 */
public class BurpGenerator implements IBurpExtender, ITab, IHttpListener {
    private JTabbedPane tabs;
    public PrintWriter stdout;
    private static final String EXTENSION_NAME = "Nu_Te_Gen V1.5";
    private static final String TAB_CAPTION = "Nu_Te_Gen";

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // 初始化标准输出
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello Nu_Te_Gen!");
        this.stdout.println("version:1.5");

        // 设置扩展名称
        callbacks.setExtensionName(EXTENSION_NAME);

        // 在 EDT 中初始化UI
        SwingUtilities.invokeLater(() -> {
            // 创建主要UI组件
            TemplatePanel templatePanel = new TemplatePanel();
            
            // 创建选项卡容器
            tabs = new JTabbedPane();
            tabs.addTab(TAB_CAPTION, templatePanel);
            
            // 将UI组件添加到Burp
            callbacks.customizeUiComponent(tabs);
            callbacks.addSuiteTab(BurpGenerator.this);
            
            // 注册HTTP监听器
            callbacks.registerHttpListener(BurpGenerator.this);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 当前实现中不需要处理HTTP消息
        // 此方法可用于将来扩展，例如从实际请求中生成模板
    }

    @Override
    public String getTabCaption() {
        return TAB_CAPTION;
    }

    @Override
    public Component getUiComponent() {
        return tabs;
    }
}
