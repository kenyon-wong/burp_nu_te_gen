package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.ui.TemplateGeneratorUI;

/**
 * Burp Suite 扩展入口点 - 使用 Montoya API
 * 这是扩展的唯一入口,Burp Suite 会自动发现并加载此类
 */
public class NuTeGenExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "Nu_Te_Gen";
    private static final String VERSION = "2.0.0";

    @Override
    public void initialize(MontoyaApi api) {
        // 设置扩展名称
        api.extension().setName(EXTENSION_NAME + " v" + VERSION);

        // 输出启动信息
        api.logging().logToOutput("Hello " + EXTENSION_NAME + "!");
        api.logging().logToOutput("Version: " + VERSION);
        api.logging().logToOutput("Using Montoya API");

        // 创建 UI 组件
        TemplateGeneratorUI ui = new TemplateGeneratorUI(api);

        // 注册 UI 标签页
        api.userInterface().registerSuiteTab(EXTENSION_NAME, ui.getComponent());

        api.logging().logToOutput(EXTENSION_NAME + " initialized successfully");
    }
}
