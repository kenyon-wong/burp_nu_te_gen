package burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.UserInterface;
import burp.generator.YamlGenerator;
import burp.model.MatcherConfig;
import burp.model.TemplateConfig;

import javax.swing.*;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.util.EnumMap;
import java.util.Map;

/**
 * 模板生成器 UI 组件
 * 使用 Montoya API 的组件工厂
 */
public class TemplateGeneratorUI {

    private final MontoyaApi mApi;
    private final JPanel mMainPanel;

    // 表单组件
    private final Map<FormField, JTextField> mTextFields = new EnumMap<>(FormField.class);
    private final Map<FormField, JComboBox<String>> mComboBoxes = new EnumMap<>(FormField.class);
    private final Map<MatcherType, JCheckBox> mMatcherCheckBoxes = new EnumMap<>(MatcherType.class);
    private final JTextArea mOutputArea;

    public TemplateGeneratorUI(MontoyaApi api) {
        this.mApi = api;
        this.mMainPanel = new JPanel();
        this.mOutputArea = new JTextArea();

        initializeUI();
    }

    private void initializeUI() {
        mMainPanel.setLayout(new BorderLayout());

        // 创建三个主要区域
        JPanel inputPanel = createInputPanel();
        JPanel matcherPanel = createMatcherPanel();
        JPanel outputPanel = createOutputPanel();
        JPanel helpPanel = createHelpPanel();

        // 使用分割面板布局 - 自适应比例
        JSplitPane leftSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplit.setTopComponent(inputPanel);
        leftSplit.setBottomComponent(matcherPanel);
        leftSplit.setResizeWeight(0.6);

        JSplitPane rightSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        rightSplit.setLeftComponent(outputPanel);
        rightSplit.setRightComponent(helpPanel);
        rightSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setLeftComponent(leftSplit);
        mainSplit.setRightComponent(rightSplit);
        mainSplit.setResizeWeight(0.35);

        mMainPanel.add(mainSplit, BorderLayout.CENTER);
    }

    /**
     * 创建输入表单面板
     */
    private JPanel createInputPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(13, 2, 5, 5));

        // 添加按钮
        JButton generateBtn = new JButton("生成");
        JButton clearBtn = new JButton("清空");

        generateBtn.addActionListener(e -> generateTemplate());
        clearBtn.addActionListener(e -> mOutputArea.setText(""));

        panel.add(generateBtn);
        panel.add(clearBtn);

        // 添加文本字段
        addTextField(panel, FormField.ID, "test");
        addTextField(panel, FormField.NAME, "test");
        addTextField(panel, FormField.AUTHOR, "ffffffff0x");
        addTextField(panel, FormField.DESCRIPTION, "由插件自动生成");
        addTextField(panel, FormField.TAGS, "auto");

        // 添加下拉框
        addComboBox(panel, FormField.SEVERITY, TemplateConfig.Severity.values());
        addComboBox(panel, FormField.METHOD, TemplateConfig.RequestMethod.values());

        addTextField(panel, FormField.PATH, "");

        addComboBox(panel, FormField.CONTENT_TYPE, TemplateConfig.ContentType.values());

        // 添加重定向选项
        addComboBox(panel, FormField.REDIRECTS, new String[]{"false", "true"});
        addTextField(panel, FormField.MAX_REDIRECTS, "0");

        return panel;
    }

    /**
     * 创建匹配器选择面板
     */
    private JPanel createMatcherPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(12, 2, 5, 5));

        for (MatcherType type : MatcherType.values()) {
            JLabel label = new JLabel("matchers模版 ", SwingConstants.RIGHT);
            JCheckBox checkBox = new JCheckBox(" (" + type.getDisplayName() + ")");
            mMatcherCheckBoxes.put(type, checkBox);

            panel.add(label);
            panel.add(checkBox);
        }

        return panel;
    }

    /**
     * 创建输出区域
     */
    private JPanel createOutputPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());

        mOutputArea.setRows(30);
        mOutputArea.setColumns(30);
        mOutputArea.setLineWrap(true);
        mOutputArea.setEditable(true);

        JScrollPane scrollPane = new JScrollPane(mOutputArea);
        panel.add(scrollPane, BorderLayout.CENTER);

        return panel;
    }

    /**
     * 创建帮助面板
     */
    private JPanel createHelpPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(1, 2));

        JScrollPane help1 = createHelpSection("/help1.txt");
        JScrollPane help2 = createHelpSection("/help2.txt");

        panel.add(help1);
        panel.add(help2);

        return panel;
    }

    private JScrollPane createHelpSection(String resourcePath) {
        JTextArea textArea = new JTextArea();
        textArea.setText(loadHelpResource(resourcePath));
        textArea.setRows(30);
        textArea.setColumns(30);
        textArea.setLineWrap(true);
        textArea.setEditable(true);

        return new JScrollPane(textArea);
    }

    private String loadHelpResource(String path) {
        try (var is = getClass().getResourceAsStream(path)) {
            if (is == null) {
                return "帮助文件未找到: " + path;
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "加载失败: " + e.getMessage();
        }
    }

    /**
     * 添加文本字段
     */
    private void addTextField(JPanel panel, FormField field, String defaultValue) {
        JLabel label = new JLabel(field.getLabel(), SwingConstants.RIGHT);
        JTextField textField = new JTextField(defaultValue);
        mTextFields.put(field, textField);

        panel.add(label);
        panel.add(textField);
    }

    /**
     * 添加下拉框
     */
    private <E extends Enum<E>> void addComboBox(JPanel panel, FormField field, E[] values) {
        JLabel label = new JLabel(field.getLabel(), SwingConstants.RIGHT);

        String[] items = new String[values.length];
        for (int i = 0; i < values.length; i++) {
            items[i] = values[i].name();
        }

        JComboBox<String> comboBox = new JComboBox<>(items);
        mComboBoxes.put(field, comboBox);

        panel.add(label);
        panel.add(comboBox);
    }

    private void addComboBox(JPanel panel, FormField field, String[] values) {
        JLabel label = new JLabel(field.getLabel(), SwingConstants.RIGHT);
        JComboBox<String> comboBox = new JComboBox<>(values);
        mComboBoxes.put(field, comboBox);

        panel.add(label);
        panel.add(comboBox);
    }

    /**
     * 生成模板
     */
    private void generateTemplate() {
        try {
            TemplateConfig config = buildConfigFromForm();
            String yaml = YamlGenerator.generate(config);
            mOutputArea.setText(yaml);
        } catch (Exception e) {
            mApi.logging().logToError("生成模板失败: " + e.getMessage());
            mOutputArea.setText("生成失败: " + e.getMessage());
        }
    }

    /**
     * 从表单构建配置对象
     */
    private TemplateConfig buildConfigFromForm() {
        String id = mTextFields.get(FormField.ID).getText();
        String name = mTextFields.get(FormField.NAME).getText();
        String author = mTextFields.get(FormField.AUTHOR).getText();
        String description = mTextFields.get(FormField.DESCRIPTION).getText();
        String tags = mTextFields.get(FormField.TAGS).getText();
        String path = mTextFields.get(FormField.PATH).getText();

        TemplateConfig.Severity severity = TemplateConfig.Severity.valueOf(
            (String) mComboBoxes.get(FormField.SEVERITY).getSelectedItem()
        );

        TemplateConfig.RequestMethod method = TemplateConfig.RequestMethod.valueOf(
            (String) mComboBoxes.get(FormField.METHOD).getSelectedItem()
        );

        TemplateConfig.ContentType contentType = TemplateConfig.ContentType.valueOf(
            (String) mComboBoxes.get(FormField.CONTENT_TYPE).getSelectedItem()
        );

        boolean followRedirects = "true".equals(mComboBoxes.get(FormField.REDIRECTS).getSelectedItem());
        int maxRedirects = Integer.parseInt(mTextFields.get(FormField.MAX_REDIRECTS).getText());

        MatcherConfig matchers = new MatcherConfig(
            mMatcherCheckBoxes.get(MatcherType.WORD).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.HEADER).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.STATUS).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.NEGATIVE).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.TIME).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.SIZE).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.INTERACTSH_PROTOCOL).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.INTERACTSH_REQUEST).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.REGEX).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.BINARY).isSelected(),
            mMatcherCheckBoxes.get(MatcherType.EXTRACTORS).isSelected()
        );

        return new TemplateConfig(
            id, name, author, severity, description, tags,
            method, path, contentType, "", followRedirects, maxRedirects, matchers
        );
    }

    public Component getComponent() {
        return mMainPanel;
    }

    /**
     * 表单字段枚举
     */
    private enum FormField {
        ID("模版id:"),
        NAME("模版名称:"),
        AUTHOR("作者名称:"),
        SEVERITY("严重程度:"),
        DESCRIPTION("描述:"),
        TAGS("Tags:"),
        METHOD("请求方式:"),
        PATH("请求路径:"),
        CONTENT_TYPE("Content-Type:"),
        REDIRECTS("是否跟随跳转:"),
        MAX_REDIRECTS("跳转次数:");

        private final String mLabel;

        FormField(String label) {
            this.mLabel = label;
        }

        public String getLabel() {
            return mLabel;
        }
    }

    /**
     * 匹配器类型枚举
     */
    private enum MatcherType {
        WORD("word"),
        HEADER("header"),
        STATUS("status"),
        EXTRACTORS("extractors"),
        NEGATIVE("negative"),
        TIME("time"),
        SIZE("size"),
        INTERACTSH_PROTOCOL("interactsh_protocol"),
        INTERACTSH_REQUEST("interactsh_request"),
        REGEX("regex"),
        BINARY("binary");

        private final String mDisplayName;

        MatcherType(String displayName) {
            this.mDisplayName = displayName;
        }

        public String getDisplayName() {
            return mDisplayName;
        }
    }
}
