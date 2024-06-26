package burp;

import burp.utils.Config;

import java.awt.Component;
import java.io.PrintWriter;
import javax.swing.*;
import java.awt.*;
import java.util.*;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {
    private JTabbedPane tabs;
    public PrintWriter stdout;
    private Map<String, Boolean> matchFlags;
    private boolean extractors;
    private Map<String, JComponent> components;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello Nu_Te_Gen!");
        this.stdout.println("version:1.4");

        callbacks.getHelpers();
        callbacks.setExtensionName("Nu_Te_Gen V1.4");

        initializeMatchFlags();

        SwingUtilities.invokeLater(() -> createUI(callbacks));
    }

    private void initializeMatchFlags() {
        matchFlags = new HashMap<>();
        matchFlags.put("word", false);
        matchFlags.put("header", false);
        matchFlags.put("status", false);
        matchFlags.put("negative", false);
        matchFlags.put("time", false);
        matchFlags.put("size", false);
        matchFlags.put("interactsh_protocol", false);
        matchFlags.put("interactsh_request", false);
        matchFlags.put("regex", false);
        matchFlags.put("binary", false);
    }

    private void createUI(IBurpExtenderCallbacks callbacks) {
        JPanel mainPanel = createMainPanel();
        JPanel matchersPanel = createMatchersPanel();
        JPanel outputPanel = createOutputPanel();
        JPanel helpPanel = createHelpPanel();

        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, mainPanel, matchersPanel);
        leftSplitPane.setDividerLocation(450);

        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, outputPanel, helpPanel);
        rightSplitPane.setDividerLocation(430);

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplitPane, rightSplitPane);
        mainSplitPane.setDividerLocation(380);

        tabs = new JTabbedPane();
        tabs.addTab("Template生成", mainSplitPane);

        callbacks.customizeUiComponent(tabs);
        callbacks.addSuiteTab(BurpExtender.this);
        callbacks.registerHttpListener(BurpExtender.this);
    }

    private JPanel createMainPanel() {
        JPanel panel = new JPanel(new GridLayout(13, 1));

        JButton generateButton = new JButton("生成");
        JButton clearButton = new JButton("清空");

        String[] labels = {"模版id：", "模版名称：", "作者名称：", "严重程度：", "描述：", "Tags：",
                "请求方式：", "请求路径：", "Content-Type：", "body：", "是否跟随跳转：", "跳转次数："};
        String[] defaultValues = {"test", "test", "ffffffff0x", "", "由插件自动生成", "auto", "", "", "", "", "", "0"};

        components = new HashMap<>();

        for (int i = 0; i < labels.length; i++) {
            JLabel label = createLabel(labels[i]);
            JComponent component;

            if (i == 3) {
                component = createComboBox(GetSeverityModes(), 0);
            } else if (i == 6) {
                component = createComboBox(GetReqModes(), 0);
            } else if (i == 8) {
                component = createComboBox(GetHeadersModes(), 0);
            } else if (i == 9) {
                component = createComboBox(GetBodyModes(), 0);
            } else if (i == 10) {
                component = createComboBox(GetRedirectsModes(), 1);
            } else {
                component = createTextField(defaultValues[i]);
            }

            panel.add(label);
            panel.add(component);
            components.put(labels[i], component);
        }

        panel.add(generateButton);
        panel.add(clearButton);

        generateButton.addActionListener(e -> generateTemplate());
        clearButton.addActionListener(e -> clearOutput());

        return panel;
    }

    private void generateTemplate() {
        String id = getComponentValue("模版id：");
        String name = getComponentValue("模版名称：");
        String author = getComponentValue("作者名称：");
        String severity = getComponentValue("严重程度：");
        String description = getComponentValue("描述：");
        String tags = getComponentValue("Tags：");
        String req = getComponentValue("请求方式：");
        String path = getComponentValue("请求路径：");
        String header = getComponentValue("Content-Type：");
        String body = getComponentValue("body：");
        String isRedirect = getComponentValue("是否跟随跳转：");
        String redirectNum = getComponentValue("跳转次数：");

        String yaml = generateYaml(id, name, author, description, tags, isRedirect, redirectNum, req, path, header, body, severity);
        setOutputText(yaml);
    }

    private String getComponentValue(String key) {
        JComponent component = components.get(key);
        if (component instanceof JTextField) {
            return ((JTextField) component).getText();
        } else if (component instanceof JComboBox) {
            return (String) ((JComboBox<?>) component).getSelectedItem();
        }
        return "";
    }

    private void clearOutput() {
        setOutputText("");
    }

    private void setOutputText(String text) {
        JTextArea outputArea = (JTextArea) ((JScrollPane) components.get("outputArea")).getViewport().getView();
        outputArea.setText(text);
    }

    private JPanel createMatchersPanel() {
        JPanel panel = new JPanel(new GridLayout(14, 2));

        String[] matcherLabels = {"word", "header", "status", "extractors", "negative", "time", "size",
                "interactsh_protocol", "interactsh_request", "regex", "binary"};

        for (String label : matcherLabels) {
            JLabel matchLabel = new JLabel("matchers模版 ", SwingConstants.RIGHT);
            JCheckBox checkBox = new JCheckBox(" (" + label + ")");

            checkBox.addActionListener(e -> {
                if ("extractors".equals(label)) {
                    extractors = checkBox.isSelected();
                } else {
                    matchFlags.put(label, checkBox.isSelected());
                }
            });

            panel.add(matchLabel);
            panel.add(checkBox);
        }

        return panel;
    }

    private JPanel createOutputPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 1));
        JTextArea outputArea = new JTextArea();
        outputArea.setRows(30);
        outputArea.setColumns(30);
        outputArea.setLineWrap(true);
        outputArea.setEditable(true);
        JScrollPane scrollPane = new JScrollPane(outputArea);
        panel.add(scrollPane);
        components.put("outputArea", scrollPane);
        return panel;
    }

    private JPanel createHelpPanel() {
        JPanel panel = new JPanel(new GridLayout(1, 2));
        panel.add(createHelpScrollPane("/help1.txt"));
        panel.add(createHelpScrollPane("/help2.txt"));
        return panel;
    }

    private JScrollPane createHelpScrollPane(String filePath) {
        String helpData = HelpDataLoader.loadHelpData(filePath);
        JTextArea textArea = new JTextArea(helpData);
        textArea.setRows(30);
        textArea.setColumns(30);
        textArea.setLineWrap(true);
        textArea.setEditable(true);
        return new JScrollPane(textArea);
    }

    private JLabel createLabel(String text) {
        return new JLabel(text, SwingConstants.RIGHT);
    }

    private JTextField createTextField(String defaultValue) {
        JTextField textField = new JTextField();
        textField.setText(defaultValue);
        return textField;
    }

    private JComboBox<String> createComboBox(String[] items, int selectedIndex) {
        JComboBox<String> comboBox = new JComboBox<>(items);
        comboBox.setSelectedIndex(selectedIndex);
        return comboBox;
    }

    private String[] enumToStringArray(Enum<?>[] enumValues) {
        return Arrays.stream(enumValues)
                .map(e -> e.name().replace('_', '/'))
                .toArray(String[]::new);
    }

    private String[] GetReqModes() {
        return enumToStringArray(Config.reqMode.values());
    }

    private String[] GetSeverityModes() {
        return enumToStringArray(Config.severityMode.values());
    }

    private String[] GetBodyModes() {
        return enumToStringArray(Config.ContentBodyMode.values());
    }

    private String[] GetHeadersModes() {
        return enumToStringArray(Config.ContentTypeMode.values());
    }

    private String[] GetRedirectsModes() {
        return enumToStringArray(Config.RedirectsMode.values());
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Implementation not provided in the original code
    }

    @Override
    public String getTabCaption() {
        return "Nu_Te_Gen";
    }

    @Override
    public Component getUiComponent() {
        return tabs;
    }

    private String generateYaml(String TP_Id, String TP_Name, String TP_Author, String TP_Description, String TP_Tags,
                                String TP_IsRedirect, String TP_Redirect_Num, String TP_Req, String TP_Path, String TP_Header,
                                String TP_Body, String Tp_Severity) {
        StringBuilder data = new StringBuilder();

        // Metadata section
        data.append(String.format("""
            id: %s
            
            info:
              name: %s
              author: %s
              severity: %s
              description: |
                %s
              metadata:
                fofa-query:
                shodan-query:
                hunter-query:
              reference:
                - https://
              tags: %s
            """, TP_Id, TP_Name, TP_Author, Tp_Severity, TP_Description, TP_Tags));

        // HTTP request section
        appendHttpSection(data, TP_Req, TP_Path, TP_Header, TP_Body);

        // Redirects section
        if ("istrue".equals(TP_IsRedirect)) {
            data.append(String.format("""
                host-redirects: true
                max-redirects: %s
            """, TP_Redirect_Num));
        }

        // Matchers section
        appendMatchersSection(data);

        return data.toString();
    }

    private void appendHttpSection(StringBuilder data, String TP_Req, String TP_Path, String TP_Header, String TP_Body) {
        if ("RAW".equals(TP_Req)) {
            data.append(String.format("""
                http:
                  - raw:
                      - |
                        POST %s HTTP/1.1
                        Host: {{Hostname}}
                        Content-Type: %s
                        
                        %s
            """, TP_Path, TP_Header, "带".equals(TP_Body) ? "Body" : ""));
        } else {
            data.append(String.format("""
                http:
                  - method: %s
                    path:
                      - "{{BaseURL}}%s"
            """, TP_Req, TP_Path));

            data.append(String.format("""
                headers:
                  Content-Type: %s
            """, TP_Header));

            if (!"不带".equals(TP_Body)) {
                data.append("""
                    body: |
                      替换此处注意每行缩进
            """);
            }
        }
    }

    private void appendMatchersSection(StringBuilder data) {
        boolean hasMatchers = matchFlags.values().stream().anyMatch(Boolean::booleanValue);
        if (hasMatchers) {
            data.append("""
                matchers-condition: and
                matchers:
            """);

            appendMatcherIfEnabled(data, "word", """
                  - type: word
                    part: body
                    words:
                      - 'test1'
                      - 'test2'
                    condition: or
            """);

            appendMatcherIfEnabled(data, "header", """
                  - type: word
                    part: header
                    words:
                      - 'tomcat'
            """);

            appendMatcherIfEnabled(data, "status", """
                  - type: status
                    status:
                      - 200
            """);

            appendMatcherIfEnabled(data, "negative", """
                  - type: word
                    words:
                      - "荣耀立方"
                      - 'var model = "LW-N605R"'
                    part: body
                    negative: true
                    condition: or
            """);

            appendMatcherIfEnabled(data, "time", """
                  - type: dsl
                    dsl:
                      - 'duration>=6'
            """);

            appendMatcherIfEnabled(data, "size", """
                  - type: dsl
                    dsl:
                      - 'len(body)<130'
            """);

            appendMatcherIfEnabled(data, "interactsh_protocol", """
                  - type: word
                    part: interactsh_protocol  # 配合 {{interactsh-url}} 关键词使用
                    words:
                      - "http"
            """);

            appendMatcherIfEnabled(data, "interactsh_request", """
                  - type: regex
                    part: interactsh_request   # 配合 {{interactsh-url}} 关键词使用
                    regex:
                      - "root:.*:0:0:"
            """);

            appendMatcherIfEnabled(data, "regex", """
                  - type: regex
                    regex:
                      - "root:.*:0:0:"
                    part: body
            """);

            appendMatcherIfEnabled(data, "binary", """
                  - type: binary
                    binary:
                      - "D0CF11E0"  # db
                      - "53514C69746520"  # SQLite
                    part: body
                    condition: or
            """);
        }

        if (extractors) {
            data.append("""
                extractors:
                  - part: header
                    internal: true
                    group: 1
                    type: regex
                    regex:
                      - 'Set-Cookie: PHPSESSID=(.*); path=/'
            """);
        }
    }

    private void appendMatcherIfEnabled(StringBuilder data, String matcherType, String matcherContent) {
        if (Boolean.TRUE.equals(matchFlags.get(matcherType))) {
            data.append(matcherContent);
        }
    }
}