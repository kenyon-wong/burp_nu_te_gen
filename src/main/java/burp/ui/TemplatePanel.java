package burp.ui;

import burp.model.TemplateConfig;
import burp.generator.YamlGenerator;
import burp.utils.ConfigUtils;
import burp.HelpDataLoader;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;

/**
 * Template Panel UI Component
 * Responsible for creating and managing the UI components for template generation
 */
public class TemplatePanel extends JPanel {
    
    private final TemplateConfig config;
    private final YamlGenerator yamlGenerator;
    
    // UI Components
    private JTextField tfId;
    private JTextField tfName;
    private JTextField tfAuthor;
    private JTextField tfDescription;
    private JTextField tfTags;
    private JComboBox<String> cbSeverity;
    private JComboBox<String> cbRequestType;
    private JTextField tfPath;
    private JComboBox<String> cbContentType;
    private JComboBox<String> cbBody;
    private JComboBox<String> cbRedirects;
    private JTextField tfRedirectsNum;
    
    // Matcher checkboxes
    private JCheckBox cbMatchWord;
    private JCheckBox cbMatchHeader;
    private JCheckBox cbMatchStatus;
    private JCheckBox cbMatchNegative;
    private JCheckBox cbMatchTime;
    private JCheckBox cbMatchSize;
    private JCheckBox cbMatchInteractshProtocol;
    private JCheckBox cbMatchInteractshRequest;
    private JCheckBox cbMatchRegex;
    private JCheckBox cbMatchBinary;
    private JCheckBox cbExtractors;
    
    // Results area
    private JTextArea taResults;
    
    /**
     * Constructor
     */
    public TemplatePanel() {
        this.config = new TemplateConfig();
        this.yamlGenerator = new YamlGenerator();
        
        setLayout(new BorderLayout());
        
        // Create the main panel with tabs
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("模板配置", createConfigPanel());
        tabs.addTab("生成结果", createResultsPanel());
        tabs.addTab("帮助", createHelpPanel("/help1.txt"));
        tabs.addTab("示例", createHelpPanel("/help2.txt"));
        
        add(tabs, BorderLayout.CENTER);
    }
    
    /**
     * Create the main configuration panel
     */
    private JPanel createConfigPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Left panel for inputs
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new GridLayout(13, 1));
        
        // Create and add form fields
        tfId = createTextField(config.getId());
        tfName = createTextField(config.getName());
        tfAuthor = createTextField(config.getAuthor());
        tfDescription = createTextField(config.getDescription());
        tfTags = createTextField(config.getTags());
        cbSeverity = createComboBox(getSeverityModes(), 0);
        cbRequestType = createComboBox(getReqModes(), 0);
        tfPath = createTextField(config.getPath());
        cbContentType = createComboBox(getHeadersModes(), 0);
        cbBody = createComboBox(getBodyModes(), 0);
        cbRedirects = createComboBox(getRedirectsModes(), 1);
        tfRedirectsNum = createTextField(config.getRedirectNum());
        
        // Add components to left panel
        leftPanel.add(createFieldPanel("模版id：", tfId));
        leftPanel.add(createFieldPanel("模版名称：", tfName));
        leftPanel.add(createFieldPanel("作者名称：", tfAuthor));
        leftPanel.add(createFieldPanel("严重程度：", cbSeverity));
        leftPanel.add(createFieldPanel("描述：", tfDescription));
        leftPanel.add(createFieldPanel("Tags：", tfTags));
        leftPanel.add(createFieldPanel("请求方式：", cbRequestType));
        leftPanel.add(createFieldPanel("请求路径：", tfPath));
        leftPanel.add(createFieldPanel("Content-Type：", cbContentType));
        leftPanel.add(createFieldPanel("body：", cbBody));
        leftPanel.add(createFieldPanel("是否跟随跳转：", cbRedirects));
        leftPanel.add(createFieldPanel("跳转次数：", tfRedirectsNum));
        
        // Right panel for matcher checkboxes
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new GridLayout(11, 1));
        
        // Create and add matcher checkboxes
        cbMatchWord = createMatcherCheckBox("word", e -> {
            config.setMatchWord(cbMatchWord.isSelected());
        });
        
        cbMatchHeader = createMatcherCheckBox("header", e -> {
            config.setMatchHeader(cbMatchHeader.isSelected());
        });
        
        cbMatchStatus = createMatcherCheckBox("status", e -> {
            config.setMatchStatus(cbMatchStatus.isSelected());
        });
        
        cbMatchNegative = createMatcherCheckBox("negative", e -> {
            config.setMatchNegative(cbMatchNegative.isSelected());
        });
        
        cbMatchTime = createMatcherCheckBox("time", e -> {
            config.setMatchTime(cbMatchTime.isSelected());
        });
        
        cbMatchSize = createMatcherCheckBox("size", e -> {
            config.setMatchSize(cbMatchSize.isSelected());
        });
        
        cbMatchInteractshProtocol = createMatcherCheckBox("interactsh_protocol", e -> {
            config.setMatchInteractshProtocol(cbMatchInteractshProtocol.isSelected());
        });
        
        cbMatchInteractshRequest = createMatcherCheckBox("interactsh_request", e -> {
            config.setMatchInteractshRequest(cbMatchInteractshRequest.isSelected());
        });
        
        cbMatchRegex = createMatcherCheckBox("regex", e -> {
            config.setMatchRegex(cbMatchRegex.isSelected());
        });
        
        cbMatchBinary = createMatcherCheckBox("binary", e -> {
            config.setMatchBinary(cbMatchBinary.isSelected());
        });
        
        cbExtractors = createMatcherCheckBox("extractors", e -> {
            config.setExtractors(cbExtractors.isSelected());
        });
        
        // Add all matcher checkboxes to right panel
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchWord));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchHeader));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchStatus));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchNegative));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchTime));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchSize));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchInteractshProtocol));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchInteractshRequest));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchRegex));
        rightPanel.add(createMatcherPanel("matchers模版", cbMatchBinary));
        rightPanel.add(createMatcherPanel("extractors", cbExtractors));
        
        // Bottom panel for buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        JButton btnGenerate = new JButton("生成");
        btnGenerate.addActionListener(e -> generateTemplate());
        
        JButton btnClear = new JButton("清空");
        btnClear.addActionListener(e -> clearForm());
        
        buttonPanel.add(btnGenerate);
        buttonPanel.add(btnClear);
        
        // Combine panels
        JPanel centerPanel = new JPanel(new GridLayout(1, 2));
        centerPanel.add(leftPanel);
        centerPanel.add(rightPanel);
        
        mainPanel.add(centerPanel, BorderLayout.CENTER);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        return mainPanel;
    }
    
    /**
     * Create a panel for help content
     */
    private JPanel createHelpPanel(String resourcePath) {
        JPanel panel = new JPanel(new BorderLayout());
        
        try {
            String helpContent = HelpDataLoader.loadHelpData(resourcePath);
            JTextArea textArea = new JTextArea(helpContent);
            textArea.setEditable(false);
            JScrollPane scrollPane = new JScrollPane(textArea);
            panel.add(scrollPane, BorderLayout.CENTER);
        } catch (RuntimeException ex) {
            JLabel errorLabel = new JLabel("Failed to load help content: " + ex.getMessage());
            panel.add(errorLabel, BorderLayout.CENTER);
        }
        
        return panel;
    }
    
    /**
     * Create a panel for results
     */
    private JPanel createResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        taResults = new JTextArea(20, 80);
        taResults.setEditable(true);
        JScrollPane scrollPane = new JScrollPane(taResults);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * Generate YAML template based on current configuration
     */
    private void generateTemplate() {
        // Update config from UI components
        updateConfigFromUI();
        
        // Generate YAML
        String yaml = yamlGenerator.generateYaml(config);
        
        // Display result
        taResults.setText(yaml);
    }
    
    /**
     * Clear all form fields
     */
    private void clearForm() {
        // Reset config to defaults
        config.resetAllMatchers();
        
        // Reset text fields to defaults
        tfId.setText("test");
        tfName.setText("test");
        tfAuthor.setText("ffffffff0x");
        tfDescription.setText("由插件自动生成");
        tfTags.setText("auto");
        tfPath.setText("");
        tfRedirectsNum.setText("0");
        
        // Reset combo boxes to defaults
        cbSeverity.setSelectedIndex(0);
        cbRequestType.setSelectedIndex(0);
        cbContentType.setSelectedIndex(0);
        cbBody.setSelectedIndex(0);
        cbRedirects.setSelectedIndex(1);
        
        // Reset checkboxes
        cbMatchWord.setSelected(false);
        cbMatchHeader.setSelected(false);
        cbMatchStatus.setSelected(false);
        cbMatchNegative.setSelected(false);
        cbMatchTime.setSelected(false);
        cbMatchSize.setSelected(false);
        cbMatchInteractshProtocol.setSelected(false);
        cbMatchInteractshRequest.setSelected(false);
        cbMatchRegex.setSelected(false);
        cbMatchBinary.setSelected(false);
        cbExtractors.setSelected(false);
        
        // Clear results
        taResults.setText("");
    }
    
    /**
     * Update config object from UI component values
     */
    private void updateConfigFromUI() {
        config.setId(tfId.getText());
        config.setName(tfName.getText());
        config.setAuthor(tfAuthor.getText());
        config.setDescription(tfDescription.getText());
        config.setTags(tfTags.getText());
        config.setSeverity((String) cbSeverity.getSelectedItem());
        config.setRequestType((String) cbRequestType.getSelectedItem());
        config.setPath(tfPath.getText());
        config.setContentType((String) cbContentType.getSelectedItem());
        config.setBody((String) cbBody.getSelectedItem());
        config.setIsRedirect((String) cbRedirects.getSelectedItem());
        config.setRedirectNum(tfRedirectsNum.getText());
        
        // Matchers are already updated via checkbox listeners
    }
    
    /* Helper methods for creating UI components */
    
    private JPanel createFieldPanel(String labelText, JComponent field) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(createLabel(labelText), BorderLayout.WEST);
        panel.add(field, BorderLayout.CENTER);
        return panel;
    }
    
    private JPanel createMatcherPanel(String labelText, JCheckBox checkBox) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JLabel(labelText, SwingConstants.RIGHT), BorderLayout.WEST);
        panel.add(checkBox, BorderLayout.CENTER);
        return panel;
    }
    
    private JLabel createLabel(String text) {
        return new JLabel(text, SwingConstants.RIGHT);
    }
    
    private JTextField createTextField(String defaultValue) {
        JTextField textField = new JTextField(defaultValue);
        return textField;
    }
    
    private JComboBox<String> createComboBox(String[] items, int selectedIndex) {
        JComboBox<String> comboBox = new JComboBox<>(items);
        comboBox.setSelectedIndex(selectedIndex);
        return comboBox;
    }
    
    private JCheckBox createMatcherCheckBox(String text, ActionListener listener) {
        JCheckBox checkBox = new JCheckBox(" (" + text + ")");
        checkBox.addActionListener(listener);
        return checkBox;
    }
    
    /* Methods for obtaining dropdown values from Config */
    
    /**
     * 获取请求方式列表
     */
    private String[] getReqModes() {
        return ConfigUtils.getReqModes();
    }
    
    /**
     * 获取严重程度列表
     */
    private String[] getSeverityModes() {
        return ConfigUtils.getSeverityModes();
    }
    
    /**
     * 获取Body模式列表
     */
    private String[] getBodyModes() {
        return ConfigUtils.getBodyModes();
    }
    
    /**
     * 获取Content-Type列表
     */
    private String[] getHeadersModes() {
        return ConfigUtils.getHeadersModes();
    }
    
    /**
     * 获取重定向模式列表
     */
    private String[] getRedirectsModes() {
        return ConfigUtils.getRedirectsModes();
    }
}
