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

    boolean match_true;
    boolean match_word;
    boolean match_header;
    boolean match_status;
    boolean match_negative;
    boolean match_time;
    boolean match_size;
    boolean match_interactsh_protocol;
    boolean match_interactsh_request;
    boolean match_regex;
    boolean match_binary;
    boolean extractors;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("hello Nu_Te_Gen!");
        this.stdout.println("version:1.4");

        callbacks.getHelpers();

        callbacks.setExtensionName("Nu_Te_Gen V1.4");

        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {

                JPanel Nuc_jp1 = new JPanel();
                Nuc_jp1.setLayout(new GridLayout(13, 1));

                JButton Nuc_bt_1 = new JButton("生成");
                JButton Nuc_bt_2 = new JButton("清空");

                JLabel Nuc_lb_id = createLabel("模版id：");
                JTextField Nuc_tf_id = createTextField("test");

                JLabel Nuc_lb_name = createLabel("模版名称：");
                JTextField Nuc_tf_name = createTextField("test");

                JLabel Nuc_lb_author = createLabel("作者名称：");
                JTextField Nuc_tf_author = createTextField("ffffffff0x");

                JLabel Nuc_lb_severity = createLabel("严重程度：");
                JComboBox<String> Nuc_Tab_severity = createComboBox(GetSeverityModes(), 0);

                JLabel Nuc_lb_description = createLabel("描述：");
                JTextField Nuc_tf_description = createTextField("由插件自动生成");

                JLabel Nuc_lb_tags = createLabel("Tags：");
                JTextField Nuc_tf_tags = createTextField("auto");

                JLabel Nuc_lb_req = createLabel("请求方式：");
                JComboBox<String> Nuc_Tab_req = createComboBox(GetReqModes(), 0);

                JLabel Nuc_lb_path = createLabel("请求路径：");
                JTextField Nuc_tf_path = createTextField("");

                JLabel Nuc_lb_headers = createLabel("Content-Type：");
                JComboBox<String> Nuc_Tab_headers = createComboBox(GetHeadersModes(), 0);

                JLabel Nuc_lb_body = createLabel("body：");
                JComboBox<String> Nuc_Tab_body = createComboBox(GetBodyModes(), 0);

                JLabel Nuc_lb_redirects = createLabel("是否跟随跳转：");
                JComboBox<String> Nuc_Tab_redirects = createComboBox(GetRedirectsModes(), 1);

                JLabel Nuc_lb_redirects_num = createLabel("跳转次数：");
                JTextField Nuc_tf_redirects_num = createTextField("0");

                // 分割

                JLabel Nuc_lb_Match_word = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_word = new JCheckBox(" (word)");
                Nuc_CB_Match_word.addActionListener(e -> {
                    if (Nuc_CB_Match_word.isSelected()) {
                        match_word = true;
                        match_true = true;
                    } else {
                        match_word = false;
                    }
                });

                JLabel Nuc_lb_Match_header = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_header = new JCheckBox(" (header)");
                Nuc_CB_Match_header.addActionListener(e -> {
                    if (Nuc_CB_Match_header.isSelected()) {
                        match_header = true;
                        match_true = true;
                    } else {
                        match_header = false;
                    }
                });

                JLabel Nuc_lb_Match_status = new JLabel("matchers模版", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_status = new JCheckBox(" (status)");
                Nuc_CB_Match_status.addActionListener(e -> {
                    if (Nuc_CB_Match_status.isSelected()) {
                        match_status = true;
                        match_true = true;
                    } else {
                        match_status = false;
                    }
                });

                JLabel Nuc_lb_Match_extractors = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_extractors = new JCheckBox(" (extractors)");
                Nuc_CB_Match_extractors.addActionListener(e -> extractors = Nuc_CB_Match_extractors.isSelected());

                JLabel Nuc_lb_Match_negative = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_negative = new JCheckBox(" (negative)");
                Nuc_CB_Match_negative.addActionListener(e -> {
                    if (Nuc_CB_Match_negative.isSelected()) {
                        match_negative = true;
                        match_true = true;
                    } else {
                        match_negative = false;
                    }
                });

                JLabel Nuc_lb_Match_time = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_time = new JCheckBox(" (time)");
                Nuc_CB_Match_time.addActionListener(e -> {
                    if (Nuc_CB_Match_time.isSelected()) {
                        match_time = true;
                        match_true = true;
                    } else {
                        match_time = false;
                    }
                });

                JLabel Nuc_lb_Match_size = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_size = new JCheckBox(" (size)");
                Nuc_CB_Match_size.addActionListener(e -> {
                    if (Nuc_CB_Match_size.isSelected()) {
                        match_size = true;
                        match_true = true;
                    } else {
                        match_size = false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_protocol = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_protocol = new JCheckBox(" (interactsh_protocol)");
                Nuc_CB_Match_interactsh_protocol.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_protocol.isSelected()) {
                        match_interactsh_protocol = true;
                        match_true = true;
                    } else {
                        match_interactsh_protocol = false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_request = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_request = new JCheckBox(" (interactsh_request)");
                Nuc_CB_Match_interactsh_request.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_request.isSelected()) {
                        match_interactsh_request = true;
                        match_true = true;
                    } else {
                        match_interactsh_request = false;
                    }
                });

                JLabel Nuc_lb_Match_regex = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_regex = new JCheckBox(" (regex)");
                Nuc_CB_Match_regex.addActionListener(e -> {
                    if (Nuc_CB_Match_regex.isSelected()) {
                        match_regex = true;
                        match_true = true;
                    } else {
                        match_regex = false;
                    }
                });

                JLabel Nuc_lb_Match_binary = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_binary = new JCheckBox(" (binary)");
                Nuc_CB_Match_binary.addActionListener(e -> {
                    if (Nuc_CB_Match_binary.isSelected()) {
                        match_binary = true;
                        match_true = true;
                    } else {
                        match_binary = false;
                    }
                });

                Component[] components = {
                        Nuc_bt_1, Nuc_bt_2,
                        Nuc_lb_id, Nuc_tf_id,
                        Nuc_lb_name, Nuc_tf_name,
                        Nuc_lb_author, Nuc_tf_author,
                        Nuc_lb_severity, Nuc_Tab_severity,
                        Nuc_lb_description, Nuc_tf_description,
                        Nuc_lb_tags, Nuc_tf_tags,
                        Nuc_lb_req, Nuc_Tab_req,
                        Nuc_lb_path, Nuc_tf_path,
                        Nuc_lb_headers, Nuc_Tab_headers,
                        Nuc_lb_body, Nuc_Tab_body,
                        Nuc_lb_redirects, Nuc_Tab_redirects,
                        Nuc_lb_redirects_num, Nuc_tf_redirects_num
                };

                for (Component component : components) {
                    Nuc_jp1.add(component);
                }

                JPanel Nuc_jp4 = new JPanel();
                Nuc_jp4.setLayout(new GridLayout(14, 2));

                Component[] matchComponents = {
                        Nuc_lb_Match_word, Nuc_CB_Match_word,
                        Nuc_lb_Match_header, Nuc_CB_Match_header,
                        Nuc_lb_Match_status, Nuc_CB_Match_status,
                        Nuc_lb_Match_extractors, Nuc_CB_Match_extractors,
                        Nuc_lb_Match_negative, Nuc_CB_Match_negative,
                        Nuc_lb_Match_time, Nuc_CB_Match_time,
                        Nuc_lb_Match_size, Nuc_CB_Match_size,
                        Nuc_lb_Match_interactsh_protocol, Nuc_CB_Match_interactsh_protocol,
                        Nuc_lb_Match_interactsh_request, Nuc_CB_Match_interactsh_request,
                        Nuc_lb_Match_regex, Nuc_CB_Match_regex, Nuc_lb_Match_binary, Nuc_CB_Match_binary
                };

                for (Component component : matchComponents) {
                    Nuc_jp4.add(component);
                }

                JPanel Nuc_jp2 = new JPanel();
                Nuc_jp2.setLayout(new GridLayout(1, 1));

                JTextArea Nuc_ta_2 = new JTextArea();
                Nuc_ta_2.setText("");
                Nuc_ta_2.setRows(30);
                Nuc_ta_2.setColumns(30);
                Nuc_ta_2.setLineWrap(true);
                Nuc_ta_2.setEditable(true);
                JScrollPane Nuc_sp_2 = new JScrollPane(Nuc_ta_2);

                Nuc_jp2.add(Nuc_sp_2);

                // 使用方法加载两个帮助数据并创建对应的面板
                JPanel Nuc_jp3 = new JPanel();
                Nuc_jp3.setLayout(new GridLayout(1, 2));

                JScrollPane Nuc_sp_3 = createHelpPanel("/help1.txt");
                JScrollPane Nuc_sp_4 = createHelpPanel("/help2.txt");

                Nuc_jp3.add(Nuc_sp_3);
                Nuc_jp3.add(Nuc_sp_4);

                Nuc_bt_1.addActionListener(e -> {
                    Object redirects = Nuc_Tab_redirects.getSelectedItem();
                    Object req = Nuc_Tab_req.getSelectedItem();
                    Object headers = Nuc_Tab_headers.getSelectedItem();
                    Object body = Nuc_Tab_body.getSelectedItem();
                    Object severity = Nuc_Tab_severity.getSelectedItem();

                    String redirectsString = redirects != null ? redirects.toString() : "";
                    String reqString = req != null ? req.toString() : "";
                    String headersString = headers != null ? headers.toString() : "";
                    String bodyString = body != null ? body.toString() : "";
                    String severityString = severity != null ? severity.toString() : "";

                    Nuc_ta_2.setText(Yaml_Gen(Nuc_tf_id.getText(), Nuc_tf_name.getText(), Nuc_tf_author.getText(),
                            Nuc_tf_description.getText(), Nuc_tf_tags.getText(), redirectsString,
                            Nuc_tf_redirects_num.getText(), reqString, Nuc_tf_path.getText(),
                            headersString, bodyString, severityString));
                });

                Nuc_bt_2.addActionListener(e -> Nuc_ta_2.setText(""));

                tabs = new JTabbedPane();

                JSplitPane Nu_Te_Pane2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                tabs.addTab("Template生成", Nu_Te_Pane2);

                JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPanes.setTopComponent(Nuc_jp1);
                splitPanes.setBottomComponent(Nuc_jp4);
                splitPanes.setDividerLocation(450);

                JSplitPane splitPanes_2 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                splitPanes_2.setLeftComponent(Nuc_jp2);
                splitPanes_2.setRightComponent(Nuc_jp3);
                splitPanes_2.setDividerLocation(430);

                Nu_Te_Pane2.setLeftComponent(splitPanes);
                Nu_Te_Pane2.setRightComponent(splitPanes_2);
                Nu_Te_Pane2.setDividerLocation(380);

                callbacks.customizeUiComponent(tabs);

                callbacks.addSuiteTab(BurpExtender.this);

                callbacks.registerHttpListener(BurpExtender.this);

            }

            private JLabel createLabel(String text) {
                return new JLabel(text, SwingConstants.RIGHT);
            }

            private JTextField createTextField(String defaultValue) {
                JTextField textField = new JTextField(1);
                textField.setText(defaultValue);
                return textField;
            }

            private JComboBox<String> createComboBox(String[] items, int selectedIndex) {
                JComboBox<String> comboBox = new JComboBox<>(items);
                comboBox.setMaximumSize(comboBox.getPreferredSize());
                comboBox.setSelectedIndex(selectedIndex);
                return comboBox;
            }

            // 方法提取加载帮助数据
            private JScrollPane createHelpPanel(String filePath) {
                JPanel panel = new JPanel();
                panel.setLayout(new GridLayout(1, 1));

                String helpData = HelpDataLoader.loadHelpData(filePath);

                JTextArea textArea = new JTextArea();
                textArea.setText(helpData);
                textArea.setRows(30);
                textArea.setColumns(30);
                textArea.setLineWrap(true); // 自动换行
                textArea.setEditable(true); // 可编辑
                JScrollPane scrollPane = new JScrollPane(textArea);

                panel.add(scrollPane);
                return scrollPane;
            }

            private String[] GetReqModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.reqMode[] backends = Config.reqMode.values();
                for (Config.reqMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] GetSeverityModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.severityMode[] backends = Config.severityMode.values();
                for (Config.severityMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] GetBodyModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.ContentBodyMode[] backends = Config.ContentBodyMode.values();
                for (Config.ContentBodyMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] GetHeadersModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.ContentTypeMode[] backends = Config.ContentTypeMode.values();
                for (Config.ContentTypeMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] GetRedirectsModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.RedirectsMode[] backends = Config.RedirectsMode.values();
                for (Config.RedirectsMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    }

    @Override
    public String getTabCaption() {
        return "Nu_Te_Gen";
    }

    @Override
    public Component getUiComponent() {
        return tabs;
    }

    private String Yaml_Gen(String TP_Id, String TP_Name, String TP_Author, String TP_Description, String TP_Tags,
            String TP_IsRedirect, String TP_Redirect_Num, String TP_Req, String TP_Path, String TP_Header,
            String TP_Body, String Tp_Severity) {
        String data = "";

        // 图省事，直接修改此处，硬编码metadata字段
        String id_info = """
                id: %s

                info:
                  name: %s
                  author: %s
                  severity: %s
                  description: |
                    %s
                  metadata:
                    fofa-query:\s
                    shodan-query:\s
                    hunter-query:\s
                  reference:
                    - https://
                  tags: %s

                """;
        data += String.format(id_info, TP_Id, TP_Name, TP_Author, Tp_Severity, TP_Description, TP_Tags);

        String raw_requests = """
                http:
                  - raw:
                      - |
                        POST %s HTTP/1.1
                        Host: {{Hostname}}
                        Content-Type: %s

                        %s

                """;

        String requests = """
                http:
                  - method: %s
                    path:
                      - "{{BaseURL}}%s"

                """;

        String Header = """
                    headers:
                      Content-Type: %s

                """;

        String Body = """
                    body: |
                      替换此处注意每行缩进

                """;

        String redirects = """
                    host-redirects: true
                    max-redirects: %s

                """;

        String Matchers = """
                    matchers-condition: and
                    matchers:
                """;

        String MatchersWord = """
                      - type: word
                        part: body
                        words:
                          - 'test1'
                          - 'test2'
                        condition: or

                """;

        String MatchersHeader = """
                      - type: word
                        part: header
                        words:
                          - 'tomcat'

                """;

        String MatchersStatus = """
                      - type: status
                        status:
                          - 200

                """;

        String MatchersNegative = """
                      - type: word
                        words:
                          - "荣耀立方"
                          - 'var model = "LW-N605R"'
                        part: body
                        negative: true
                        condition: or

                """;

        String MatchersTime = """
                      - type: dsl
                        dsl:
                          - 'duration>=6'

                """;

        String MatchersSize = """
                      - type: dsl
                        dsl:
                          - 'len(body)<130'

                """;

        String MatchersInteractsh_Protocol = """
                      - type: word
                        part: interactsh_protocol  # 配合 {{interactsh-url}} 关键词使用
                        words:
                          - "http"

                """;

        String MatchersInteractsh_Request = """
                      - type: regex
                        part: interactsh_request   # 配合 {{interactsh-url}} 关键词使用
                        regex:
                          - "root:.*:0:0:"

                """;

        String MatchersInteractsh_Regex = """
                      - type: regex
                        regex:
                          - "root:.*:0:0:"
                        part: body

                """;

        String MatchersInteractsh_Binary = """
                      - type: binary
                        binary:
                          - "D0CF11E0"  # db
                          - "53514C69746520"  # SQLite
                        part: body
                        condition: or

                """;

        String Extractors = """
                    extractors:
                      - part: header
                        internal: true
                        group: 1
                        type: regex
                        regex:
                          - 'Set-Cookie: PHPSESSID=(.*); path=/'

                """;

        if ("RAW".equals(TP_Req)) {
            if ("urlencoded".equals(TP_Header)) {
                TP_Header = "application/x-www-form-urlencoded";
            } else if ("json".equals(TP_Header)) {
                TP_Header = "application/json";
            }

            if ("带".equals(TP_Body)) {
                TP_Body = "Body";
            } else if ("不带".equals(TP_Body)) {
                TP_Body = "";
            }

            data += String.format(raw_requests, TP_Path, TP_Header, TP_Body);
        } else {
            data += String.format(requests, TP_Req, TP_Path);
            if ("urlencoded".equals(TP_Header)) {
                data += String.format(Header, "application/x-www-form-urlencoded");
            } else if ("json".equals(TP_Header)) {
                data += String.format(Header, "application/json");
            } else if ("xml".equals(TP_Header)) {
                data += String.format(Header, "text/xml");
            }

            if (!"不带".equals(TP_Body)) {
                data += String.format(Body, TP_Body);
            }
        }

        if ("istrue".equals(TP_IsRedirect)) {
            data += String.format(redirects, TP_Redirect_Num);
        }

        data = getString(data, Matchers, MatchersWord, MatchersHeader, MatchersStatus, MatchersNegative, MatchersTime,
                match_true, match_word, match_header, match_status, match_negative, match_time);
        data = getString(data, MatchersSize, MatchersInteractsh_Protocol, MatchersInteractsh_Request,
                MatchersInteractsh_Regex, MatchersInteractsh_Binary, Extractors, match_size, match_interactsh_protocol,
                match_interactsh_request, match_regex, match_binary, extractors);
        return data;
    }

    private String getString(String data, String matchers, String matchersWord, String matchersHeader,
            String matchersStatus, String matchersNegative, String matchersTime, boolean matchTrue, boolean matchWord,
            boolean matchHeader, boolean matchStatus, boolean matchNegative, boolean matchTime) {
        if (matchTrue) {
            data += matchers;
        }
        if (matchWord) {
            data += matchersWord;
        }
        if (matchHeader) {
            data += matchersHeader;
        }
        if (matchStatus) {
            data += matchersStatus;
        }
        if (matchNegative) {
            data += matchersNegative;
        }
        if (matchTime) {
            data += matchersTime;
        }
        return data;
    }
}