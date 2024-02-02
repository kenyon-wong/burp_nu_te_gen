package burp;

import burp.utils.Config;

import java.awt.Component;
import java.io.PrintWriter;
import javax.swing.*;
import java.awt.*;
import java.util.*;

public class BurpGenerator implements IBurpExtender, ITab, IHttpListener {
    private JTabbedPane tabs;
    public PrintWriter stdout;

    boolean matchTrue;
    boolean matchWord;
    boolean matchHeader;
    boolean matchStatus;
    boolean matchNegative;
    boolean matchTime;
    boolean matchSize;
    boolean matchInteractshProtocol;
    boolean matchInteractshRequest;
    boolean matchRegex;
    boolean matchBinary;
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
                JComboBox<String> Nuc_Tab_severity = createComboBox(getSeverityModes(), 0);

                JLabel Nuc_lb_description = createLabel("描述：");
                JTextField Nuc_tf_description = createTextField("由插件自动生成");

                JLabel Nuc_lb_tags = createLabel("Tags：");
                JTextField Nuc_tf_tags = createTextField("auto");

                JLabel Nuc_lb_req = createLabel("请求方式：");
                JComboBox<String> Nuc_Tab_req = createComboBox(getReqModes(), 0);

                JLabel Nuc_lb_path = createLabel("请求路径：");
                JTextField Nuc_tf_path = createTextField("");

                JLabel Nuc_lb_headers = createLabel("Content-Type：");
                JComboBox<String> Nuc_Tab_headers = createComboBox(GetHeadersModes(), 0);

                JLabel Nuc_lb_body = createLabel("body：");
                JComboBox<String> Nuc_Tab_body = createComboBox(getBodyModes(), 0);

                JLabel Nuc_lb_redirects = createLabel("是否跟随跳转：");
                JComboBox<String> Nuc_Tab_redirects = createComboBox(GetRedirectsModes(), 1);

                JLabel Nuc_lb_redirects_num = createLabel("跳转次数：");
                JTextField Nuc_tf_redirects_num = createTextField("0");

                JLabel Nuc_lb_Match_word = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_word = new JCheckBox(" (word)");
                Nuc_CB_Match_word.addActionListener(e -> {
                    if (Nuc_CB_Match_word.isSelected()) {
                        matchWord = true;
                        matchTrue = true;
                    } else {
                        matchWord = false;
                    }
                });

                JLabel Nuc_lb_Match_header = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_header = new JCheckBox(" (header)");
                Nuc_CB_Match_header.addActionListener(e -> {
                    if (Nuc_CB_Match_header.isSelected()) {
                        matchHeader = true;
                        matchTrue = true;
                    } else {
                        matchHeader = false;
                    }
                });

                JLabel Nuc_lb_Match_status = new JLabel("matchers模版", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_status = new JCheckBox(" (status)");
                Nuc_CB_Match_status.addActionListener(e -> {
                    if (Nuc_CB_Match_status.isSelected()) {
                        matchStatus = true;
                        matchTrue = true;
                    } else {
                        matchStatus = false;
                    }
                });

                JLabel Nuc_lb_Match_extractors = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_extractors = new JCheckBox(" (extractors)");
                Nuc_CB_Match_extractors.addActionListener(e -> extractors = Nuc_CB_Match_extractors.isSelected());

                JLabel Nuc_lb_Match_negative = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_negative = new JCheckBox(" (negative)");
                Nuc_CB_Match_negative.addActionListener(e -> {
                    if (Nuc_CB_Match_negative.isSelected()) {
                        matchNegative = true;
                        matchTrue = true;
                    } else {
                        matchNegative = false;
                    }
                });

                JLabel Nuc_lb_Match_time = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_time = new JCheckBox(" (time)");
                Nuc_CB_Match_time.addActionListener(e -> {
                    if (Nuc_CB_Match_time.isSelected()) {
                        matchTime = true;
                        matchTrue = true;
                    } else {
                        matchTime = false;
                    }
                });

                JLabel Nuc_lb_Match_size = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_size = new JCheckBox(" (size)");
                Nuc_CB_Match_size.addActionListener(e -> {
                    if (Nuc_CB_Match_size.isSelected()) {
                        matchSize = true;
                        matchTrue = true;
                    } else {
                        matchSize = false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_protocol = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_protocol = new JCheckBox(" (interactsh_protocol)");
                Nuc_CB_Match_interactsh_protocol.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_protocol.isSelected()) {
                        matchInteractshProtocol = true;
                        matchTrue = true;
                    } else {
                        matchInteractshProtocol = false;
                    }
                });

                JLabel Nuc_lb_Match_interactsh_request = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_interactsh_request = new JCheckBox(" (interactsh_request)");
                Nuc_CB_Match_interactsh_request.addActionListener(e -> {
                    if (Nuc_CB_Match_interactsh_request.isSelected()) {
                        matchInteractshRequest = true;
                        matchTrue = true;
                    } else {
                        matchInteractshRequest = false;
                    }
                });

                JLabel Nuc_lb_Match_regex = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_regex = new JCheckBox(" (regex)");
                Nuc_CB_Match_regex.addActionListener(e -> {
                    if (Nuc_CB_Match_regex.isSelected()) {
                        matchRegex = true;
                        matchTrue = true;
                    } else {
                        matchRegex = false;
                    }
                });

                JLabel Nuc_lb_Match_binary = new JLabel("matchers模版 ", SwingConstants.RIGHT);
                JCheckBox Nuc_CB_Match_binary = new JCheckBox(" (binary)");
                Nuc_CB_Match_binary.addActionListener(e -> {
                    if (Nuc_CB_Match_binary.isSelected()) {
                        matchBinary = true;
                        matchTrue = true;
                    } else {
                        matchBinary = false;
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

                    Nuc_ta_2.setText(yamlGen(Nuc_tf_id.getText(), Nuc_tf_name.getText(), Nuc_tf_author.getText(),
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

                callbacks.addSuiteTab(BurpGenerator.this);

                callbacks.registerHttpListener(BurpGenerator.this);

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

            private String[] getReqModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.reqMode[] backends = Config.reqMode.values();
                for (Config.reqMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] getSeverityModes() {
                ArrayList<String> algStrs = new ArrayList<>();
                Config.severityMode[] backends = Config.severityMode.values();
                for (Config.severityMode backend : backends) {
                    algStrs.add(backend.name().replace('_', '/'));
                }
                return algStrs.toArray(new String[0]);
            }

            private String[] getBodyModes() {
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

    private String yamlGen(String tpId, String tpName, String tpAuthor, String tpDescription, String tpTags,
                           String tpIsRedirect, String tpRedirectNum, String tpReq, String tpPath, String tpHeader,
                           String tpBody, String tpSeverity) {
        String data = "";

        String id_info = "id: %s\n\n" +
                "info:\n" +
                "  name: %s\n" +
                "  author: %s\n" +
                "  severity: %s\n" +
                "  description: |\n" +
                "    %s\n" +
                "  metadata:\n" +
                "    fofa-query: \n" +
                "    shodan-query: \n" +
                "    hunter-query: \n" +
                "  reference:\n" +
                "    - https://\n" +
                "  tags: %s\n\n";
        data += String.format(id_info, tpId, tpName, tpAuthor, tpSeverity, tpDescription, tpTags);

        String raw_requests = "http:\n" +
                "  - raw:\n" +
                "      - |\n" +
                "        POST %s HTTP/1.1\n" +
                "        Host: {{Hostname}}\n" +
                "        Content-Type: %s\n" +
                "\n" +
                "        %s\n\n";

        String requests = "http:\n" +
                "  - method: %s\n" +
                "    path:\n" +
                "      - \"{{BaseURL}}%s\"\n\n";

        String Header = "    headers:\n" +
                "      Content-Type: %s\n\n";

        String Body = "    body: |\n" +
                "      替换此处注意每行缩进\n\n";

        String redirects = "    host-redirects: true\n" +
                "    max-redirects: %s\n\n";

        String Matchers = "    matchers-condition: and\n" +
                "    matchers:\n";

        String MatchersWord = "      - type: word\n" +
                "        part: body\n" +
                "        words:\n" +
                "          - 'test1'\n" +
                "          - 'test2'\n" +
                "        condition: or\n\n";

        String MatchersHeader = "      - type: word\n" +
                "        part: header\n" +
                "        words:\n" +
                "          - 'tomcat'\n\n";

        String MatchersStatus = "      - type: status\n" +
                "        status:\n" +
                "          - 200\n\n";

        String MatchersNegative = "      - type: word\n" +
                "        words:\n" +
                "          - \"荣耀立方\"\n" +
                "          - 'var model = \"LW-N605R\"'\n" +
                "        part: body\n" +
                "        negative: true\n" +
                "        condition: or\n\n";

        String MatchersTime = "      - type: dsl\n" +
                "        dsl:\n" +
                "          - 'duration>=6'\n\n";

        String MatchersSize = "      - type: dsl\n" +
                "        dsl:\n" +
                "          - 'len(body)<130'\n\n";

        String MatchersInteractsh_Protocol = "      - type: word\n" +
                "        part: interactsh_protocol  # 配合 {{interactsh-url}} 关键词使用\n" +
                "        words:\n" +
                "          - \"http\"\n\n";

        String MatchersInteractsh_Request = "      - type: regex\n" +
                "        part: interactsh_request   # 配合 {{interactsh-url}} 关键词使用\n" +
                "        regex:\n" +
                "          - \"root:.*:0:0:\"\n\n";

        String MatchersInteractsh_Regex = "      - type: regex\n" +
                "        regex:\n" +
                "          - \"root:.*:0:0:\"\n" +
                "        part: body\n\n";

        String MatchersInteractsh_Binary = "      - type: binary\n" +
                "        binary:\n" +
                "          - \"D0CF11E0\"  # db\n" +
                "          - \"53514C69746520\"  # SQLite\n" +
                "        part: body\n" +
                "        condition: or\n\n";

        String Extractors = "    extractors:\n" +
                "      - part: header\n" +
                "        internal: true\n" +
                "        group: 1\n" +
                "        type: regex\n" +
                "        regex:\n" +
                "          - 'Set-Cookie: PHPSESSID=(.*); path=/'\n\n";

        if ("RAW".equals(tpReq)) {
            if ("urlencoded".equals(tpHeader)) {
                tpHeader = "application/x-www-form-urlencoded";
            } else if ("json".equals(tpHeader)) {
                tpHeader = "application/json";
            }

            if ("带".equals(tpBody)) {
                tpBody = "Body";
            } else if ("不带".equals(tpBody)) {
                tpBody = "";
            }

            data += String.format(raw_requests, tpPath, tpHeader, tpBody);
        } else {
            data += String.format(requests, tpReq, tpPath);
            if ("urlencoded".equals(tpHeader)) {
                data += String.format(Header, "application/x-www-form-urlencoded");
            } else if ("json".equals(tpHeader)) {
                data += String.format(Header, "application/json");
            } else if ("xml".equals(tpHeader)) {
                data += String.format(Header, "text/xml");
            }

            if (!"不带".equals(tpBody)) {
                data += String.format(Body, tpBody);
            }
        }

        if ("istrue".equals(tpIsRedirect)) {
            data += String.format(redirects, tpRedirectNum);
        }

        data = getString(data, Matchers, MatchersWord, MatchersHeader, MatchersStatus, MatchersNegative, MatchersTime,
                matchTrue, matchWord, matchHeader, matchStatus, matchNegative, matchTime);
        data = getString(data, MatchersSize, MatchersInteractsh_Protocol, MatchersInteractsh_Request,
                MatchersInteractsh_Regex, MatchersInteractsh_Binary, Extractors, matchSize, matchInteractshProtocol,
                matchInteractshRequest, matchRegex, matchBinary, extractors);
        return data;
    }

    private String getString(String data, String matchers, String matchersWord, String matchersHeader,
                             String matchersStatus, String matchersNegative, String matchersTime, boolean matchTrue,
                             boolean matchWord, boolean matchHeader, boolean matchStatus, boolean matchNegative,
                             boolean matchTime) {
        StringBuilder stringBuilder = new StringBuilder(data);
        if (matchTrue) {
            stringBuilder.append(matchers);
        }
        if (matchWord) {
            stringBuilder.append(matchersWord);
        }
        if (matchHeader) {
            stringBuilder.append(matchersHeader);
        }
        if (matchStatus) {
            stringBuilder.append(matchersStatus);
        }
        if (matchNegative) {
            stringBuilder.append(matchersNegative);
        }
        if (matchTime) {
            stringBuilder.append(matchersTime);
        }
        return stringBuilder.toString();
    }

}