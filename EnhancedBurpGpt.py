# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IScannerCheck
from burp import ITab
from javax.swing import JMenuItem, JPanel, JTextArea, JScrollPane, BoxLayout, JTabbedPane, JDialog, JProgressBar, JLabel
from javax.swing import JButton, JTextField, JOptionPane, JSplitPane
from java.awt import BorderLayout, Dimension, Color
from java.io import PrintWriter
from java.util import ArrayList
import json
import urllib2
import ssl
from javax.swing import SwingUtilities
from java.lang import Thread, Runnable, String, System
from java.util.concurrent import TimeUnit, Future, TimeoutException
from java.util.concurrent import ExecutorService, Executors
import java.text
from java.io import ByteArrayOutputStream, OutputStreamWriter
from java.nio.charset import StandardCharsets
import base64
from javax.swing import DefaultListModel, JList
from javax.swing.event import ListSelectionListener
from javax.swing import BorderFactory, Box
from java.awt import GridBagLayout, GridBagConstraints, Insets

class BurpExtender(IBurpExtender, IContextMenuFactory, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        self.api_key = "Please enter your API key"
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "Please select or enter the model name to use"
        self.max_tokens = 3072
        self.timeout_seconds = 60  # 设置超时时间
        
        # 添加默认长度限制
        self.max_request_length = 1000
        self.max_response_length = 2000
        
        # 创建线程池
        self.executor = Executors.newCachedThreadPool()
        
        # 创建主标签页面板
        self.tab = JTabbedPane()
        
        # 创建日志面板
        self.log_panel = JPanel(BorderLayout())
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        log_scroll = JScrollPane(self.log_area)
        self.log_panel.add(log_scroll, BorderLayout.CENTER)
        
        # 创建配置面板
        config_panel = self.create_config_panel()
        
        # 创建结果面板
        results_panel = self.create_results_panel()
        
        # 添加标签页
        self.tab.addTab("Configuration", config_panel)
        self.tab.addTab("Analysis Results", results_panel)
        self.tab.addTab("Logs", self.log_panel)  # 添加日志标签页
        
        # 注册扩展
        callbacks.setExtensionName("Enhanced BurpGPT")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)
        
        # 需要添加debug变量初始化
        self.debug = True  # 或从配置中读取
        
        # 设置默认的prompt模板，只使用ASCII字符
        default_prompt = """Answer in Chinese.Please analyze this HTTP request and response:

Request:
{REQUEST}

Response:
{RESPONSE}

Please identify any security issues and suggest fixes."""
        
        self.prompt_area.setText(default_prompt)
        
        # 配置SSL
        System.setProperty("jsse.enableSNIExtension", "false")
        System.setProperty("https.protocols", "TLSv1.2")
        System.setProperty("javax.net.ssl.trustStore", "")
        System.setProperty("javax.net.ssl.trustStorePassword", "")
        
    def create_config_panel(self):
        config_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 10, 5, 10)  # 上、左、下、右的边距
        
        # API设置面板
        api_panel = JPanel(GridBagLayout())
        api_panel.setBorder(BorderFactory.createTitledBorder("API Settings"))
        
        # API URL配置
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 1
        constraints.weightx = 0.2
        api_panel.add(JLabel("API URL:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.url_field = JTextField(self.api_url, 40)
        self.url_field.setToolTipText("Enter the API endpoint URL")
        api_panel.add(self.url_field, constraints)
        
        # API Key配置
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.2
        api_panel.add(JLabel("API Key:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.key_field = JTextField(self.api_key, 40)
        self.key_field.setToolTipText("Enter your API key")
        api_panel.add(self.key_field, constraints)
        
        # Model配置区域改造
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0.2
        api_panel.add(JLabel("Model:"), constraints)
        
        # 创建模型选择的组合框
        from javax.swing import JComboBox
        self.model_combo = JComboBox()
        self.model_combo.setEditable(True)  # 允许手动输入
        self.model_combo.setToolTipText("Select or enter the model name to use")
        
        # 创建获取模型列表的按钮
        fetch_models_button = JButton("Fetch Models")
        fetch_models_button.setToolTipText("Fetch available models from API")
        
        # 创建模型选择面板
        model_panel = JPanel(BorderLayout())
        model_panel.add(self.model_combo, BorderLayout.CENTER)
        model_panel.add(fetch_models_button, BorderLayout.EAST)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        api_panel.add(model_panel, constraints)
        
        # 限制设置面板
        limits_panel = JPanel(GridBagLayout())
        limits_panel.setBorder(BorderFactory.createTitledBorder("Limits & Timeouts"))
        
        # Timeout配置
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Timeout (seconds):"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.timeout_field = JTextField(str(self.timeout_seconds), 10)
        self.timeout_field.setToolTipText("Maximum time to wait for API response")
        limits_panel.add(self.timeout_field, constraints)
        
        # 请求长度限制
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Max Request Length:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.req_length_field = JTextField(str(self.max_request_length), 10)
        self.req_length_field.setToolTipText("Maximum length of request content to analyze")
        limits_panel.add(self.req_length_field, constraints)
        
        # 响应长度限制
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Max Response Length:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.resp_length_field = JTextField(str(self.max_response_length), 10)
        self.resp_length_field.setToolTipText("Maximum length of response content to analyze")
        limits_panel.add(self.resp_length_field, constraints)
        
        # Prompt模板面板
        prompt_panel = JPanel(GridBagLayout())
        prompt_panel.setBorder(BorderFactory.createTitledBorder("Prompt Template"))
        
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        constraints.weighty = 1.0
        self.prompt_area = JTextArea(5, 40)
        self.prompt_area.setLineWrap(True)
        self.prompt_area.setWrapStyleWord(True)
        self.prompt_area.setToolTipText("Template for analysis prompt. Use {URL}, {METHOD}, {REQUEST}, {RESPONSE} as placeholders")
        prompt_scroll = JScrollPane(self.prompt_area)
        prompt_panel.add(prompt_scroll, constraints)
        
        # 按钮面板
        button_panel = JPanel()
        button_panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0))
        
        def fetch_models(event):
            try:
                # 验证必要的配置
                api_url = self.url_field.getText()
                api_key = self.key_field.getText()
                
                if not api_url or not api_key:
                    JOptionPane.showMessageDialog(None, "Please enter API URL and API Key first!")
                    return
                
                # 构造models API URL
                models_url = api_url.replace("/v1/chat/completions", "/v1/models")
                
                # 从配置中获取Host
                host = models_url.split("://")[-1].split("/")[0]
                
                # 请求头
                headers = {
                    "Host": host,
                    "Authorization": "Bearer " + api_key,
                    "Accept": "*/*",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.215",
                    "Accept-Language": "zh-CN"
                }
                
                self.log("[+] Fetching models from {}".format(models_url))
                
                # 创建请求
                request = urllib2.Request(
                    url=models_url,
                    headers=headers
                )
                
                # 发送请求
                response = urllib2.urlopen(request, timeout=self.timeout_seconds)
                response_data = response.read()
                response_text = response_data.decode('utf-8')
                
                # 解析JSON响应
                models_data = json.loads(response_text)
                
                if 'data' in models_data:
                    # 清除现有的模型列表
                    self.model_combo.removeAllItems()
                    
                    # 添加新的模型
                    for model in models_data['data']:
                        model_id = model.get('id')
                        if model_id:
                            self.model_combo.addItem(model_id)
                    
                    self.log("[+] Successfully fetched {} models".format(len(models_data['data'])))
                    JOptionPane.showMessageDialog(None, "Successfully fetched models!")
                else:
                    raise Exception("Invalid response format")
                
            except Exception as e:
                error_msg = "Error fetching models: {}".format(str(e))
                self.log("[-] " + error_msg)
                JOptionPane.showMessageDialog(None, error_msg)
        
        fetch_models_button.addActionListener(fetch_models)
        
        def save_config(event):
            try:
                # 更新配置值
                self.api_url = self.url_field.getText()
                self.api_key = self.key_field.getText()
                self.model = str(self.model_combo.getSelectedItem())  # 从组合框获取选中的模型
                self.timeout_seconds = int(self.timeout_field.getText())
                self.max_request_length = int(self.req_length_field.getText())
                self.max_response_length = int(self.resp_length_field.getText())
                
                # 验证配置
                if not self.api_url or not self.api_key or not self.model:
                    JOptionPane.showMessageDialog(None, "API URL, API Key and Model cannot be empty!")
                    return
                    
                # 更新成功提示
                JOptionPane.showMessageDialog(None, "Configuration saved successfully!")
                
                # 记录更新到日志
                self.log("[+] Configuration updated:")
                self.log("  - API URL: {}".format(self.api_url))
                self.log("  - Model: {}".format(self.model))
                self.log("  - API Key: {}".format("*" * len(self.api_key)))
                
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error saving configuration: " + str(e))
                self.log("[-] Error saving configuration: {}".format(str(e)))
        
        def reset_config(event):
            if JOptionPane.showConfirmDialog(None, 
                "Are you sure you want to reset all settings to default values?",
                "Confirm Reset",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
                self.url_field.setText("https://openai.com/v1/chat/completions")
                self.key_field.setText("Please enter your API key")
                self.model_combo.removeAllItems()
                self.model_combo.addItem("gpt-4o")
                self.model_combo.setSelectedItem("gpt-4o")
                self.timeout_field.setText("60")
                self.req_length_field.setText("1000")
                self.resp_length_field.setText("2000")
                self.prompt_area.setText(self.get_default_prompt())
        
        save_button = JButton("Save Configuration")
        save_button.setToolTipText("Save current configuration")
        reset_button = JButton("Reset to Defaults")
        reset_button.setToolTipText("Reset all settings to default values")
        
        save_button.addActionListener(save_config)
        reset_button.addActionListener(reset_config)
        
        button_panel.add(save_button)
        button_panel.add(Box.createHorizontalStrut(10))  # 添加间距
        button_panel.add(reset_button)
        
        # 将所有面板添加到主配置面板
        main_constraints = GridBagConstraints()
        main_constraints.fill = GridBagConstraints.HORIZONTAL
        main_constraints.insets = Insets(5, 5, 5, 5)
        main_constraints.gridx = 0
        main_constraints.gridy = 0
        main_constraints.weightx = 1.0
        config_panel.add(api_panel, main_constraints)
        
        main_constraints.gridy = 1
        config_panel.add(limits_panel, main_constraints)
        
        main_constraints.gridy = 2
        main_constraints.weighty = 1.0
        main_constraints.fill = GridBagConstraints.BOTH
        config_panel.add(prompt_panel, main_constraints)
        
        main_constraints.gridy = 3
        main_constraints.weighty = 0.0
        main_constraints.fill = GridBagConstraints.HORIZONTAL
        config_panel.add(button_panel, main_constraints)
        
        return config_panel
        
    def get_default_prompt(self):
        return """Please analyze this HTTP request and response:

URL: {URL}
Method: {METHOD}

Request:
{REQUEST}

Response:
{RESPONSE}

Please identify any security issues and suggest fixes."""
        
    def create_results_panel(self):
        results_panel = JPanel(BorderLayout())
        
        # 创建分割面板
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setDividerLocation(200)
        
        # 创建工具栏面板
        toolbar = JPanel()
        clear_button = JButton("Clear Results")
        search_field = JTextField(20)
        search_button = JButton("Search")
        export_button = JButton("Export Results")
        
        # 创建列表模型和JList用于显示分析历史
        self.list_model = DefaultListModel()
        self.analysis_list = JList(self.list_model)
        analysis_scroll = JScrollPane(self.analysis_list)
        
        # 创建详细结果面板
        self.results_area = JTextArea()
        self.results_area.setEditable(False)
        results_scroll = JScrollPane(self.results_area)
        
        # 添加列表选择监听器
        class SelectionListener(ListSelectionListener):
            def __init__(self, outer):
                self.outer = outer
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    index = self.outer.analysis_list.getSelectedIndex()
                    if index >= 0:
                        result = self.outer.analysis_results[index]
                        self.outer.display_result_details(result)
        
        self.analysis_list.addListSelectionListener(SelectionListener(self))
        
        # 初始化结果存储列表
        self.analysis_results = []
        
        # 添加按钮事件
        def clear_results(event):
            self.list_model.clear()
            self.analysis_results = []
            self.results_area.setText("")
        clear_button.addActionListener(clear_results)
        
        def search_results(event):
            search_text = search_field.getText().lower()
            if search_text:
                for i in range(self.list_model.size()):
                    if search_text in self.list_model.getElementAt(i).lower():
                        self.analysis_list.setSelectedIndex(i)
                        self.analysis_list.ensureIndexIsVisible(i)
                        break
        search_button.addActionListener(search_results)
        
        def export_results(event):
            try:
                if self.analysis_results:
                    timestamp = java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(java.util.Date())
                    filename = "gpt_analysis_{}.txt".format(timestamp)
                    
                    # 使用 OutputStreamWriter 来指定编码
                    from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter
                    from java.nio.charset import StandardCharsets
                    
                    writer = BufferedWriter(
                        OutputStreamWriter(
                            FileOutputStream(filename),
                            StandardCharsets.UTF_8
                        )
                    )
                    
                    try:
                        # 写入导出信息头
                        writer.write("Enhanced BurpGPT Analysis Report\n")
                        writer.write("=" * 50 + "\n")
                        writer.write("Export Time: {}\n".format(timestamp))
                        writer.write("Total Results: {}\n".format(len(self.analysis_results)))
                        writer.write("=" * 50 + "\n\n")
                        
                        # 遍历每个分析结果
                        for index, result in enumerate(self.analysis_results, 1):
                            writer.write("Analysis #{}\n".format(index))
                            writer.write("-" * 30 + "\n")
                            writer.write("Time: {}\n".format(result.time))
                            writer.write("URL: {}\n".format(result.url))
                            writer.write("\nAnalysis Result:\n")
                            writer.write("-" * 30 + "\n")
                            writer.write(result.response)
                            writer.write("\n" + "=" * 50 + "\n\n")
                        
                        JOptionPane.showMessageDialog(None, "Results exported to {}".format(filename))
                        
                        # 在日志中记录导出信息
                        self.log("[+] Exported {} analysis results to {}".format(
                            len(self.analysis_results), filename))
                        
                    finally:
                        writer.close()
            
            except Exception as e:
                error_msg = "Export failed: {}".format(str(e))
                JOptionPane.showMessageDialog(None, error_msg)
                self.log("[-] " + error_msg)
        export_button.addActionListener(export_results)
        
        # 添加组件到工具栏
        toolbar.add(clear_button)
        toolbar.add(search_field)
        toolbar.add(search_button)
        toolbar.add(export_button)
        
        # 组装面板
        split_pane.setTopComponent(analysis_scroll)
        split_pane.setBottomComponent(results_scroll)
        
        results_panel.add(toolbar, BorderLayout.NORTH)
        results_panel.add(split_pane, BorderLayout.CENTER)
        
        return results_panel
        
    def send_to_gpt(self, invocation):
        try:
            # 添加时间戳检查，防止短时间内重复触发
            current_time = System.currentTimeMillis()
            if hasattr(self, '_last_trigger_time') and (current_time - self._last_trigger_time < 1000):  # 1秒内不重复触发
                self.log("[*] Ignoring duplicate trigger")
                return
            self._last_trigger_time = current_time
            
            self.log("[+] Send to GPT method called - Thread: " + str(Thread.currentThread().getName()))
            http_msgs = invocation.getSelectedMessages()
            self.log("[+] Selected messages: {}".format(len(http_msgs)))
            
            if http_msgs and len(http_msgs) == 1:
                msg = http_msgs[0]
                request = msg.getRequest()
                response = msg.getResponse()
                url = msg.getUrl().toString()
                
                self.log("[+] Processing URL: {}".format(url))
                
                # 创建进度对话框
                progress_dialog = JDialog()
                progress_dialog.setTitle("Analyzing...")
                progress_dialog.setSize(300, 100)
                progress_dialog.setLocationRelativeTo(None)
                progress_dialog.setLayout(BorderLayout())
                
                progress_bar = JProgressBar()
                progress_bar.setIndeterminate(True)
                label = JLabel("GPT is analyzing the request/response...", SwingUtilities.CENTER)
                progress_dialog.add(label, BorderLayout.NORTH)
                progress_dialog.add(progress_bar, BorderLayout.CENTER)
                
                # 创建一个实现Runnable接口的类
                class AsyncTask(Runnable):
                    def __init__(self, outer):
                        self.outer = outer
                    
                    def run(self):
                        try:
                            self.outer.log("[+] AsyncTask started - Thread: " + str(Thread.currentThread().getName()))
                            SwingUtilities.invokeLater(lambda: progress_dialog.setVisible(True))
                            
                            self.outer.log("[+] Creating GPT request")
                            gpt_request = GPTRequest(self.outer._helpers, msg, self.outer.model, self.outer.max_tokens)
                            gpt_request.set_prompt(self.outer.prompt_area.getText())
                            
                            self.outer.log("[+] Sending request to GPT API")
                            
                            # 发送请求
                            gpt_response = self.outer.call_gpt_api(gpt_request)
                            
                            self.outer.log("[+] Received response from GPT API")
                            
                            def update_ui():
                                try:
                                    self.outer.log("[+] Updating UI - Thread: " + str(Thread.currentThread().getName()))
                                    # 关闭进度对话框
                                    progress_dialog.dispose()
                                    
                                    if isinstance(gpt_response, GPTResponse):
                                        content = gpt_response.get_content()
                                        usage = gpt_response.get_token_usage()
                                        
                                        if content:
                                            self.outer.update_results(url, content, usage)
                                        else:
                                            self.outer.update_results(url, "No valid analysis result received.", {
                                                "prompt_tokens": 0, 
                                                "completion_tokens": 0, 
                                                "total_tokens": 0
                                            })
                                    else:
                                        error_msg = "Error: {}".format(str(gpt_response))
                                        self.outer.update_results(url, error_msg, {
                                            "prompt_tokens": 0, 
                                            "completion_tokens": 0, 
                                            "total_tokens": 0
                                        })
                                    
                                    self.outer.log("[+] UI updated successfully")
                                    
                                except Exception as e:
                                    self.outer.log("[-] Error in update_ui: {}".format(str(e)))
                            
                            # 确保在EDT线程中更新UI
                            SwingUtilities.invokeLater(update_ui)
                            
                        except Exception as e:
                            self.outer.log("[-] Error in run_async: {}".format(str(e)))
                            SwingUtilities.invokeLater(lambda: progress_dialog.dispose())
                            SwingUtilities.invokeLater(lambda: self.outer.results_area.append(
                                "\n[-] Error: {}\n\n".format(str(e))))
                
                # 使用正确的方式创建和启动线程
                self.log("[+] Starting AsyncTask thread")
                Thread(AsyncTask(self)).start()
                
            else:
                self.log("[-] No message selected or multiple messages selected")
            
        except Exception as e:
            self.log("[-] Error in send_to_gpt: {}".format(str(e)))
            
    def truncate_content(self, content, max_length):
        """智能截断内容，保留头部信息和部分正文"""
        if not content:
            return ""
            
        content_str = self._helpers.bytesToString(content)
        
        if len(content_str) <= max_length:
            return content_str
            
        # 分离头部和正文
        headers_end = content_str.find("\r\n\r\n")
        if headers_end == -1:
            # 没有找到头部分隔符，直接截断
            return content_str[:max_length] + "\n... (content truncated)"
            
        headers = content_str[:headers_end]
        body = content_str[headers_end+4:]
        
        # 计算剩余可用长度
        remaining_length = max_length - len(headers) - 50  # 预留50字符给提示信息
        
        if remaining_length <= 0:
            # 如果头部已经超过限制，只保留部分头部
            return content_str[:max_length] + "\n... (content truncated)"
            
        # 截断正文
        truncated_body = body[:remaining_length]
        
        return "{}\r\n\r\n{}\n... (content truncated, total length: {})".format(
            headers,
            truncated_body,
            len(content_str)
        )
        
    def build_prompt(self, request, response):
        """使用截断后的请求和响应构建提示词"""
        truncated_request = self.truncate_content(request, self.max_request_length)
        truncated_response = self.truncate_content(response, self.max_response_length)
        
        return self.prompt_area.getText().format(
            truncated_request,
            truncated_response
        )
                  
    def call_gpt_api(self, gpt_request):
        try:
            # 构造请求数据，使用当前配置的模型名称
            data = {
                "model": self.model,  # 使用配置中的模型
                "messages": [
                    {
                        "role": "user",
                        "content": gpt_request.prompt
                    }
                ],
                "max_tokens": self.max_tokens
            }
            
            # 转换为JSON
            json_data = json.dumps(data).encode('utf-8')
            
            # 从配置中获取Host
            host = self.api_url.split("://")[-1].split("/")[0]
            
            # 请求头
            headers = {
                "Host": host,
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.api_key,  # 使用配置中的API key
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.215",
                "Accept-Language": "zh-CN"
            }
            
            self.log("[+] Sending request to {}".format(self.api_url))  # 使用配置中的API URL
            
            # 创建请求
            request = urllib2.Request(
                url=self.api_url,  # 使用配置中的API URL
                data=json_data,
                headers=headers
            )
            
            # 设置超时
            response = urllib2.urlopen(request, timeout=self.timeout_seconds)
            
            # 读取原始响应数据
            response_data = response.read()
            
            try:
                # 尝试不同的编码方式
                for encoding in ['utf-8', 'gbk', 'gb2312', 'iso-8859-1']:
                    try:
                        response_text = response_data.decode(encoding)
                        # 如果成功解码，就使用这个结果
                        break
                    except:
                        continue
                
                # 解析JSON
                result = json.loads(response_text)
                return GPTResponse(result)
                
            except Exception as decode_error:
                # 如果所有编码都失败了，打印原始数据的十六进制
                self.log("[-] Raw response (hex): " + response_data.hex())
                raise decode_error
            
        except urllib2.HTTPError as e:
            error_body = e.read()
            try:
                error_text = error_body.decode('utf-8')
            except:
                error_text = str(error_body)
            self.log("[-] HTTP Error Response: " + error_text)
            raise Exception("Error calling GPT API: " + str(e))
        except Exception as e:
            self.log("[-] Error: " + str(e))
            raise Exception("Error calling GPT API: " + str(e))
    
    def getTabCaption(self):
        return "GPT Analysis"
        
    def getUiComponent(self):
        return self.tab

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Send to GPT")
        menu_item.addActionListener(lambda x: self.send_to_gpt(invocation))
        menu_list.add(menu_item)
        return menu_list

    def log(self, message):
        # 输出到Burp的标准输出
        self.stdout.println(message)
        # 输出到日志面板
        if hasattr(self, 'log_area'):
            SwingUtilities.invokeLater(lambda: self.log_area.append(message + "\n"))
            SwingUtilities.invokeLater(lambda: self.log_area.setCaretPosition(self.log_area.getDocument().getLength()))

    def update_results(self, url, content, usage):
        """更新结果显示"""
        timestamp = java.text.SimpleDateFormat("HH:mm:ss").format(java.util.Date())
        
        # 创建新的分析结果对象
        result = AnalysisResult(timestamp, url, content)
        
        # 添加到结果列表
        self.analysis_results.append(result)
        
        # 更新列表显示
        self.list_model.addElement("[{}] {}".format(timestamp, url))
        
        # 选中新添加的项
        last_index = self.list_model.size() - 1
        self.analysis_list.setSelectedIndex(last_index)
        self.analysis_list.ensureIndexIsVisible(last_index)

    def display_result_details(self, result):
        """显示选中结果的详细信息"""
        self.results_area.setText("")
        self.results_area.append("="*50 + "\n")
        self.results_area.append("Analysis Time: {}\n".format(result.time))
        self.results_area.append("Target URL: {}\n".format(result.url))
        self.results_area.append("-"*50 + "\n")
        self.results_area.append(result.response + "\n")
        self.results_area.append("="*50 + "\n")
        self.results_area.setCaretPosition(0)

class GPTRequest:
    def __init__(self, helpers, http_message, model, max_prompt_size):
        try:
            # 获取请求信息
            request_info = helpers.analyzeRequest(http_message)
            
            # 获取基本信息
            self.url = str(http_message.getUrl())
            self.method = str(request_info.getMethod())
            
            # 获取请求和响应
            request_bytes = http_message.getRequest()
            self.request = helpers.bytesToString(request_bytes)
            
            response_bytes = http_message.getResponse()
            self.response = helpers.bytesToString(response_bytes) if response_bytes else ""
            
            self.model = model
            self.max_prompt_size = max_prompt_size
            self.prompt = None
            
        except Exception as e:
            raise Exception("Error initializing GPTRequest: " + str(e))

    def set_prompt(self, prompt_template):
        try:
            # 构建提示词
            prompt = prompt_template
            
            # 替换占位符
            prompt = prompt.replace("{URL}", self.url)
            prompt = prompt.replace("{METHOD}", self.method)
            prompt = prompt.replace("{REQUEST}", self.request)
            prompt = prompt.replace("{RESPONSE}", self.response)
            
            # 截断过长的内容
            if len(prompt) > self.max_prompt_size:
                prompt = prompt[:self.max_prompt_size]
            
            self.prompt = prompt
            return prompt
            
        except Exception as e:
            raise Exception("Error setting prompt: " + str(e))

    def log(self, message):
        if hasattr(self, '_callbacks'):
            stdout = self._callbacks.getStdout()
            if stdout:
                writer = PrintWriter(stdout, True)
                writer.println(message)

class GPTResponse:
    def __init__(self, raw_response):
        self.raw_response = raw_response
        self.choices = raw_response.get("choices", [])
        self.usage = raw_response.get("usage", {})
        
    def get_content(self):
        if self.choices and len(self.choices) > 0:
            return self.choices[0]["message"]["content"]
        return None
        
    def get_token_usage(self):
        return {
            "prompt_tokens": self.usage.get("prompt_tokens", 0),
            "completion_tokens": self.usage.get("completion_tokens", 0),
            "total_tokens": self.usage.get("total_tokens", 0)
        }

class AnalysisResult:
    def __init__(self, time, url, response):
        self.time = time
        self.url = url
        self.response = response
        self.severity = "Information"
        self.notes = ""
        
    def __str__(self):
        return "[{}] {}".format(self.time, self.url)
