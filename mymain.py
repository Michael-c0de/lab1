# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication, QMessageBox, QInputDialog

import sys
from table import  DynamicTable, MyTableModel
from device_mm import PcapDeviceManager
import subprocess
from logger import logging, logger
from scapy.all import Packet, raw, PcapReader
from util import hexdump_bytes, packet2dict, check_bpf_filter_validity
import tree
import os
logger.setLevel(logging.DEBUG)

class Ui_Form(object):
    def setupUi(self, Form, dynamic_table):
        
        Form.setObjectName("Form")
        # Use a vertical layout for the main form
        main_layout = QtWidgets.QVBoxLayout(Form)
        
        self.splitter_2 = QtWidgets.QSplitter(Form)
        self.splitter_2.setOrientation(QtCore.Qt.Vertical)
        self.splitter_2.setObjectName("splitter_2")

        # 创建一个 QWidget 作为容器
        bar = QtWidgets.QWidget(self.splitter_2)

        # 创建一个水平布局来容纳四个控件
        self.filter_layout = QtWidgets.QHBoxLayout(bar)

        # 设置边距和间距
        self.filter_layout.setContentsMargins(0, 0, 0, 0)  # 设置边距为0
        self.filter_layout.setSpacing(0)  # 设置布局间距为0

        # 创建四个控件
        self.start_button = QtWidgets.QPushButton("开始", bar)
        self.end_button = QtWidgets.QPushButton("结束", bar)

        self.filter_exp = QtWidgets.QLineEdit(bar)
        self.filter_exp.setPlaceholderText("实时过滤器")

        # 设置合适的大小策略和最大高度
        for part in [self.start_button, self.end_button, self.filter_exp]:
            part.setMaximumHeight(30)
            part.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

        # 添加控件到布局
        self.filter_layout.addWidget(self.start_button)  # Start button
        self.filter_layout.addWidget(self.end_button)  # End button
        self.filter_layout.addWidget(self.filter_exp)  # Line Edit 2




        # 将 container 添加到 splitter_2
        self.splitter_2.addWidget(bar)

        # self.filter_exp = QLineEdit(self.splitter_2)
        # self.filter_exp.setMaximumHeight(30)
        self.dynamic_table = dynamic_table
        self.dynamic_table.setObjectName("dynamicTable")

        # Use a horizontal splitter for the text browsers
        self.splitter = QtWidgets.QSplitter(self.splitter_2)
        self.splitter.setOrientation(QtCore.Qt.Horizontal)
        self.splitter.setObjectName("splitter")

        self.textBrowser = tree.DictTree(self.splitter)
        self.textBrowser.setObjectName("textBrowser")
        self.textBrowser.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        self.textBrowser_2 = QtWidgets.QTextBrowser(self.splitter)
        self.textBrowser_2.setObjectName("textBrowser_2")
        self.textBrowser_2.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)

        # Add the splitter to the main layout
        main_layout.addWidget(self.splitter_2)
        # Add widgets to the splitter
        # self.splitter_2.addWidget(self.filter_exp)
        self.splitter_2.addWidget(self.dynamic_table)
        self.splitter_2.addWidget(self.splitter)

        self.splitter.addWidget(self.textBrowser)
        self.splitter.addWidget(self.textBrowser_2)

        # Set the stretch factors to allow height adjustment
        self.splitter.setSizes([1, 1])  # Equal space for text browsers

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))

import time
from PyQt5.QtCore import QThread, pyqtSignal

class SyncThread(QThread):
    data_synced = pyqtSignal(int)  # 用于通知主线程同步的数量

    def __init__(self, subp, reader, last_item, item_list, dynamic_table):
        super().__init__()
        self.subp = subp
        self.reader = reader
        self.last_item = last_item
        self.item_list = item_list
        self.dynamic_table = dynamic_table
        self.running = True  # 控制线程运行状态

    def run(self):
        """线程的主要逻辑，持续同步数据"""
        while self.running:
            # 每次同步前可以加一个时间间隔，比如 1 秒
            self.sync_data()  # 执行同步操作
            time.sleep(1)  # 设置同步的频率，每 1 秒同步一次

    def sync_data(self):
        """执行实际的数据同步逻辑"""
        # 询问缓冲区大小
        self.subp.stdin.write("1\n")
        self.subp.stdin.flush()  # 刷新缓冲区，确保数据立即发送到子进程
        output = self.subp.stdout.readline().strip()
        value = int(output)
        count = value - self.last_item
        assert(count >= 0)
        if count == 0:
            return
        # 限制同步数量
        if count > 1000:
            count = 1000
        # 同步数据
        for index in range(self.last_item, self.last_item + count):
            self.item_list.append((index, next(self.reader)))
        self.last_item += count
        # 更新表格
        # self.dynamic_table.update_table()
        # 发出信号通知主线程
        self.data_synced.emit(count)

    def stop(self):
        """停止线程的运行"""
        self.running = False




# 数据逻辑应该被迁移到这里
class MainWindow(QtWidgets.QMainWindow):

    def set_dynamic_table(self, item_list):
        self.headers = ["count", "src1", "dst1", "src2", "dst2", "info"]
        self.tabe_model = MyTableModel([], self.headers)
        self.dynamic_table = DynamicTable(item_list, self.tabe_model)

        self.dynamic_table.table_view.clicked.connect(self.click_item_event)

    def set_data(self, packet:Packet):
        self.ui.textBrowser.update_dict(packet2dict(packet))

    def set_raw_data(self, packet:bytes):
        self.ui.textBrowser_2.setText(hexdump_bytes(packet))
    
    def __init__(self):
        super().__init__()
        self.item_list = []
        self.reader = None
        self.subp = None
        
        # table, item_list为表格渲染数据来源
        self.set_dynamic_table(self.item_list)
        # Create the Form UI
        self.form_widget = QtWidgets.QWidget()
        self.setCentralWidget(self.form_widget)
        self.ui = Ui_Form()
        self.ui.setupUi(self.form_widget, self.dynamic_table)

        self.cur_dev_name = None
        self.dev_mm = PcapDeviceManager()
        self.bpf_exp = ""
        # Set up the menu bar
        self.setupMenu()
        # Maximize the form
        self.showMaximized()
        

        # 过滤表达式
        self.ui.filter_exp.returnPressed.connect(self.enter_exp_event)
        # 开始捕获
        self.ui.start_button.clicked.connect(self.start_new_listen)
        # 结束捕获
        self.ui.end_button.clicked.connect(self.stop_listen)
        
    def start_new_listen(self):
        if self.subp!=None:
            QMessageBox.information(self,"警告","您必须先停止正在进行的抓包，才能开始新的抓包")
            return
        # 清空数据模型
        self.tabe_model.delete_all_data()
        # 删除缓存
        self.dynamic_table.arrive_list.clear()
        self.dynamic_table.filter_exp = None

        out_file = "tmp.pcap"
        dev = self.cur_dev_name
        bpf = self.bpf_exp
        if os.path.exists(out_file):
            os.remove(out_file)
        self.subp = subprocess.Popen(
            args=["main.exe", dev, out_file, bpf],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            )
        
        while not os.path.exists(out_file):
            pass
        self.reader = PcapReader(out_file)
        
        self.last_item = 1
        # 启动同步线程
        self.sync_thread = SyncThread(self.subp, self.reader, self.last_item, self.item_list, self.dynamic_table)
        self.sync_thread.data_synced.connect(self.on_data_synced)  # 连接信号
        self.sync_thread.start()  # 启动线程
        logger.info(f"start listen {self.subp.pid}")
    
    def on_data_synced(self, count):
        """同步完成后更新界面或其他操作"""
        logger.info(f"sync {count} packet")
        self.dynamic_table.update_table()
    
    def stop_listen(self):
        if self.subp==None:
            QMessageBox.information(self,"警告","抓包已经结束，或从未开始")
            return
        # 结束同步
        self.subp.stdin.write("2\n")
        self.subp.stdin.flush()
        self.subp.wait()
        self.reader.close()
        logger.info(f"stop  listen {self.subp.pid}")
        self.subp=None
        self.reader=None
        self.sync_thread.stop()
        self.sync_thread.wait()  # 等待线程完全结束
        
        logger.info("sync thread end")

    # def sync_data(self):
    #     """定期同步两个进程的数据,并更新表格"""
    #     # 询问缓冲区大小
    #     self.subp.stdin.write("1\n")
    #     self.subp.stdin.flush()  # 刷新缓冲区，确保数据立即发送到子进程
    #     output = self.subp.stdout.readline().strip()
    #     value = int(output)
    #     count = value - self.last_item
    #     assert(count>=0)
    #     if count==0:
    #         return
    #     # 限制数量
    #     if count>1000:
    #         count=1000
    #     for index in range(self.last_item, self.last_item + count):
    #         self.item_list.append((index, next(self.reader)))
    #     self.last_item += count
    #     self.dynamic_table.update_table()
    #     logger.debug(f"sync {count} packets end")
    
    def show_input_dialog(self):
        # 弹出输入对话框
        text, ok = QInputDialog.getText(self, "BPF过滤", "输入BPF过滤表达式")
        if ok and text:
            if check_bpf_filter_validity(text):
                QMessageBox.information(self, "BPF过滤", f"设置BPF过滤器为{text}")
                self.bpf_exp = text
            else:
                QMessageBox.information(self, "BPF过滤", "表达式不合法")
    def setupMenu(self):
        # Create a menu bar
        menubar = self.menuBar()

        self.file = menubar.addMenu("文件")
        self.bpf = menubar.addMenu("BPF过滤器")
        self.dev_menu = menubar.addMenu("网卡")

        input_action = self.bpf.addAction("输入BPF表达式")
        input_action.triggered.connect(self.show_input_dialog)
        self.dev_mm.find_all_devices()
        for index, name, addr in self.dev_mm.list_devices():
            self.dev_menu.addAction(f"{index+1}.{name}\t{addr}")
        #默认选择第一个网卡
        self.cur_dev_name = self.dev_mm.get_device(0)
        self.dev_menu.triggered.connect(self.select_dev)

        # Adding actions to the File menu
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)  # Close the application
        # Edit menu
        edit_menu = menubar.addMenu("Edit")

    
    def select_dev(self, Item=None):
        value = Item.text()
        index = int(value.split(".")[0])-1
        cur_dev_name = self.dev_mm.get_device(index)
        self.cur_dev_name = cur_dev_name
        QMessageBox.information(self, "设备选择", f"监听网卡{value}")
        
    def click_item_event(self, Item=None):
        # 如果单元格对象为空
        if Item is None:
            return
        row = Item.row()
        # col = Item.column()
        id = int(self.tabe_model.index(row, 0).data())
        logger.info(f"click item {id}")
        packet = self.dynamic_table.arrive_list[id-1][1]
        self.set_data(packet)
        raw_byets = raw(packet)
        self.set_raw_data(raw_byets)
        
    def enter_exp_event(self):
        # 处理回车事件
        text = self.ui.filter_exp.text()
        logger.info(f"enter bpf exp {text}")

        self.dynamic_table.filter_exp = text
        self.dynamic_table.offset = 0
        self.tabe_model.delete_all_data()
        self.dynamic_table.update_table()
    


    
if __name__ == "__main__":
    # 启动Qt应用
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
    if window.subp!=None:
        window.stop_listen()
    sys.exit()
