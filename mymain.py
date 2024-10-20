# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QApplication

import sys
from table import  DynamicTable, MyTableModel
from device_mm import select_device
import subprocess
from logger import logging, logger
from scapy.all import Packet, raw, PcapReader
from util import hexdump_bytes, packet2dict
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
        self.filter_part4 = QtWidgets.QLineEdit(bar)

        # 设置合适的大小策略和最大高度
        for part in [self.start_button, self.end_button, self.filter_exp, self.filter_part4]:
            part.setMaximumHeight(30)
            part.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

        # 添加控件到布局
        self.filter_layout.addWidget(self.start_button)  # Start button
        self.filter_layout.addWidget(self.end_button)  # End button
        self.filter_layout.addWidget(self.filter_exp)  # Line Edit 2
        self.filter_layout.addWidget(self.filter_part4)  # Line Edit 3

        # 使用 QSpacerItem 来调整比例
        spacer1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        spacer2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)

        # 添加间隔项，调整控件宽度比例
        self.filter_layout.addItem(spacer1)  # 在第一个和第二个控件之间
        self.filter_layout.addItem(spacer2)  # 在第二个和第三个控件之间

        # 将 container 添加到 splitter_2
        self.splitter_2.addWidget(bar)

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



# 数据逻辑应该被迁移到这里
class MainWindow(QtWidgets.QMainWindow):

    def set_dynamic_table(self, item_list):
        self.headers = ["count", "ts", "src1", "dst1", "src2", "dst2", "info"]
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
        # Set up the menu bar
        self.setupMenu()
        # Maximize the form
        self.showMaximized()
        
        # 同步计时器
        self.update_timer = QtCore.QTimer(self)
        self.update_timer.setInterval(1000)  # 每1秒同步一次数据
        self.update_timer.timeout.connect(self.sync_data)
        # 过滤表达式
        self.ui.filter_exp.returnPressed.connect(self.enter_exp_event)
    
    def start_new_listen(self):
        self.tabe_model.delete_all_data()
        out_file = "tmp.pcap"
        dev = select_device()
        bpf = ""
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
        # 开启同步
        self.update_timer.start()

    def stop_listen(self):
        # 结束同步
        logger.info("try stop listen")
        self.update_timer.stop()
        self.subp.stdin.write("2\n")
        self.subp.stdin.flush()
        self.subp.wait()
        self.subp=None
        self.reader=None

        
    def sync_data(self):
        """定期同步两个进程的数据,并更新表格"""
        # 询问大小
        #define SIGUSR 25
        
        self.subp.stdin.write("1\n")
        self.subp.stdin.flush()  # 刷新缓冲区，确保数据立即发送到子进程
        output = self.subp.stdout.readline().strip()
        value = int(output)
        count = value - self.last_item
        assert(count>=0)
        if count==0:
            return
        
        for index in range(self.last_item, value):
            self.item_list.append((index, next(self.reader)))
        self.last_item = value
        self.dynamic_table.update_table()
        logger.debug(f"sync {count} packets end")
    def setupMenu(self):
        # Create a menu bar
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")
        
        # Adding actions to the File menu
        exit_action = QtWidgets.QAction("Exit", self)
        exit_action.triggered.connect(self.close)  # Close the application
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")
        
        # Additional edit actions can be added here
        # Example: edit_action = QtWidgets.QAction("Edit Item", self)
        # edit_menu.addAction(edit_action)
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
    window.start_new_listen()
    app.exec_()
    window.stop_listen()