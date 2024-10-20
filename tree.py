from PyQt5.QtWidgets import QApplication, QTreeView, QWidget, QVBoxLayout
from PyQt5.QtGui import  QStandardItemModel, QStandardItem
class DictTree(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        self.tree_view = QTreeView()
        self.model = QStandardItemModel()
        
        self.tree_view.setModel(self.model)
        self.tree_view.header().hide()
        layout = QVBoxLayout()
        layout.addWidget(self.tree_view)
        self.setLayout(layout)

    def update_dict(self, data_dict):
        # 删除旧数据
        self.model.clear()
        # 渲染新数据
        self.populate_tree(self.model.invisibleRootItem(), data_dict)
        self.tree_view.expandAll()

    def populate_tree(self, parent, dictionary):
        """递归渲染嵌套字典"""
        for key, value in dictionary.items():
            key_item = QStandardItem(str(key))
            if isinstance(value, dict):
                value_item = QStandardItem("")
                parent.appendRow([key_item, value_item])
                self.populate_tree(key_item, value)
            else:
                value_item = QStandardItem(str(value))
                parent.appendRow([key_item, value_item])