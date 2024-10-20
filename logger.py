import logging

# 定义颜色
class ColoredFormatter(logging.Formatter):
    # ANSI 转义序列定义颜色
    COLOR_CODES = {
        'DEBUG': '\033[94m',    # 蓝色
        'INFO': '\033[92m',     # 绿色
        'WARNING': '\033[93m',  # 黄色
        'ERROR': '\033[91m',    # 红色
        'CRITICAL': '\033[95m', # 洋红色
    }
    RESET_CODE = '\033[0m'  # 重置颜色

    def format(self, record):
        log_color = self.COLOR_CODES.get(record.levelname, self.RESET_CODE)  # 根据日志级别设置颜色
        message = super().format(record)  # 获取原始日志消息
        return f"{log_color}{message}{self.RESET_CODE}"  # 返回带颜色的日志

# 配置日志输出
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(filename)s[line:%(lineno)d] \t-%(levelname)s:\t %(message)s',
    handlers=[logging.StreamHandler()]
)

# 创建自定义带颜色的格式化器
colored_formatter = ColoredFormatter('%(asctime)s - %(filename)s[line:%(lineno)d] \t-%(levelname)s:\t %(message)s')

# 设置处理器
console_handler = logging.StreamHandler()
console_handler.setFormatter(colored_formatter)

# 获取根日志记录器并添加带颜色的处理器
logger = logging.getLogger()
logger.handlers = []  # 清除默认的处理器
logger.addHandler(console_handler)