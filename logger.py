"""
日志模块

使用方式：
    from logger import log
    log.info('程序启动')
    log.warn('密钥长度不足')
    log.error('解密失败', exception=True)  # 附带异常栈
"""

import os
import logging
import utils
from logging.handlers import RotatingFileHandler
from datetime import datetime

class _LoggerManager:
    """日志管理器（单例）"""

    _instance = None
    _logger = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init_logger()
        return cls._instance

    def _init_logger(self):
        """初始化 logger：控制台 + 滚动文件双输出"""
        self._logger = logging.getLogger("mmbox")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False  # 防止重复输出到 root logger

        # 如果已经有 handler 了（二次初始化场景），先清空避免重复
        if self._logger.handlers:
            return

        # 日志格式：时间 - 级别 - 消息
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # ---------- 1. 控制台输出（调试用，仅 WARNING 及以上）----------
        try:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.WARNING)
            console_handler.setFormatter(formatter)
            self._logger.addHandler(console_handler)
        except Exception:
            pass  # 某些无控制台环境失败无所谓

        # ---------- 2. 文件输出（DEBUG 及以上，按大小滚动）----------
        try:
            log_dir = utils.Utils.get_exe_dir()
            # 日志文件名：mmbox_YYYYMMDD.log（每天自动换文件名，也可按大小滚动）
            date_str = datetime.now().strftime("%Y%m%d")
            log_file = os.path.join(log_dir, f"mmbox_{date_str}.log")

            # 滚动文件：单个日志最大 5MB，最多保留 10 份，超过自动覆盖旧的
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=5 * 1024 * 1024,   # 5MB
                backupCount=10,
                encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)
        except Exception as e:
            # 日志文件初始化失败不影响主程序，尝试在控制台简单提示
            try:
                print(f"[LOGGER_WARN] 日志文件创建失败: {e}")
            except Exception:
                pass

    # -------- 对外接口 --------

    def info(self, message):
        """普通信息记录"""
        try:
            self._logger.info(str(message))
        except Exception:
            pass

    def warn(self, message):
        """警告信息"""
        try:
            self._logger.warning(str(message))
        except Exception:
            pass

    def warning(self, message):
        """警告信息（别名，兼容 logging 风格）"""
        self.warn(message)

    def error(self, message, exception=False):
        """
        错误信息
        :param message: 错误消息
        :param exception: 是否同时记录当前异常栈（在 except 块中使用时传 True）
        """
        try:
            if exception:
                self._logger.error(str(message), exc_info=True)
            else:
                self._logger.error(str(message))
        except Exception:
            pass

    def debug(self, message):
        """调试信息（默认不输出到控制台，只写文件）"""
        try:
            self._logger.debug(str(message))
        except Exception:
            pass


# ============================================================
# 对外导出统一实例：使用方直接 `from logger import log` 即可
# ============================================================
log = _LoggerManager()


# 快速测试（直接运行本文件看效果）
# if __name__ == "__main__":
#     log.info("这是一条 INFO 日志")
#     log.warn("这是一条 WARN 日志")
#     log.error("这是一条 ERROR 日志")
#     try:
#         1 / 0
#     except Exception:
#         log.error("发生除零异常", exception=True)