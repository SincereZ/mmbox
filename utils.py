import os
import sys
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import constants

class Utils:
    """公共工具类 - 只包含通用方法"""
    
    @staticmethod
    def get_base_path():
        """获取程序基础路径（支持PyInstaller打包）"""
        try:
            return sys._MEIPASS
        except Exception:
            return os.path.abspath(".")
    
    @staticmethod
    def get_exe_dir():
        """获取可执行文件所在目录"""
        return os.path.dirname(os.path.abspath(
            sys.executable if getattr(sys, 'frozen', False) else __file__
        ))
    
    @staticmethod
    def get_config_path():
        """获取配置文件完整路径"""
        return os.path.join(Utils.get_exe_dir(), constants.CONFIG_FILE)
    
    @staticmethod
    def get_data_path():
        """获取数据文件完整路径"""
        return os.path.join(Utils.get_exe_dir(), constants.DATA_FILE)
    
    @staticmethod
    def center_window(window, master, width, height):
        """将窗口居中显示在主窗口中央（无闪烁）"""
        was_visible = window.winfo_viewable()
        if was_visible:
            window.withdraw()
        
        window.update_idletasks()
        
        master_x = master.winfo_x()
        master_y = master.winfo_y()
        master_width = master.winfo_width()
        master_height = master.winfo_height()
        
        x = master_x + (master_width - width) // 2
        y = master_y + (master_height - height) // 2
        
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        
        if x + width > screen_width:
            x = screen_width - width - 10
        if y + height > screen_height:
            y = screen_height - height - 10
        if x < 0:
            x = 10
        if y < 0:
            y = 10
        
        window.geometry(f"{width}x{height}+{int(x)}+{int(y)}")
        
        if was_visible:
            window.deiconify()
    
    @staticmethod
    def setup_window_icon(window):
        """设置窗口图标"""
        try:
            base_path = Utils.get_base_path()
            window.iconbitmap(os.path.join(base_path, constants.ICON_FILE))
        except Exception:
            pass
    
    @staticmethod
    def encrypt_field(key, text):
        """AES加密"""
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
    
    @staticmethod
    def decrypt_field(key, text):
        """AES解密"""
        data = base64.b64decode(text)
        iv, ct = data[:AES.block_size], data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')