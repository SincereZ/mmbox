import tkinter as tk
from tkinter import ttk, messagebox
import os
import json
import re
import utils
import constants
from models import AppConfig

class InitDialog:
    """初始化对话框"""
    
    def __init__(self, master, exe_dir):
        self.master = master
        self.exe_dir = exe_dir
        self.result = False
        
        self.dialog = tk.Toplevel(master)
        self.dialog.title("初始化 - 设置密钥")
        self.dialog.resizable(False, False)
        self.dialog.transient(master)
        self.dialog.grab_set()
        
        utils.Utils.setup_window_icon(self.dialog)
        self.create_widgets()
        utils.Utils.center_window(self.dialog, master, constants.DIALOG_WIDTH, constants.DIALOG_HEIGHT)

        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        master.wait_window(self.dialog)
    
    def create_widgets(self):
        """创建界面组件"""
        ttk.Label(self.dialog, text="首次使用，请设置16位密钥（数字+字母组合）").grid(
            row=0, column=0, columnspan=2, padx=5, pady=(15, 5)
        )
        
        ttk.Label(self.dialog, text="密钥:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.key_entry = ttk.Entry(self.dialog, show="*", width=30)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        self.hint_label = ttk.Label(self.dialog, text="请输入16位数字和字母", foreground="gray")
        self.hint_label.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.key_entry.bind("<KeyRelease>", self.validate_key)
        
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=15)
        
        ttk.Button(
            button_frame, 
            text="确定", 
            command=self.on_confirm, 
            bootstyle="success"
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            button_frame, 
            text="取消", 
            command=self.on_cancel, 
            bootstyle="warning"
        ).pack(side=tk.LEFT, padx=10)
        
        self.key_entry.focus_set()
    
    def validate_key(self, event=None):
        """验证密钥输入"""
        key = self.key_entry.get()
        
        if key and not re.match(r'^[A-Za-z0-9]+$', key):
            valid_key = re.sub(r'[^A-Za-z0-9]', '', key)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, valid_key)
            key = valid_key
        
        if len(key) > constants.KEY_LENGTH:
            self.key_entry.delete(constants.KEY_LENGTH, tk.END)
        
        if len(key) == 0:
            self.hint_label.config(text=f"请输入{constants.KEY_LENGTH}位数字和字母", foreground="gray")
        elif len(key) < constants.KEY_LENGTH:
            self.hint_label.config(text=f"还需要 {constants.KEY_LENGTH - len(key)} 个字符", foreground="orange")
        else:
            self.hint_label.config(text="✓ 密钥长度符合要求", foreground="green")
    
    def on_confirm(self):
        """确认初始化"""
        key = self.key_entry.get()
        
        if len(key) != constants.KEY_LENGTH:
            messagebox.showerror("错误", f"密钥必须为{constants.KEY_LENGTH}位", parent=self.dialog)
            return
        
        if not re.match(r'^[A-Za-z0-9]+$', key):
            messagebox.showerror("错误", "密钥只能包含数字和字母", parent=self.dialog)
            return
        
        try:
            # 创建数据文件
            data_file_path = self.create_data_file(self.exe_dir, key)
            
            # 创建配置对象并保存
            config = AppConfig(
                data_file=data_file_path
            )
            self.save_config(config)
            
            messagebox.showinfo("成功", "初始化完成！数据文件路径：" + data_file_path, parent=self.dialog)
            self.result = True
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("错误", f"初始化失败: {str(e)}", parent=self.dialog)
    
    def on_cancel(self):
        """取消初始化"""
        if messagebox.askyesno("确认", "确定要退出吗？", parent=self.dialog):
            self.dialog.destroy()
            self.master.destroy()
    
    @staticmethod
    def create_data_file(exe_dir, master_key):
        """创建数据文件"""
        data_file_path = os.path.join(exe_dir, 'data.dat')
        key_bytes = master_key.encode('utf-8')
        
        with open(data_file_path, 'w', encoding='utf-8') as f:
            encrypted_empty = utils.Utils.encrypt_field(key_bytes, json.dumps([]))
            f.write(encrypted_empty)
        
        return data_file_path
    
    @staticmethod
    def load_config():
        """加载配置文件，返回 AppConfig 对象"""
        exe_dir = utils.Utils.get_exe_dir()
        config_path = os.path.join(exe_dir, 'mmbox.ini')
        
        if not os.path.exists(config_path):
            return None
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return AppConfig.from_dict(data)
        except Exception:
            return None
    
    @staticmethod
    def save_config(config):
        """保存配置对象到文件"""
        exe_dir = utils.Utils.get_exe_dir()
        config_path = os.path.join(exe_dir, 'mmbox.ini')
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config.to_dict(), f, indent=2)
    
    @staticmethod
    def check_initialized():
        """检查是否已初始化"""
        exe_dir = utils.Utils.get_exe_dir()
        config_path = os.path.join(exe_dir, 'mmbox.ini')
        return os.path.exists(config_path)