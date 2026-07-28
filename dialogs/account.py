import tkinter as tk
import utils
from tkinter import ttk, messagebox
from models import Account

class AccountDialog:
    """账号编辑对话框"""
    
    def __init__(self, master, account, dialog_type, on_confirm):
        """
        Args:
            master: 父窗口
            account: Account对象，编辑时传入，新增时为空Account
            dialog_type: 'add' 或 'edit'
            on_confirm: 确认回调函数
        """
        self.master = master
        self.account = account
        self.dialog_type = dialog_type
        self.on_confirm = on_confirm
        
        title = "新增账号" if dialog_type == 'add' else "编辑账号"
        
        self.dialog = tk.Toplevel(master)
        self.dialog.title(title)
        self.dialog.resizable(False, False)
        self.dialog.transient(master)
        self.dialog.grab_set()
        
        # 设置图标
        utils.Utils.setup_window_icon(self.dialog)
        
        # 创建界面
        self.create_widgets()

        utils.Utils.center_window(self.dialog, master, 350, 180)
        
        # 等待对话框关闭
        master.wait_window(self.dialog)
    
    def create_widgets(self):
        """创建界面组件"""
        # 应用名
        ttk.Label(self.dialog, text="应用:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.app_entry = ttk.Entry(self.dialog, width=40)
        self.app_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.app_entry.insert(0, self.account.app_name)
        
        # 账号
        ttk.Label(self.dialog, text="账号:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(self.dialog, width=40)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.username_entry.insert(0, self.account.username)
        
        # 密码
        ttk.Label(self.dialog, text="密码:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(self.dialog, width=40)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.password_entry.insert(0, self.account.password)
        
        # 按钮区域
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(
            button_frame, 
            text="确定", 
            command=self.on_confirm_click, 
            bootstyle="success"
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            button_frame, 
            text="取消", 
            command=self.dialog.destroy, 
            bootstyle="warning"
        ).pack(side=tk.LEFT, padx=10)
        
        self.app_entry.focus_set()
    
    def on_confirm_click(self):
        """确认按钮点击事件"""
        app_name = self.app_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not app_name or not username or not password:
            messagebox.showerror("错误", "所有字段都必须填写", parent=self.dialog)
            return
        
        # 调用回调函数
        if self.on_confirm:
            new_account = Account(app_name=app_name, username=username, password=password)
            self.on_confirm(new_account, self.account, self.dialog_type)
        
        self.dialog.destroy()