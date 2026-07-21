import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import base64
import sys
import os
import json
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from pathlib import Path
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from dataclasses import dataclass

@dataclass
class Account:
    app_name: str
    username: str
    password: str

class PasswordManager:
    def __init__(self, master):
        self.master = master
        master.title("密码箱 - 安全存储你的应用账号密码")
        master.resizable(False, False)  # 禁止窗口缩放

        """设置程序图标"""
        try:
            # PyInstaller 创建的临时文件夹中的路径
            self.base_path = sys._MEIPASS
        except Exception:
            # 正常开发环境下的路径
            self.base_path = os.path.abspath(".")
        master.iconbitmap(os.path.join(self.base_path, 'mm.ico'))

        """设置窗口大小且居中显示"""
        width = 800
        height = 500
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        # 计算 x 和 y 坐标
        x = (screen_width/2) - (width/2)
        y = (screen_height/2) - (height/2)
        # 设置窗口位置和大小
        self.master.geometry('%dx%d+%d+%d' % (width, height, x, y))

        # 缓存账户数据
        self.accounts = []

        # 缓存文件路径
        self.data_file_path= ''

        # 使用ttkbootstrap样式 litera cerculean
        self.style = ttk.Style(theme='litera')

        # 顶部控制区域
        control_frame = ttk.Frame(master, padding=5)
        control_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
        
        # 选择数据文件
        ttk.Label(control_frame, text="数据文件").pack(side=tk.LEFT)
        self.file_path = ttk.Entry(control_frame, width=25)
        self.file_path.pack(side=tk.LEFT, padx=5)

        # 添加浏览文件按钮
        self.browse_button = ttk.Button(
            control_frame, 
            text="选择", 
            command=self.browse_file, 
            width=8,
            bootstyle=PRIMARY
        )
        self.browse_button.pack(side=tk.LEFT, padx=2)

        # 主密码
        ttk.Label(control_frame, text="密钥").pack(side=tk.LEFT)
        self.person_key = ttk.Entry(control_frame, show="*", width=25)
        self.person_key.pack(side=tk.LEFT, padx=5)
        
        # 解密按钮
        self.decrypt_button = ttk.Button(
            control_frame, 
            text="解密", 
            command=self.decrypt_file, 
            width=8,
            bootstyle=PRIMARY
        )
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        
        # 新增按钮
        self.add_button = ttk.Button(
            control_frame, 
            text="新增", 
            command=self.show_add_dialog, 
            width=8,
            bootstyle=SUCCESS
        )
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        # 添加水平分割线
        separator = ttk.Separator(master, orient='horizontal', bootstyle=LIGHT)
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        
        # 表格区域
        self.setup_table()
        self.setup_context_menu()
        
        # 配置网格布局权重
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(2, weight=1)

    def setup_table(self):
        """初始化表格控件"""
        columns = ('app_name', 'username', 'password')
        self.tree = ttk.Treeview(
            self.master,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=12,
            bootstyle="primary"
        )
        
        # 配置列
        self.tree.heading('app_name', text='应 用', anchor='w')
        self.tree.heading('username', text='账 号', anchor='w')
        self.tree.heading('password', text='密 码', anchor='w')
        self.tree.column('app_name', width=200, minwidth=100)
        self.tree.column('username', width=150, minwidth=100)
        self.tree.column('password', width=150, minwidth=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(
            self.master, 
            orient="vertical", 
            command=self.tree.yview,
            bootstyle="round"
        )
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 布局
        self.tree.grid(row=2, column=0, columnspan=3, sticky="nsew", padx=10, pady=(0,10))
        scrollbar.grid(row=2, column=3, sticky="ns", pady=(0,10))
        
        # 绑定事件
        self.tree.bind("<Button-1>", self.reveal_password)  # 单击显示/隐藏密码
        self.tree.bind("<Double-1>", self.show_edit_dialog)  # 双击编辑条目
    
    def show_add_dialog(self):
        self.show_acc_dialog('add')
    
    def show_edit_dialog(self, event=None):
        self.show_acc_dialog('edit')

    def show_acc_dialog(self, type):
        current_acc = Account('', '', '')
        if type == 'add':
            title = "新增账号"
        else:
            title = "编辑账号"
            item = self.tree.selection()
            if not item:
                return
                
            # 获取当前选中项的数据
            values = self.tree.item(item, 'values')
            app_name = values[0]
            username = values[1]
            
            # 查找完整的账号信息(包括密码)
            current_acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)

        dialog = ttk.Toplevel(self.master)
        dialog.title(title)
        dialog.resizable(False, False)
        dialog.transient(self.master)
        dialog.grab_set()
        
        """设置程序图标"""
        dialog.iconbitmap(os.path.join(self.base_path, 'mm.ico'))

        # 居中显示对话框
        dialog_width = 350
        dialog_height = 180
        x = self.master.winfo_x() + (self.master.winfo_width() - dialog_width) // 2
        y = self.master.winfo_y() + (self.master.winfo_height() - dialog_height) // 2
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        # 表单内容
        ttk.Label(dialog, text="应用:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        app_entry = ttk.Entry(dialog, width=40)
        app_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        app_entry.insert(0, current_acc.app_name)
        
        ttk.Label(dialog, text="账号:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        username_entry = ttk.Entry(dialog, width=40)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        username_entry.insert(0, current_acc.username)
        
        ttk.Label(dialog, text="密码:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        password_entry = ttk.Entry(dialog, width=40)
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        password_entry.insert(0, current_acc.password)
        
        # 按钮区域
        button_frame = ttk.Frame(dialog)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        def on_confirm():
            """确认按钮点击事件"""
            app_name = app_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            
            if not app_name or not username or not password:
                messagebox.showerror("错误", "所有字段都必须填写", parent=dialog)
                return
            
            # 检查是否已存在相同应用和账号
            existing = next((acc for acc in self.accounts if acc.app_name == app_name and acc.username == username), None)
            if existing:
                messagebox.showwarning("警告", f"应用 '{app_name}' 下的账号 '{username}' 已存在", parent=dialog)
                return
            else:
                if type == "add":
                    self.accounts.append(Account(app_name=app_name, username=username, password=password))
                else:
                    accs = [ac for ac in self.accounts if not (ac.app_name == current_acc.app_name and ac.username == current_acc.username)]
                    accs.append(Account(app_name=app_name, username=username, password=password))
                    self.accounts = accs
                self.save_data()
                self.display_accounts()
            dialog.destroy()
        
        ttk.Button(
            button_frame, 
            text="确定", 
            command=on_confirm, 
            bootstyle=SUCCESS
        ).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(
            button_frame, 
            text="取消", 
            command=dialog.destroy, 
            bootstyle=WARNING
        ).pack(side=tk.LEFT, padx=10)
        
        app_entry.focus_set()

    def browse_file(self):
        """打开文件选择对话框"""
        file_path = filedialog.askopenfilename (
            title="选择或创建数据文件",
            defaultextension=".dat",
            filetypes=[("数据文件", "*.dat"), ("所有文件", "*.*")]
        )
        if file_path:
            self.data_file_path = file_path
            path = Path(file_path)
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, path.name)
            self.file_path.config(state='readonly')
            self.person_key.config(state='normal')

    def setup_context_menu(self):
        """初始化右键菜单"""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="复制账号", command=self.copy_username)
        self.context_menu.add_command(label="复制密码", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="删除条目", command=self.delete_item)
        
        self.tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_username(self):
        """复制账号到剪贴板"""
        item = self.tree.selection()
        if item:
            username = self.tree.item(item, 'values')[1]
            self.master.clipboard_clear()
            self.master.clipboard_append(username)

    def copy_password(self):
        """复制密码到剪贴板"""
        item = self.tree.selection()
        if item:
            app_name = self.tree.item(item, 'values')[0]
            username = self.tree.item(item, 'values')[1]
            acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
            self.master.clipboard_clear()
            self.master.clipboard_append(acc.password)

    def delete_item(self):
        """删除选中条目"""
        item = self.tree.selection()
        if item:
            app_name = self.tree.item(item, 'values')[0]
            username = self.tree.item(item, 'values')[1]
            if messagebox.askyesno("确认", f"确定要删除应用 '{app_name}' 下的账号 '{username}' 吗？"):
                self.accounts = [acc for acc in self.accounts if not (acc.app_name == app_name and acc.username == username)]
                self.save_data()
                self.display_accounts()

    def reveal_password(self, event):
        """单击显示/隐藏密码"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            values = self.tree.item(item, 'values')
            if '***' in values[2]:  # 如果当前显示的是星号
                app_name = values[0]
                username = values[1]
                acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
                self.tree.item(item, values=(app_name, username, acc.password))
            else:
                self.tree.item(item, values=(values[0], values[1], '***' * 3))

    # 以下是原有的加密/解密和数据操作方法
    def get_cipher(self):
        password = self.person_key.get()
        if not password:
            messagebox.showerror("错误", "请输入密钥")
            return None
        
        key = password.encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("错误", "密钥长度为16位")
            return None
        return key
    
    @staticmethod
    def encrypt_field(key, text):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
    
    @staticmethod 
    def decrypt_field(key, text):
        data = base64.b64decode(text)
        iv, ct = data[:AES.block_size], data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    
    def decrypt_file(self):
        fpath = self.data_file_path
        if not os.path.exists(fpath):
            messagebox.showerror("错误", "数据文件不存在")
            return

        key = self.get_cipher()
        if not key:
            return
        
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                self.accounts = []
                self.display_accounts()
                return
            
            try:
                decrypted_data = self.decrypt_field(key, encrypted_data)
                accounts_data = json.loads(decrypted_data)
                self.accounts = [Account(**acc) for acc in accounts_data]
                self.display_accounts()
                self.person_key.config(state='readonly')
            except (ValueError, json.JSONDecodeError) as e:
                messagebox.showerror("错误", f"文件格式错误: {str(e)}")
        
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
    
    def display_accounts(self):
        """更新表格显示"""
        self.tree.delete(*self.tree.get_children())
        for acc in sorted(self.accounts, key=lambda x: (x.app_name, x.username)):
            self.tree.insert('', 'end', values=(
                acc.app_name,
                acc.username, 
                '***' * 3
            ))
    
    def save_data(self):
        """保存数据到文件"""
        key = self.get_cipher()
        if not key:
            return
        
        if not self.accounts:
            encrypted_data = ''
        else:    
            accounts_data = [{'app_name': acc.app_name, 'username': acc.username, 'password': acc.password} 
                            for acc in self.accounts]
            data_to_save = json.dumps(accounts_data, indent=2)
            encrypted_data = self.encrypt_field(key, data_to_save)
        
        try:
            with open(self.data_file_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败: {str(e)}")

if __name__ == "__main__":
    root = ttk.Window(themename="minty")  # 使用ttkbootstrap的Window
    app = PasswordManager(root)
    root.mainloop()