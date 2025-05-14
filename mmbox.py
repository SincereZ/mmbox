import tkinter as tk
from tkinter import ttk, messagebox
import base64
import os
import json
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from dataclasses import dataclass

@dataclass
class Account:
    app_name: str
    username: str
    password: str

class PasswordManager:
    def __init__(self, master):
        self.master = master
        master.title("密码箱")

        # 图标设置仅适配windows环境，其他运行环境注释此行
        master.iconbitmap('mm.ico')

        master.geometry("800x500")  # 加宽窗口以适应新列
        self.accounts = []

        # 顶部控制区域 - 将三个元素放在同一行
        control_frame = tk.Frame(master)
        control_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
        
        # 文件路径
        tk.Label(control_frame, text="数据文件路径").pack(side=tk.LEFT)
        self.file_path = tk.Entry(control_frame, width=50)
        self.file_path.pack(side=tk.LEFT, padx=5)
        
        # 主密码
        tk.Label(control_frame, text="私人密钥").pack(side=tk.LEFT)
        self.person_key = tk.Entry(control_frame, show="*", width=20)
        self.person_key.pack(side=tk.LEFT, padx=5)
        
        # 解密按钮
        self.decrypt_button = tk.Button(control_frame, text="解密/加载", command=self.decrypt_file, width=10)
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        
        # 添加水平分割线
        separator = ttk.Separator(master, orient='horizontal')
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        
        # 账号添加区域
        add_frame = tk.Frame(master)
        add_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky="ew")
        
        tk.Label(add_frame, text="应用").pack(side=tk.LEFT)
        self.app_entry = tk.Entry(add_frame, width=30)
        self.app_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(add_frame, text="账号").pack(side=tk.LEFT)
        self.account_entry = tk.Entry(add_frame, width=18)
        self.account_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(add_frame, text="密码").pack(side=tk.LEFT)
        self.password_entry = tk.Entry(add_frame, width=18)
        self.password_entry.pack(side=tk.LEFT, padx=5)
        
        # 将按钮放在同一行
        button_frame = tk.Frame(add_frame)
        button_frame.pack(side=tk.LEFT, padx=10)
        
        self.add_button = tk.Button(button_frame, text="添加", command=self.add_account, width=8)
        self.add_button.pack(side=tk.LEFT, padx=2)
        
        self.clear_button = tk.Button(button_frame, text="清空", command=self.clear_entries, width=8)
        self.clear_button.pack(side=tk.LEFT, padx=2)
        
        # 表格区域
        self.setup_table()
        self.setup_context_menu()
        
        # 配置网格布局权重
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(3, weight=1)
        
        # 默认加载测试数据
        # self.file_path.insert(0, "a.dat")
        # self.person_key.insert(0, "1111111111111111")

    def clear_entries(self):
        """清空输入框"""
        self.app_entry.delete(0, tk.END)
        self.account_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def setup_table(self):
        """初始化表格控件"""
        columns = ('app_name', 'username', 'password')
        self.tree = ttk.Treeview(
            self.master,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=12
        )
        
        # 配置样式
        style = ttk.Style()
        style.configure("Treeview", 
            font=('Microsoft YaHei', 10), 
            rowheight=25,
            foreground="#333333",
            fieldbackground="#ffffff"
        )
        style.configure("Treeview.Heading", 
            font=('Microsoft YaHei', 10, 'bold'),
            background="#f0f0f0"
        )
        
        # 配置列
        self.tree.heading('app_name', text='应 用', anchor='w')
        self.tree.heading('username', text='账 号', anchor='w')
        self.tree.heading('password', text='密 码', anchor='w')
        self.tree.column('app_name', width=200, minwidth=100)
        self.tree.column('username', width=100, minwidth=100)
        self.tree.column('password', width=100, minwidth=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 布局
        self.tree.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=10, pady=(0,10))
        scrollbar.grid(row=3, column=3, sticky="ns", pady=(0,10))
        
        # 绑定事件
        self.tree.bind("<Double-1>", self.reveal_password)

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
            messagebox.showinfo("成功", "账号已复制到剪贴板")

    def copy_password(self):
        """复制密码到剪贴板"""
        item = self.tree.selection()
        if item:
            app_name = self.tree.item(item, 'values')[0]
            username = self.tree.item(item, 'values')[1]
            acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
            self.master.clipboard_clear()
            self.master.clipboard_append(acc.password)
            messagebox.showinfo("成功", "密码已复制到剪贴板")

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
        """切换密码显示/隐藏"""
        item = self.tree.selection()
        if item:
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
            messagebox.showerror("错误", "请输入主密码")
            return None
        
        key = password.encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("错误", "主密码长度为16位")
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
        fpath = self.file_path.get()
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
    
    def add_account(self):
        fpath = self.file_path.get()
        if not fpath:
            messagebox.showerror("错误", "请先指定数据文件路径")
            return

        key = self.get_cipher()
        if not key:
            return
        
        app_name = self.app_entry.get()
        username = self.account_entry.get()
        password = self.password_entry.get()
        
        if not app_name or not username or not password:
            messagebox.showerror("错误", "应用名、账号和密码不能为空")
            return
        
        # 更新或添加账号
        existing = next((acc for acc in self.accounts if acc.app_name == app_name and acc.username == username), None)
        if existing:
            if messagebox.askyesno("确认", f"应用 '{app_name}' 下的账号 '{username}' 已存在，是否更新密码？"):
                existing.password = password
        else:
            self.accounts.append(Account(app_name=app_name, username=username, password=password))
        
        self.save_data()
        self.display_accounts()
        
        # 清空输入框
        self.clear_entries()
    
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
            with open(self.file_path.get(), 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()