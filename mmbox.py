import tkinter as tk
from tkinter import messagebox, filedialog
import os
import json
import tempfile
from pathlib import Path
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import constants
import utils
from logger import log
from models import Account, AppConfig
from dialogs import InitDialog, AccountDialog

class PasswordManager:
    def __init__(self, master):
        log.info('程序启动')
        self.master = master
        master.title("密码箱 - 安全存储你的应用账号密码")
        master.resizable(False, False)

        # 设置程序图标
        utils.Utils.setup_window_icon(master)

        # 设置窗口大小且居中显示
        width = constants.MAIN_WINDOW_WIDTH
        height = constants.MAIN_WINDOW_HEIGHT
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x = (screen_width/2) - (width/2)
        y = (screen_height/2) - (height/2)
        self.master.geometry('%dx%d+%d+%d' % (width, height, x, y))

        # 检查是否需要初始化
        if not self.check_and_init():
            return

        # 缓存账户数据
        self.accounts = []
        self.data_file_path = ''
        self.master_key = ''

        # 用于存储单击事件的“预约ID”
        self._click_after_id = None

        # 加载配置
        self.load_config()

        # 使用ttkbootstrap样式
        self.style = ttk.Style(constants.THEME_NAME)

        # 创建主界面
        self.setup_ui()
        
    def check_and_init(self):
        """检查是否需要初始化"""
        exe_dir = utils.Utils.get_exe_dir()
        config_path = utils.Utils.get_config_path()
        
        # 如果配置文件存在，直接返回
        if os.path.exists(config_path):
            return True
        
        # 显示初始化对话框
        init_dialog = InitDialog(self.master, exe_dir)
        return init_dialog.result if hasattr(init_dialog, 'result') else False

    def load_config(self):
        """加载配置"""
        config = InitDialog.load_config()
        if config:
            self.config = config
            self.data_file_path = config.data_file
        else:
            self.config = AppConfig(data_file='')
            
    def setup_ui(self):
        """构建主界面"""
        # 顶部控制区域
        control_frame = ttk.Frame(self.master, padding=5)
        control_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=5, sticky="ew")

        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=2)

        # 选择数据文件  
        ttk.Label(row1, text="数据文件").pack(side=tk.LEFT)
        self.file_path = ttk.Entry(row1, width=80)
        self.file_path.pack(side=tk.LEFT, padx=5)
        self.file_path.insert(0, self.data_file_path)
        self.file_path.config(state='readonly')

        # 浏览文件按钮
        self.browse_button = ttk.Button(
            row1, 
            text="选择文件", 
            command=self.browse_file, 
            width=8,
            bootstyle=PRIMARY
        )
        self.browse_button.pack(side=tk.LEFT, padx=2)

        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X, pady=2)

        # 主密码
        ttk.Label(row2, text="文件密钥").pack(side=tk.LEFT)
        self.person_key = ttk.Entry(row2, show="*", width=25)
        self.person_key.pack(side=tk.LEFT, padx=5)
        
        # 解密按钮
        self.decrypt_button = ttk.Button(
            row2, 
            text="解密", 
            command=self.decrypt_file, 
            width=8,
            bootstyle=PRIMARY
        )
        self.decrypt_button.pack(side=tk.LEFT, padx=5)
        
        # 新增按钮
        self.add_button = ttk.Button(
            row2, 
            text="新增", 
            command=self.show_add_dialog, 
            width=8,
            state=tk.DISABLED,
            bootstyle=SUCCESS
        )
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        # 分割线
        separator = ttk.Separator(self.master, orient='horizontal', bootstyle=LIGHT)
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        
        # 表格区域
        self.setup_table()
        self.setup_context_menu()
        
        # 配置网格布局权重
        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure(2, weight=1)

    def setup_table(self):
        """初始化表格控件"""
        columns = ('app_name', 'username', 'password')
        self.tree = ttk.Treeview(
            self.master,
            columns=columns,
            show='headings',
            selectmode='extended',
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
        
        # 滚动条
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
        self.tree.bind("<Button-1>", self.reveal_password)
        self.tree.bind("<Double-1>", self.show_edit_dialog)

    def setup_context_menu(self):
        """初始化右键菜单"""
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="复制账号", command=self.copy_username)
        self.context_menu.add_command(label="复制密码", command=self.copy_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="删除此项", command=self.delete_item)
        
        self.tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """显示右键菜单"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def show_add_dialog(self):
        """显示新增对话框"""
        AccountDialog(
            self.master,
            Account('', '', ''),
            'add',
            self.on_account_confirm
        )

    def show_edit_dialog(self, event=None):
        """显示编辑对话框"""
        if self._click_after_id:
            self.master.after_cancel(self._click_after_id)
            self._click_after_id = None
        
        item = self.tree.selection()
        if not item:
            return
        
        values = self.tree.item(item, 'values')
        app_name = values[0]
        username = values[1]
        
        # 查找完整的账号信息
        current_acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
        
        AccountDialog(
            self.master,
            current_acc,
            'edit',
            self.on_account_confirm
        )

    def on_account_confirm(self, new_account, old_account, dialog_type):
        """账号确认回调"""
        # 检查是否已存在相同应用和账号
        if dialog_type == 'add':
            existing = next((acc for acc in self.accounts 
                           if acc.app_name == new_account.app_name and acc.username == new_account.username), None)
            if existing:
                messagebox.showwarning("警告", f"应用 '{new_account.app_name}' 下的账号 '{new_account.username}' 已存在")
                return
            self.accounts.append(new_account)
        else:  # edit
            self.accounts = [acc for acc in self.accounts 
                           if not (acc.app_name == old_account.app_name and acc.username == old_account.username)]
            self.accounts.append(new_account)
        
        self.save_data()
        self.display_accounts()

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
            
            self.file_path.config(state='normal')
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, path)
            self.file_path.config(state='readonly')
          
            # 清理密钥缓存
            self.person_key.config(state='normal')
            self.person_key.delete(0, tk.END)
            self.person_key.focus_set()

            #重置旧状态：清空密钥缓存/旧账号数据/清空表格
            self.master_key = ''
            self.accounts = []
            self.display_accounts()

            # 写入配置文件
            try:
                if not hasattr(self, 'config') or self.config is None:
                    self.config = AppConfig(data_file='')
                self.config.data_file = file_path
                InitDialog.save_config(self.config)
            except Exception as e:
                log.error(f"写入配置文件失败: {e}", exception=True)

            # 新增按钮禁用，解密按钮启用
            self.add_button.config(state=tk.DISABLED)
            self.decrypt_button.config(state=tk.NORMAL)


    def copy_username(self):
        """复制账号到剪贴板"""
        item = self.tree.selection()
        if item:
            username = self.tree.item(item, 'values')[1]
            self.master.clipboard_clear()
            self.master.clipboard_append(username)
            messagebox.showinfo("提示", f"已复制账号: {username}")

    def copy_password(self):
        """复制密码到剪贴板"""
        item = self.tree.selection()
        if item:
            app_name = self.tree.item(item, 'values')[0]
            username = self.tree.item(item, 'values')[1]
            acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
            self.master.clipboard_clear()
            self.master.clipboard_append(acc.password)
            messagebox.showinfo("提示", f"已复制密码: {acc.password}")

    def delete_item(self):
        """删除选中条目"""
        item = self.tree.selection()
        if item:
            app_name = self.tree.item(item, 'values')[0]
            username = self.tree.item(item, 'values')[1]
            if messagebox.askyesno("确认", f"确定要删除应用 '{app_name}' 下的账号 '{username}' 吗？"):
                self.accounts = [acc for acc in self.accounts 
                               if not (acc.app_name == app_name and acc.username == username)]
                self.save_data()
                self.display_accounts()
                messagebox.showinfo("提示", f"已删除应用 '{app_name}' 下的账号 '{username}'")

    def reveal_password(self, event):
        """单击显示/隐藏密码"""
        item = self.tree.identify_row(event.y)
        if not item:
            return

        # 如果之前有预约的单击任务，先取消
        if self._click_after_id:
            self.master.after_cancel(self._click_after_id)

        def do_reveal():
            """真正执行显示/隐藏密码逻辑的函数"""
            self.tree.selection_set(item)
            values = self.tree.item(item, 'values')
            if '***' in values[2]:
                app_name = values[0]
                username = values[1]
                acc = next(acc for acc in self.accounts if acc.app_name == app_name and acc.username == username)
                self.tree.item(item, values=(app_name, username, acc.password))
            else:
                self.tree.item(item, values=(values[0], values[1], '***' * 3))
            # 执行完毕后，清空预约ID
            self._click_after_id = None

        # 预约在400毫秒(经验值)后执行do_reveal
        self._click_after_id = self.master.after(400, do_reveal)

    def decrypt_file(self):
        """解密文件"""
        fpath = self.data_file_path
        if not os.path.exists(fpath):
            log.error(f"解密文件失败: {fpath} 不存在")
            messagebox.showerror("错误", "数据文件不存在")
            return

        self.master_key = self.get_cipher()
        if not self.master_key: 
            return
        
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                self.accounts = []
                self.display_accounts()
                messagebox.showinfo("提示", "数据文件为空")
                return
            
            try:
                decrypted_data = utils.Utils.decrypt_field(self.master_key, encrypted_data)
                accounts_data = json.loads(decrypted_data)
                self.accounts = [Account(**acc) for acc in accounts_data]
                self.display_accounts()
                self.person_key.config(state='readonly')
            except (ValueError, json.JSONDecodeError) as e:
                log.error(f"解密文件失败: {e}", exception=True)
                messagebox.showerror("错误", "密钥错误或文件内容错误")
        
        except Exception as e:
            log.error(f"解密文件失败: {e}", exception=True)
            messagebox.showerror("错误", "操作失败")

        # 解密成功后，启用新增按钮
        self.add_button.config(state=tk.NORMAL)
        self.decrypt_button.config(state=tk.DISABLED)

    def get_cipher(self):
        """获取密钥"""
        password = self.person_key.get()
        if not password:
            log.error("获取密钥失败: 未输入密钥")
            messagebox.showerror("错误", "请输入密钥")
            return None
        
        key = password.encode('utf-8')
        if len(key) != 16:
            log.error("获取密钥失败: 密钥长度不足16位")
            messagebox.showerror("错误", "密钥错误, 长度不足16位")
            return None
        return key

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
        if isinstance(self.master_key, bytes):
            key = self.master_key
        elif self.master_key:
            key = self.master_key.encode('utf-8')
        else:
            # 如果 master_key 为空，尝试从输入框获取
            key = self.get_cipher()
            if not key:
                log.error("获取密钥失败")
                return
        
        if not self.accounts:
            encrypted_data = ""
        else:
            accounts_data = [acc.to_dict() for acc in self.accounts]
            data_to_save = json.dumps(accounts_data, indent=2)
            encrypted_data = utils.Utils.encrypt_field(key, data_to_save)
        
        try:
            data_dir = os.path.dirname(self.data_file_path)
            # 先写入临时文件，成功后再原子替换原文件
            fd, tmp_path = tempfile.mkstemp(dir=data_dir, suffix='.tmp')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(encrypted_data)
                # os.replace 是原子操作，确保要么成功要么失败
                os.replace(tmp_path, self.data_file_path)
            except:
                # 写入失败时清理临时文件，保留原文件不变
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            log.error(f"保存文件失败: {e}", exception=True)
            messagebox.showerror("错误", "操作失败")

if __name__ == "__main__":
    root = ttk.Window(themename="minty")
    app = PasswordManager(root)
    root.mainloop()