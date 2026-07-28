from dataclasses import dataclass

@dataclass
class Account:
    app_name: str
    username: str
    password: str
    
    def to_dict(self):
        return {
            'app_name': self.app_name,
            'username': self.username,
            'password': self.password
        }

@dataclass
class AppConfig:
    """应用配置数据模型"""
    data_file: str  # 数据文件路径
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AppConfig':
        """从字典创建配置对象"""
        return cls(
            data_file=data.get('data_file', ''),
        )
    
    def to_dict(self) -> dict:
        """转换为字典用于保存"""
        return {
            'data_file': self.data_file
        }