# PETools
用C++写的PE工具，包含读取PE信息、新增节表、删除节表等功能，正在开发中...
## 参考资料：
+ 滴水三期，于海龙老师
## 环境配置
+ IDE：社区版本vs2019
+ windows 10 x64 专业版
## 时间节表
+ 2020.11.12  初始化项目
+ 2020.11.12  实现了打印PE文件信息功能，项目有了初步的框架
+ 2020.11.16  添加了filebuffer转为Imagebuffer的类file2image，规范了部分类的写法
+ 2020.11.17  添加了Imagebuffer转newBuffer，保存文件，偏移值转换（RVA to FOA），进一步降低前面代码的耦合
