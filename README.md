# Shirley-FAS-AUTH
## FAS流控新版本监控，由Shirley编写

## 编译说明
* 先安装支持库: yum install mariadb-devel curl libcurl-devel openssl openssl-devel gcc gcc++ gdb -y
* 编译 gcc -std=gnu99 监控源码文件 -o 编译后的文件名 -L/usr/lib64/mysql/ -lmysqlclient  -lcurl -lcrypto
* 举个例子 gcc -std=gnu99 /root/ZeroAUTH_V1.5.c -o /root/ZeroAUTH.bin -L/usr/lib64/mysql/ -lmysqlclient  -lcurl -lcrypto

## 使用方法
* 先安装FAS流控(Shirley提供的FAS内置此监控，您可以直接使用一键脚本安装)
* 删除原版监控 rm -rf /bin/FasAUTH.bin
* 杀掉正在运行的监控 killall -9 /bin/FasAUTH.bin
* 将Shirley新版监控移动至bin目录 mv /root/Shirley_FasAUTH.bin /bin/FasAUTH.bin
* 给权限 chmod -R 0777 /bin/FasAUTH.bin
* 然后重启VPN即可 vpn restart

## 免责声明
* 代码写的很辣鸡，还请大佬多多包涵。
* 本脚本仅用于学习交流，禁止商业，下载安装后请在24小时内删除！

## 温馨提醒
* 这个监控仅用于FAS流控，其他流控您需要自己修改代码
* 任何问题不要问我，不要问我，不要问我。
* 任何问题不要问我，不要问我，不要问我。
* 任何问题不要问我，不要问我，不要问我。


