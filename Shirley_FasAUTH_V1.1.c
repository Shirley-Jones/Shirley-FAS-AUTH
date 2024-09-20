#include <mysql/mysql.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#define zero_auth_configuration "/etc/openvpn/auth_config.conf"
#define MAX_LINE_LENGTH 1024
#define MAX_VALUE_LENGTH 1024
#define MAX_URL_LENGTH 1024 // 假设URL的最大长度是1024个字符
#define TOKEN_LENGTH 1024    // 假设令牌的最大长度是256个字符
/*
	FAS OpenVPN流量监控程序
	由Shirley原创编写,丢弃FAS原版未开源的监控.
	Shirley版权所有
	2024.09.20
	V1.1版
	项目地址: https://github.com/Shirley-Jones/Shirley-FAS-AUTH
*/

void hash_to_hex_string(const unsigned char* hash, size_t hash_len, char* hex_str) {
    for (size_t i = 0; i < hash_len; i++) {
        sprintf(hex_str + (i * 2), "%02x", hash[i]);
    }
}

void string_sha256(unsigned char* result, const char* str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);

    // 将哈希值复制到结果中
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result[i] = hash[i];
    }
}



// 这个函数将被libcurl调用，每当它接收到数据块时
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    strncat((char*)userp, (char*)contents, realsize);
    return realsize;
}

// 函数用于检查指定名称的进程是否在运行
int count_processes_by_name(const char *process_name) {
    int count = 0;
    DIR *proc_dir;
    struct dirent *entry;
    char path[1024];
    char cmdline[1024];
    FILE *cmdline_file;

    proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("opendir /proc");
        return -1;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        int pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue; // 忽略非数字命名的目录
        }

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        cmdline_file = fopen(path, "r");
        if (cmdline_file == NULL) {
            continue; // 忽略无法打开的cmdline文件
        }

        if (fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_file) > 0) {
            cmdline[sizeof(cmdline) - 1] = '\0'; // 确保字符串以null结尾
            // 去除cmdline中的null字符，并转换为普通字符串
            size_t len = strlen(cmdline);
            while (len > 0 && cmdline[len - 1] == '\0') {
                cmdline[len - 1] = ' ';
                len--;
            }

            // 检查进程名称是否匹配
            if (strstr(cmdline, process_name) != NULL) {
                count++;
                if (count > 2) {
                    break; // 如果已经找到超过两个进程，可以提前退出循环
                }
            }
        }
        fclose(cmdline_file);
    }

    closedir(proc_dir);
    return count;
}

int Start_Monitoring(char* MySQL_Host,char* MySQL_Port,char* MySQL_User,char* MySQL_Pass,char* MySQL_DB,char* status_file,char* Scan_interval)
{
	FILE *Configuration;
	char Configuration_line[MAX_LINE_LENGTH];
	char common_name[256];
	char Real_Address[20];
	unsigned long long received_bytes, sent_bytes;
	unsigned int sleep_time = atoi(Scan_interval);
	
	char OpenVPN_Configuration[100];
	int OpenVPN_Management_Port, OpenVPN_Port;
	char OpenVPN_agreement[20];
	
	sscanf(status_file, "%s %d %d %s", OpenVPN_Configuration, &OpenVPN_Management_Port, &OpenVPN_Port, OpenVPN_agreement);
	
	// 打开 OpenVPN TCP 文件
	Configuration = fopen(OpenVPN_Configuration, "r");
	if (Configuration == NULL) {
		perror("打开OpenVPN用户在线日志时出错!!!");
		//exit(EXIT_FAILURE);
		sleep(sleep_time);
		return 0;
	}
	
	// 跳过第一行标题
	if (fgets(Configuration_line, sizeof(Configuration_line), Configuration) == NULL) {
		perror("打开OpenVPN用户在线日志时出错!!!");
		fclose(Configuration);
		//exit(EXIT_FAILURE);
		sleep(sleep_time);
		return 0;
	}
		
	// 逐行读取文件
	while (fgets(Configuration_line, sizeof(Configuration_line), Configuration)) {
		// 解析每行数据
		if (sscanf(Configuration_line, "%[^,],%[^,],%llu,%llu", common_name, Real_Address, &received_bytes, &sent_bytes) == 4) {
			//common_name 用户名
			//received_bytes 下载流量
			//sent_bytes 上传流量
			MYSQL *conn;
			MYSQL_RES *res;
			MYSQL_ROW row;
			char *server = MySQL_Host;
			char *user = MySQL_User;
			char *password = MySQL_Pass;
			char *database = MySQL_DB;
			unsigned int port = atoi(MySQL_Port);  // 自定义的端口号
			char query_account[256];
					
			// 初始化连接
			conn = mysql_init(NULL);
			
			// 连接到数据库
			if (!mysql_real_connect(conn, server, user, password, database, port, NULL, 0)) {
				fprintf(stderr, "%s\n", mysql_error(conn));
				sleep(sleep_time); //数据库连接失败，将等待一段时间后重新查询
				continue;
				//exit(EXIT_FAILURE);
			}
			
			
			// 构建查询语句
			sprintf(query_account, "SELECT * FROM openvpn WHERE iuser = '%s' AND i = '1' AND online = '1'",common_name);

			// 执行查询
			if (mysql_query(conn, query_account)) {
				fprintf(stderr, "%s\n", mysql_error(conn));
				sleep(sleep_time); // 等待一段时间后重试
				continue;
			}

			// 获取结果
			res = mysql_store_result(conn);
			row = mysql_fetch_row(res);
			if (row) {
				// 输出MySQL查询结果
				// row[0] 是第一列的值，row[1] 是第二列的值，以此类推
				//上传流量[2] + 下载流量[3]
				long long upload = atoll(row[2]);
				long long download = atoll(row[3]);
				//获取已使用流量
				long long Used_ll;
				Used_ll = upload + download;
				//总流量[4]
				long long maximum_flow = atoll(row[4]);
				//获取剩余流量 
				long long surplus_ll;
				surplus_ll = maximum_flow - Used_ll;
				//计算实时流量 查询是否超出
				long long Used_real_time_ll;
				//计算出当前使用的流量
				Used_real_time_ll = received_bytes + sent_bytes;
				long long real_time_ll;
				//剩余流量减去当前使用流量
				real_time_ll = surplus_ll - Used_real_time_ll;
				//判断
				if (real_time_ll < 1) {
					//数值小于1 断开用户
					char Kill_Account_Online[100];
					sprintf(Kill_Account_Online,"(sleep 1;\necho kill \"%s\";\nsleep 1;\n)|telnet localhost %d >/dev/null 2>&1",common_name,OpenVPN_Management_Port);
					setbuf(stdout,NULL);
					system(Kill_Account_Online);
					//printf("用户: %s ,TCP实时流量小于1 ,数值是: %lld\n",common_name,real_time_ll);
				}else{
					//获取总时间戳[8]
					long long end_time = atoll(row[8]);
					//获取当前时间戳
					time_t current_time;
					current_time = time(NULL);
							
					//计算出剩余的实时时间戳
					long long surplus_time;
					surplus_time = end_time - current_time;
							
					//判断
					if (surplus_time < 1) {
						//数值小于1 断开用户
						//printf("用户: %s ,TCP实时时间戳小于1 ,数值是: %lld\n",common_name,surplus_time);
						char Kill_Account_Online[100];
						sprintf(Kill_Account_Online,"(sleep 1;\necho kill \"%s\";\nsleep 1;\n)|telnet localhost %d >/dev/null 2>&1",common_name,OpenVPN_Management_Port);
						setbuf(stdout,NULL);
						system(Kill_Account_Online);
					}
				}
			}else{
				//数据库中无此用户或已经被禁用.
				char Kill_Account_Online[100];
				sprintf(Kill_Account_Online,"(sleep 1;\necho kill \"%s\";\nsleep 1;\n)|telnet localhost %d >/dev/null 2>&1",common_name,OpenVPN_Management_Port);
				setbuf(stdout,NULL);
				system(Kill_Account_Online);
			}
			
			// 清理
			mysql_free_result(res);
			mysql_close(conn);
		}
	}
	fclose(Configuration);
	sleep(sleep_time);
	return 0;
}

int Create_process(char* MySQL_Host,char* MySQL_Port,char* MySQL_User,char* MySQL_Pass,char* MySQL_DB,char* Server_IP,char* status_file_1,char* status_file_2,char* status_file_3,char* status_file_4,char* status_file_5,char* Scan_interval)
{	
	printf("FasAUTH: Server Start\n");
	//sleep(1);
	
	const char *process_name = "FasAUTH.bin"; // 替换为你的程序名称
    int process_count = count_processes_by_name(process_name);

    if (process_count >= 2) {
        //printf("More than two instances of %s are running.\n", process_name);
		printf("%s 监控正在运行，无法重复执行.\n", process_name);
		exit(1);
    }
	
	
	char file_path[100];
	int num1, num2;
	char type[20];
		
	pid_t pid1, pid2, pid3, pid4, pid5;

    // 创建第一个子进程 
    pid1 = fork();
    if (pid1 < 0) {
        // fork失败
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid1 == 0) {
        // 第一个子进程
        // 创建一个新的会话
        if (setsid() < 0) {
            perror("setsid");
            exit(EXIT_FAILURE);
        }
        // 脱离控制终端，将当前进程放到后台运行
        // 子进程在这里可以执行其他任务或程序
		sscanf(status_file_1, "%s %d %d %s", file_path, &num1, &num2, type);
		printf("FasAUTH: %s %d 已启动 PID: %d\n", file_path,num1,getpid());
        
        // 例如，执行一个无限循环来模拟后台任务
        while (1) { // 这里的条件始终为真，因此循环将无限执行下去
			Start_Monitoring(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,status_file_1,Scan_interval);
		}
    }
	
	
	// 创建第二个子进程 
    pid2 = fork();
	if (pid2 < 0) {
        // fork失败
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid2 == 0) {
        // 第一个子进程
        // 创建一个新的会话
        if (setsid() < 0) {
            perror("setsid");
            exit(EXIT_FAILURE);
        }
        // 脱离控制终端，将当前进程放到后台运行
        // 子进程在这里可以执行其他任务或程序
		sscanf(status_file_2, "%s %d %d %s", file_path, &num1, &num2, type);
		printf("FasAUTH: %s %d 已启动 PID: %d\n", file_path,num1,getpid());
        
        // 例如，执行一个无限循环来模拟后台任务
        while (1) { // 这里的条件始终为真，因此循环将无限执行下去
			Start_Monitoring(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,status_file_2,Scan_interval);
		}
    }
	
	
	// 创建第三个子进程 
    pid3 = fork();
	if (pid3 < 0) {
        // fork失败
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid3 == 0) {
        // 第一个子进程
        // 创建一个新的会话
        if (setsid() < 0) {
            perror("setsid");
            exit(EXIT_FAILURE);
        }
        // 脱离控制终端，将当前进程放到后台运行
        // 子进程在这里可以执行其他任务或程序
		sscanf(status_file_3, "%s %d %d %s", file_path, &num1, &num2, type);
		printf("FasAUTH: %s %d 已启动 PID: %d\n", file_path,num1,getpid());
        
        // 例如，执行一个无限循环来模拟后台任务
        while (1) { // 这里的条件始终为真，因此循环将无限执行下去
			Start_Monitoring(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,status_file_3,Scan_interval);
		}
    }
	
	
	// 创建第四个子进程 
    pid4 = fork();
	if (pid4 < 0) {
        // fork失败
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid4 == 0) {
        // 第一个子进程
        // 创建一个新的会话
        if (setsid() < 0) {
            perror("setsid");
            exit(EXIT_FAILURE);
        }
        // 脱离控制终端，将当前进程放到后台运行
        // 子进程在这里可以执行其他任务或程序
		sscanf(status_file_4, "%s %d %d %s", file_path, &num1, &num2, type);
		printf("FasAUTH: %s %d 已启动 PID: %d\n", file_path,num1,getpid());
        
        // 例如，执行一个无限循环来模拟后台任务
        while (1) { // 这里的条件始终为真，因此循环将无限执行下去
			Start_Monitoring(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,status_file_4,Scan_interval);
		}
    }
	
	
	// 创建第五个子进程 
    pid5 = fork();
	if (pid5 < 0) {
        // fork失败
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid5 == 0) {
        // 第一个子进程
        // 创建一个新的会话
        if (setsid() < 0) {
            perror("setsid");
            exit(EXIT_FAILURE);
        }
        // 脱离控制终端，将当前进程放到后台运行
        // 子进程在这里可以执行其他任务或程序
		sscanf(status_file_5, "%s %d %d %s", file_path, &num1, &num2, type);
		printf("FasAUTH: %s %d 已启动 PID: %d\n", file_path,num1,getpid());
        
        // 例如，执行一个无限循环来模拟后台任务
        while (1) { // 这里的条件始终为真，因此循环将无限执行下去
			Start_Monitoring(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,status_file_5,Scan_interval);
		}
    }
	
	
	// 父进程可以退出，子进程已经在后台运行
	// 延时0.5秒，即500000微秒
	usleep(500000);
	exit(EXIT_SUCCESS);
} 




int Read_Configuration(char* Auth_Configuration_file)
{
	FILE *Auth_Configuration;
	char Auth_Configuration_line[MAX_LINE_LENGTH];
	char variable[MAX_VALUE_LENGTH];
	char value[MAX_VALUE_LENGTH];
	char MySQL_Host[100];
	char MySQL_Port[100];
	char MySQL_User[100];
	char MySQL_Pass[100];
	char MySQL_DB[100];
	char status_file_1[100];
	char status_file_2[100];
	char status_file_3[100];
	char status_file_4[100];
	char status_file_5[100];
	char Server_IP[256];
	char Scan_interval[100];
	printf("正在读取配置文件...\n");
	sleep(3);
	// 打开文件
	
	if (access(Auth_Configuration_file,0)){
		// 文件不存在或发生错误
		printf("配置文件不存在或发生错误...\n");
		exit(EXIT_FAILURE);
	}
			
	
	Auth_Configuration = fopen(Auth_Configuration_file, "r");
	if (Auth_Configuration == NULL) {
		perror("打开配置文件失败...");
		exit(EXIT_FAILURE);
	}
	
	// 读取文件并查找变量
	while (fgets(Auth_Configuration_line, sizeof(Auth_Configuration_line), Auth_Configuration)) {
		if (sscanf(Auth_Configuration_line, "mysql_host=\"%[^\"]\"", value) == 1) {
			strcpy(MySQL_Host,value);
			printf("MySQL Host: %s\n", MySQL_Host);
		} else if (sscanf(Auth_Configuration_line, "mysql_port=\"%[^\"]\"", value) == 1) {
			strcpy(MySQL_Port,value);
			printf("MySQL Port: %s\n", MySQL_Port);
		} else if (sscanf(Auth_Configuration_line, "mysql_user=\"%[^\"]\"", value) == 1) {
			strcpy(MySQL_User,value);
			printf("MySQL User: %s\n", MySQL_User);
		} else if (sscanf(Auth_Configuration_line, "mysql_pass=\"%[^\"]\"", value) == 1) {
			strcpy(MySQL_Pass,value);
			printf("MySQL Pass: %s\n", MySQL_Pass);
		} else if (sscanf(Auth_Configuration_line, "mysql_data=\"%[^\"]\"", value) == 1) {
			strcpy(MySQL_DB,value);
			printf("MySQL DB: %s\n", MySQL_DB);
		} else if (sscanf(Auth_Configuration_line, "address=\"%[^\"]\"", value) == 1) {
			strcpy(Server_IP,value);
			printf("Server IP: %s\n", Server_IP);
		} else if (sscanf(Auth_Configuration_line, "status_file_1=\"%[^\"]\"", value) == 1) {
			strcpy(status_file_1,value);
			printf("status_file_1: %s\n", status_file_1);
		} else if (sscanf(Auth_Configuration_line, "status_file_2=\"%[^\"]\"", value) == 1) {
			strcpy(status_file_2,value);
			printf("status_file_2: %s\n", status_file_2);
		} else if (sscanf(Auth_Configuration_line, "status_file_3=\"%[^\"]\"", value) == 1) {
			strcpy(status_file_3,value);
			printf("status_file_3: %s\n", status_file_3);
		} else if (sscanf(Auth_Configuration_line, "status_file_4=\"%[^\"]\"", value) == 1) {
			strcpy(status_file_4,value);
			printf("status_file_4: %s\n", status_file_4);
		} else if (sscanf(Auth_Configuration_line, "status_file_5=\"%[^\"]\"", value) == 1) {
			strcpy(status_file_5,value);
			printf("status_file_5: %s\n", status_file_5);
		} else if (sscanf(Auth_Configuration_line, "sleep=%s", value) == 1) {
			strcpy(Scan_interval,value);
			printf("监控扫描间隔: %s 秒\n", Scan_interval);	
		}
		// 可以继续添加其他变量的处理逻辑		
	}
	// 关闭文件
	fclose(Auth_Configuration);
	Create_process(MySQL_Host,MySQL_Port,MySQL_User,MySQL_Pass,MySQL_DB,Server_IP,status_file_1,status_file_2,status_file_3,status_file_4,status_file_5,Scan_interval);
	exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
    int c_flag_found = 0; // 标志，表示是否找到了-c参数
    char *c_value = NULL; // 用于存储-c参数的值

    // 遍历所有命令行参数
    for (int i = 1; i < argc; i++) {
        // 检查参数是否是-c
        if (strcmp(argv[i], "-c") == 0) {
            c_flag_found = 1; // 设置标志表示找到了-c

            // 检查是否有后续参数作为-c的值
            if (i + 1 < argc) {
                c_value = argv[i + 1]; // 获取-c的值
				Read_Configuration(c_value);
				exit(EXIT_SUCCESS);
            }else{
                fprintf(stderr, "错误: -c 需要一个值\n");
                exit(EXIT_FAILURE);
            }
        }
    }
	
	Read_Configuration(zero_auth_configuration);
	exit(EXIT_SUCCESS);
}



