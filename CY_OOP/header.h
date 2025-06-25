#ifndef HEADER_H
#define HEADER_H

#include <iostream>
#include <cstring>
#include <ctime>
#include <fstream>
using namespace std;

// Max constants
const int max_usernameLength = 30;
const int max_passwordLength = 30;
const int max_roleLength = 20;
const int max_signatureLength = 64;

class RoleSystem {
public:
    static const int JUNIOR = 1;
    static const int EMPLOYEE = 2;
    static const int MANAGER = 3;
    static const int DIRECTOR = 4;
    static const int EXECUTIVE = 5;
    
    static const char* getRoleName(int level) {
        static const char* names[] = {"", "Junior", "Employee", "Manager", "Director", "Executive"};
        return (level >= 1 && level <= 5) ? names[level] : "Unknown";
    }
    
    static bool isValidLevel(int level) {
        return (level >= JUNIOR && level <= EXECUTIVE);
    }
};

// Forward declarations
class Task;

// Base User Class
class User {
protected:
    char username[max_usernameLength];
    char hashedPassword[max_passwordLength];
    char role[max_roleLength];
    int clearanceLevel;

public:
    User();
    User(const char* uname, const char* hashedPwd, const char* userRole, int clearance);
    virtual ~User();

    virtual void showDashboard() = 0;
    bool verifyPassword(const char* inputPwd);
    int getClearanceLevel() const;
    const char* getRole() const;
    const char* getUsername() const;
};

// Role Classes
class Junior : public User {
public:
    Junior(const char* uname, const char* hashedPwd);
    void showDashboard();
};

class Employee : public Junior {
public:
    Employee(const char* uname, const char* hashedPwd);
    void showDashboard();
};

class Manager : public Employee {
public:
    Manager(const char* uname, const char* hashedPwd);
    void showDashboard();
};

class Director : public Manager {
public:
    Director(const char* uname, const char* hashedPwd);
    void showDashboard();
};

class Executive : public Director {
public:
    Executive(const char* uname, const char* hashedPwd);
    void showDashboard();
};

// Task Status Constants
enum TaskStatus { CREATED, ASSIGNED, IN_PROGRESS, COMPLETED, EXPIRED };
const int max_taskTitleLength = 50;
const int max_taskContentLength = 100;
const int max_priorityLevelLength = 10;

// Task Class
class Task {
private:
    int taskID;
    char title[max_taskTitleLength];
    char content[max_taskContentLength];
    char creator[max_usernameLength];
    char assignee[max_usernameLength];
    int status;
    char priority[max_priorityLevelLength];
    time_t createdTime;
    int ttlSeconds;
    char delegationChain[500];
    char signature[max_signatureLength];

public:
    Task();
    Task(int id, const char* t, const char* c, const char* createdBy, const char* assignedTo, const char* taskPriority, int ttl);

    void setPriority(const char* newPriority);
    void addToDelegationChain(const char* user);
    bool isInDelegationChain(const char* user);
    void updateStatus(int newStatus);
    void displayTask();
    bool isExpired();
    const char* getCreator();
    const char* getAssignee();
    const char* getPriority();
    int getID();
    void signTask(const char* approver);
    const char* getSignature() const;

    Task& operator+=(const char* newAssignee);
    friend ostream& operator<<(ostream& out, const Task& t);
};

// PolicyEngine Class
class PolicyEngine {
private:
    PolicyEngine() {} // Private constructor

public:
    static bool canSendMessage(const User* sender, const User* receiver, const char* messageType);
    static bool canDelegateTask(const User* delegator, const User* delegatee);
    static bool hasClearance(const User* user, int requiredLevel);
    static bool canSendNotification(const User* sender, const char* notificationType);
    static bool canModifyTask(const User* user, const Task* task);
    static bool canEscalatePriority(const User* user, const char* currentPriority, const char* newPriority);
};

// AuthenticationManager Class
class AuthenticationManager {
private:
    char storedUsername[max_usernameLength];
    char storedHashedPassword[max_passwordLength];
    int loginAttempts;

public:
    AuthenticationManager();
    void loadCredentials(const char* uname, const char* hashedPwd);
    bool authenticate(const char* uname, const char* plainPwd);
    char* generateOTP();
    bool verifyOTP(const char* enteredOTP, const char* generatedOTP);
    int getLoginAttempts();
    void incrementLoginAttempts();
    void resetAttempts();
};

// TaskManager Class
const int max_tasks = 100;
class TaskManager {
private:
    Task* tasks[max_tasks];
    int taskCount;

public:
    TaskManager();
    ~TaskManager();
    void createTask(const char* title, const char* content, const char* creator, const char* assignee, const char* priority, int ttl);
    void listAllTasksByPriority();
    void checkAndExpireTasks();
    Task* findTaskByID(int id);
    void delegateTask(Task* task, const char* fromUser, const char* toUser);
};

// Messaging System
enum MessageType { INFO, PRIVATE, ALERT };
const int max_messageLength = 150;

class Message {
private:
    char sender[max_usernameLength];
    char receiver[max_usernameLength];
    char content[max_messageLength];
    MessageType type;
    time_t timestamp;

public:
    Message();
    Message(const char* sender, const char* receiver, const char* content, MessageType type);
    void encrypt();
    void decrypt();
    void display();
    const char* getReceiver() const;
    const char* getSender() const;
    MessageType getType() const;
    void writeToInbox();
};

class MessageManager {
public:
    void sendMessage(User* sender, User* receiver, const char* content, MessageType type);
    void readInbox(const char* username);
};

// AuditLogger Class
const int max_actionLength = 100;
const int max_statusLength = 30;
class AuditLogger {
public:
    static void logAction(const char* username, const char* action, const char* details, const char* status);
};

// PerformanceTracker Class
class PerformanceTracker {
private:
    char username[max_usernameLength];
    int completedTasks;
    int expiredTasks;
    int delegatedTasks;
    int messagesSent;

public:
    PerformanceTracker();
    PerformanceTracker(const char* uname);
    void incrementCompleted();
    void incrementExpired();
    void incrementDelegated();
    void incrementMessages();
    void generateReport();
};

// AnomalyDetector Class
class AnomalyDetector {
private:
    static int failedLoginCount;
    static int expiredTaskCount;
    static int lowToHighMessageCount;

public:
    static void reportLoginFailure(const char* username);
    static void reportExpiredTask(const char* username);
    static void reportLowToHighMessage(const char* sender, const char* receiver);
    static void flushAnomalies();
};

// Notification System
enum NotificationType { WARNING, EMERGENCY };
class NotificationManager {
public:
    static void sendGlobalNotification(const User* sender, const char* content, 
                                     NotificationType type, User* recipients[], int recipientCount);
};

// Helper Functions
void hashPassword(const char* input, char* output);
void buildTaskApprovalMessage(char details[], int taskID);

#endif