#include <iostream>
#include <ctime>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <unistd.h> // for sleep on Unix-based systems
#include "header.h"
using namespace std;

bool PolicyEngine::canSendMessage(const User* sender, const User* receiver, const char* messageType) {
    if (!sender || !receiver) return false;
    
    int senderLevel = sender->getClearanceLevel();
    int receiverLevel = receiver->getClearanceLevel();

    // INFO messages can be sent by anyone to anyone
    if (strcmp(messageType, "INFO") == 0) return true;
    
    // PRIVATE: Can send to same or higher level (Junior→Manager allowed)
    else if (strcmp(messageType, "PRIVATE") == 0) 
        return receiverLevel >= senderLevel;
    
    // ALERT: Only Director+ can send to same or lower level
    else if (strcmp(messageType, "ALERT") == 0)
        return (senderLevel >= RoleSystem::DIRECTOR) && (receiverLevel <= senderLevel);
    
    return false;
}

bool PolicyEngine::canDelegateTask(const User* delegator, const User* delegatee) {
    if (!delegator || !delegatee) return false;
    
    // Only Manager+ can delegate
    if (delegator->getClearanceLevel() < RoleSystem::MANAGER) return false;
    
    // Delegator must have higher or equal clearance than delegatee
    return delegator->getClearanceLevel() >= delegatee->getClearanceLevel();
}

void hashPassword(const char* input, char* output) {
    int len = strlen(input);
    for (int i = 0; i < len; i++) {
        output[i] = input[i] + 3;
    }
    output[len] = '\0';
}

// === Task Implementation ===
Task::Task() {
    taskID = 0;
    strcpy(title, "");
    strcpy(content, "");
    strcpy(creator, "");
    strcpy(assignee, "");
    strcpy(priority, "Low");
    status = CREATED;
    createdTime = time(0);
    ttlSeconds = 60;
}

Task::Task(int id, const char* t, const char* c, const char* createdBy, const char* assignedTo, const char* taskPriority, int ttl) {
    taskID = id;
    strcpy(title, t);
    strcpy(content, c);
    strcpy(creator, createdBy);
    strcpy(assignee, assignedTo);
    strcpy(priority, taskPriority);
    status = CREATED;
    createdTime = time(0);
    ttlSeconds = ttl;
}


void Task::updateStatus(int newStatus) {
    status = newStatus;
}

// In Task.cpp:

void Task::addToDelegationChain(const char* user) {
    strcat(delegationChain, user); // Append user to delegation chain
    strcat(delegationChain, " -> ");
}

bool Task::isInDelegationChain(const char* user) {
    return strstr(delegationChain, user) != NULL; // Check if the user is in the chain
}


bool Task::isExpired() {
    time_t now = time(0);
    return (difftime(now, createdTime) >= ttlSeconds);
}

const char* Task::getCreator() { return creator; }
const char* Task::getAssignee() { return assignee; }
const char* Task::getPriority() { return priority; }
int Task::getID() { return taskID; }

void Task::displayTask() {
    cout << "\n[Task ID: " << taskID << "]\n";
    cout << "Title: " << title << "\n";
    cout << "Content: " << content << "\n";
    cout << "Creator: " << creator << "\n";
    cout << "Assignee: " << assignee << "\n";
    cout << "Priority: " << priority << "\n";
    cout << "Status: ";
    switch (status) {
        case CREATED: cout << "Created"; break;
        case ASSIGNED: cout << "Assigned"; break;
        case IN_PROGRESS: cout << "In Progress"; break;
        case COMPLETED: cout << "Completed"; break;
        case EXPIRED: cout << "Expired"; break;
    }
    cout << "\n----------------------------\n";
}

Task& Task::operator+=(const char* newAssignee) {
    strcpy(assignee, newAssignee);
    updateStatus(ASSIGNED);
    return *this;
}

ostream& operator<<(ostream& out, const Task& t) {
    out << "[Task #" << t.taskID << "] ";
    out << "From: " << t.creator << " -> " << t.assignee << ", ";
    out << "Priority: " << t.priority << ", ";
    out << "Status: ";
    switch (t.status) {
        case CREATED: out << "Created"; break;
        case ASSIGNED: out << "Assigned"; break;
        case IN_PROGRESS: out << "In Progress"; break;
        case COMPLETED: out << "Completed"; break;
        case EXPIRED: out << "Expired"; break;
    }
    out << "\n";
    return out;
}

TaskManager::TaskManager() {
    taskCount = 0;
    for (int i = 0; i < max_tasks; i++) tasks[i] = NULL;
}

TaskManager::~TaskManager() {
    for (int i = 0; i < taskCount; i++) {
        delete tasks[i];
    }
}

// In TaskManager.cpp:

void TaskManager::delegateTask(Task* task, const char* fromUser, const char* toUser) {
    if (task->isInDelegationChain(toUser)) {
        cout << "[ERROR] Cannot delegate task: cycle detected in delegation chain.\n";
        return; // Block delegation if cycle detected
    }

    task->addToDelegationChain(toUser);
    cout << "[INFO] Task delegated successfully from " << fromUser << " to " << toUser << ".\n";
}


void TaskManager::createTask(const char* title, const char* content, const char* creator, const char* assignee, const char* priority, int ttl) {
    if (taskCount < max_tasks) {
        tasks[taskCount] = new Task(taskCount + 1, title, content, creator, assignee, priority, ttl);
        taskCount++;
    } else {
        cout << "Task limit reached!\n";
    }
}

void TaskManager::listAllTasksByPriority() {
    // First: High
    for (int i = 0; i < taskCount; ++i)
        if (strcmp(tasks[i]->getPriority(), "High") == 0)
            tasks[i]->displayTask();
    // Then: Medium
    for (int i = 0; i < taskCount; ++i)
        if (strcmp(tasks[i]->getPriority(), "Medium") == 0)
            tasks[i]->displayTask();
    // Then: Low
    for (int i = 0; i < taskCount; ++i)
        if (strcmp(tasks[i]->getPriority(), "Low") == 0)
            tasks[i]->displayTask();
}

void Task::setPriority(const char* newPriority) {
    strncpy(priority, newPriority, max_priorityLevelLength);
}

void TaskManager::checkAndExpireTasks() {
    for (int i = 0; i < taskCount; i++) {
        if (tasks[i]->isExpired()) {
            tasks[i]->updateStatus(EXPIRED);
        }
    }
}

Task* TaskManager::findTaskByID(int id) {
    for (int i = 0; i < taskCount; i++) {
        if (tasks[i]->getID() == id)
            return tasks[i];
    }
    return NULL;
}



//................user class...............

User::User() {
    strcpy(username, "");
    strcpy(hashedPassword, "");
    strcpy(role, "User");
    clearanceLevel = RoleSystem::JUNIOR;
}

User::User(const char* uname, const char* hashedPwd, const char* userRole, int clearance) {
    strncpy(username, uname, max_usernameLength);
    strncpy(hashedPassword, hashedPwd, max_passwordLength);
    strncpy(role, userRole, max_roleLength);
    clearanceLevel = clearance;
}

User::~User() {
    // Cleanup if needed
}

bool User::verifyPassword(const char* inputPwd) {
    return strcmp(hashedPassword, inputPwd) == 0;
}

int User::getClearanceLevel() const {
    return clearanceLevel;
}

const char* User::getRole() const {
    return role;
}

const char* User::getUsername() const {
    return username;
}


Junior::Junior(const char* uname, const char* hashedPwd)
    : User(uname, hashedPwd, "Junior", RoleSystem::JUNIOR) {}

void Junior::showDashboard() {
    cout << "\n[Junior Dashboard for " << username << "]\n";
}

Employee::Employee(const char* uname, const char* hashedPwd)
    : Junior(uname, hashedPwd) {
    strcpy(role, "Employee");
    clearanceLevel = RoleSystem::EMPLOYEE;
}

void Employee::showDashboard() {
    cout << "\n[Employee Dashboard for " << username << "]\n";
}

Manager::Manager(const char* uname, const char* hashedPwd)
    : Employee(uname, hashedPwd) {
    strcpy(role, "Manager");
    clearanceLevel = RoleSystem::MANAGER;
}

void Manager::showDashboard() {
    cout << "\n[Manager Dashboard for " << username << "]\n";
}

Director::Director(const char* uname, const char* hashedPwd)
    : Manager(uname, hashedPwd) {
    strcpy(role, "Director");
    clearanceLevel = RoleSystem::DIRECTOR;
}

void Director::showDashboard() {
    cout << "\n[Director Dashboard for " << username << "]\n";
}

Executive::Executive(const char* uname, const char* hashedPwd)
    : Director(uname, hashedPwd) {
    strcpy(role, "Executive");
    clearanceLevel = RoleSystem::EXECUTIVE;
}

void Executive::showDashboard() {
    cout << "\n[Executive Dashboard for " << username << "]\n";
}

bool PolicyEngine::hasClearance(const User* user, int requiredLevel) {
    return user->getClearanceLevel() >= requiredLevel;
}

bool PolicyEngine::canSendNotification(const User* sender, const char* notificationType) {
    if (strcmp(notificationType, "WARNING") == 0 || strcmp(notificationType, "EMERGENCY") == 0) {
        return sender->getClearanceLevel() >= RoleSystem::MANAGER; // Only Managers and Executives
    }
    return false;
}

AuthenticationManager::AuthenticationManager() {
    strcpy(storedUsername, "");
    strcpy(storedHashedPassword, "");
    loginAttempts = 0;
}

void AuthenticationManager::loadCredentials(const char* uname, const char* hashedPwd) {
    strncpy(storedUsername, uname, max_usernameLength);
    strncpy(storedHashedPassword, hashedPwd, max_passwordLength);
}

bool AuthenticationManager::authenticate(const char* uname, const char* plainPwd) {
    return strcmp(storedUsername, uname) == 0 && strcmp(storedHashedPassword, plainPwd) == 0;
}

char* AuthenticationManager::generateOTP() {
    static char otp[7];
    srand(time(0));
    for (int i = 0; i < 6; i++) {
        otp[i] = '0' + rand() % 10;
    }
    otp[6] = '\0';
    return otp;
}

bool AuthenticationManager::verifyOTP(const char* enteredOTP, const char* generatedOTP) {
    return strcmp(enteredOTP, generatedOTP) == 0;
}

int AuthenticationManager::getLoginAttempts() {
    return loginAttempts;
}

void AuthenticationManager::incrementLoginAttempts() {
    loginAttempts++;
}

void AuthenticationManager::resetAttempts() {
    loginAttempts = 0;
}


// ================= Message Class Implementation =================

Message::Message() {
    strcpy(sender, "");
    strcpy(receiver, "");
    strcpy(content, "");
    type = INFO;
    timestamp = time(0);
}

Message::Message(const char* s, const char* r, const char* msg, MessageType t) {
    strncpy(sender, s, max_usernameLength);
    strncpy(receiver, r, max_usernameLength);
    strncpy(content, msg, max_messageLength);
    type = t;
    timestamp = time(0);
}

void Message::encrypt() {
    for (int i = 0; i < strlen(content); i++) {
        content[i] = content[i] + 3; // simple Caesar cipher
    }
}

void Message::decrypt() {
    for (int i = 0; i < strlen(content); i++) {
        content[i] = content[i] - 3;
    }
}

const char* Message::getReceiver() const {
    return receiver;
}

const char* Message::getSender() const {
    return sender;
}

MessageType Message::getType() const {
    return type;
}

void Message::display() {
    cout << "\n[FROM: " << sender << "] ";
    switch (type) {
        case INFO: cout << "[INFO] "; break;
        case PRIVATE: cout << "[PRIVATE] "; break;
        case ALERT: cout << "[ALERT] "; break;
    }
    cout << content << "\n";
}

void Message::writeToInbox() {
    char filename[50];
    strcpy(filename, receiver);
    strcat(filename, "_inbox.txt");

    ofstream fout(filename, ios::app);
    if (!fout) {
        cout << "[ERROR] Unable to open inbox file for " << receiver << ".\n";
        return;
    }

    fout << "[FROM: " << sender << "] ";
    switch (type) {
        case INFO: fout << "[INFO] "; break;
        case PRIVATE: fout << "[PRIVATE] "; break;
        case ALERT: fout << "[ALERT] "; break;
    }
    fout << content << "\n";

    fout.close();
}


// ================= MessageManager Class Implementation =================

void MessageManager::sendMessage(User* sender, User* receiver, const char* msgContent, MessageType msgType) {
    // Convert enum to string for policy check
    const char* typeStr = (msgType == INFO) ? "INFO" : (msgType == PRIVATE ? "PRIVATE" : "ALERT");

    // Check permissions
    if (!PolicyEngine::canSendMessage(sender, receiver, typeStr)) {
        cout << "[ERROR] Message type not allowed between these users.\n";
        return;
    }

    // Create and process message
    Message msg(sender->getUsername(), receiver->getUsername(), msgContent, msgType);

    if (msgType == PRIVATE) {
        msg.encrypt();
    }

    msg.writeToInbox();

    cout << "[Message SENT successfully to " << receiver->getUsername() << "]\n";
}

void MessageManager::readInbox(const char* username) {
    char filename[50];
    strcpy(filename, username);
    strcat(filename, "_inbox.txt");

    ifstream fin(filename);
    if (!fin) {
        cout << "[INFO] No messages for user " << username << ". Inbox not found.\n";
        return;
    }

    cout << "\n=========== INBOX for " << username << " ===========\n";

    char line[200];
    while (fin.getline(line, 200)) {
        cout << line << "\n";
    }

    cout << "==============================================\n";
    fin.close();
}


// ========== AuditLogger Implementation ==========
void AuditLogger::logAction(const char* username, const char* action, const char* details, const char* status) {
    ofstream fout("audit.txt", ios::app); // Append mode
    if (!fout) {
        cout << "[ERROR] Could not write to audit log.\n";
        return;
    }

    // Get current timestamp
    time_t now = time(0);
    char* dt = ctime(&now);  // Format: "Wed Apr 30 17:31:12 2025\n"
    dt[strlen(dt) - 1] = '\0';  // Remove trailing newline

    fout << "[" << dt << "] ";
    fout << username << " ";
    fout << action << " ";
    fout << details << " ";
    fout << status << "\n";

    fout.close();
}


// ========== PerformanceTracker Implementation ==========

PerformanceTracker::PerformanceTracker() {
    strcpy(username, "");
    completedTasks = 0;
    expiredTasks = 0;
    delegatedTasks = 0;
    messagesSent = 0;
}

PerformanceTracker::PerformanceTracker(const char* uname) {
    strncpy(username, uname, max_usernameLength);
    completedTasks = 0;
    expiredTasks = 0;
    delegatedTasks = 0;
    messagesSent = 0;
}

void PerformanceTracker::incrementCompleted() {
    completedTasks++;
}

void PerformanceTracker::incrementExpired() {
    expiredTasks++;
}

void PerformanceTracker::incrementDelegated() {
    delegatedTasks++;
}

void PerformanceTracker::incrementMessages() {
    messagesSent++;
}

void PerformanceTracker::generateReport() {
    ofstream fout("performance.txt", ios::app);
    if (!fout) {
        cout << "[ERROR] Could not open performance.txt\n";
        return;
    }

    fout << "[User: " << username << "] "
         << "Completed: " << completedTasks << " | "
         << "Expired: " << expiredTasks << " | "
         << "Delegated: " << delegatedTasks << " | "
         << "Messages Sent: " << messagesSent << "\n";

    fout.close();
}

int AnomalyDetector::failedLoginCount = 0;
int AnomalyDetector::expiredTaskCount = 0;
int AnomalyDetector::lowToHighMessageCount = 0;

void AnomalyDetector::reportLoginFailure(const char* username) {
    failedLoginCount++;
    if (failedLoginCount > 3) {
        ofstream fout("anomaly_log.txt", ios::app);
        time_t now = time(0);
        fout << "[" << ctime(&now);
        fout.seekp(-1, ios::cur);
        fout << "] ALERT: User '" << username << "' attempted 4+ logins - POSSIBLE BRUTE FORCE\n";
        fout.close();
    }
}

void AnomalyDetector::reportExpiredTask(const char* username) {
    expiredTaskCount++;
    if (expiredTaskCount > 5) {
        ofstream fout("anomaly_log.txt", ios::app);
        time_t now = time(0);
        fout << "[" << ctime(&now);
        fout.seekp(-1, ios::cur);
        fout << "] ALERT: User '" << username << "' has 6+ expired tasks - PERFORMANCE ISSUE\n";
        fout.close();
    }
}

void AnomalyDetector::reportLowToHighMessage(const char* sender, const char* receiver) {
    lowToHighMessageCount++;
    if (lowToHighMessageCount >= 3) {
        ofstream fout("anomaly_log.txt", ios::app);
        time_t now = time(0);
        fout << "[" << ctime(&now);
        fout.seekp(-1, ios::cur);
        fout << "] ALERT: '" << sender << "' sent 3+ messages to higher role '" << receiver << "' - SUSPICIOUS\n";
        fout.close();
        lowToHighMessageCount = 0; // reset counter
    }
}

void AnomalyDetector::flushAnomalies() {
    failedLoginCount = 0;
    expiredTaskCount = 0;
    lowToHighMessageCount = 0;
}


// Implementation of NotificationManager
void NotificationManager::sendGlobalNotification(const User* sender,
                                                 const char* content,
                                                 NotificationType type,
                                                 User* recipients[],
                                                 int recipientCount) {
    // Only Manager and Executive can send WARNING/EMERGENCY
    int level = sender->getClearanceLevel();
    if ((type == WARNING || type == EMERGENCY) && level < RoleSystem::MANAGER) {
        std::cout << "[ERROR] Insufficient clearance to send global notifications.\n";
        return;
    }
    
    // Prepare notification header
    const char* typeStr = (type == WARNING ? "WARNING" : "EMERGENCY");
    
    // Dispatch to each recipient
    for (int i = 0; i < recipientCount; ++i) {
        const char* recvName = recipients[i]->getUsername();
        
        // Write to recipient inbox
        char filename[50];
        strcpy(filename, recvName);
        strcat(filename, "_inbox.txt");
        
        std::ofstream fout(filename, std::ios::app);
        fout << "[NOTIFICATION: " << typeStr << "] " << content << "\n";
        fout.close();
    }
    
    // Audit log the notification
    AuditLogger::logAction(sender->getUsername(), "NOTIFICATION_SENT",
                           typeStr, "DELIVERED");
}
void Task::signTask(const char* approver) {
    time_t now = time(0);
    std::ostringstream oss;

    oss << std::hex << std::setw(8) << std::setfill('0') << static_cast<unsigned long>(now);

    unsigned int sum = 0;
    for (int i = 0; approver[i] != '\0'; ++i) {
        sum += (unsigned char)approver[i];
    }

    oss << std::hex << std::setw(4) << std::setfill('0') << sum;

    std::string sig = oss.str();

    // SAFE COPY (no overflow)
    strncpy(signature, sig.data(), sizeof(signature) - 1);
    signature[sizeof(signature) - 1] = '\0';
}

const char* Task::getSignature() const {
    return signature;
}




// ================= Helper Function =================
void buildTaskApprovalMessage(char details[], int taskID) {
    int index = 0;

    // Add "Task #"
    details[index++] = 'T';
    details[index++] = 'a';
    details[index++] = 's';
    details[index++] = 'k';
    details[index++] = ' ';
    details[index++] = '#';

    // Convert taskID to digits
    int digits[10];
    int digitCount = 0;
    int temp = taskID;

    if (temp == 0) {
        details[index++] = '0';
    } else {
        while (temp > 0) {
            digits[digitCount++] = temp % 10;
            temp /= 10;
        }
        for (int i = digitCount - 1; i >= 0; i--) {
            details[index++] = '0' + digits[i];
        }
    }

    // Add " approved"
    details[index++] = ' ';
    details[index++] = 'a';
    details[index++] = 'p';
    details[index++] = 'p';
    details[index++] = 'r';
    details[index++] = 'o';
    details[index++] = 'v';
    details[index++] = 'e';
    details[index++] = 'd';

    details[index] = '\0'; // Null terminator
}



void notificationMenu(User* user) {
    if (user->getClearanceLevel() < RoleSystem::MANAGER) {
        cout << "[ACCESS DENIED] Only Managers & Executives can send notifications.\n";
        return;
    }

    char choice;
    do {
        cout << "\n==================== NOTIFICATIONS ====================\n";
        cout << "1. 📢 Send Notification\n";
        cout << "2. 🔙 Back to Dashboard\n";
        cout << "=======================================================\n";
        cout << "Enter choice: ";
        cin >> choice;

        if (choice == '1') {
            char content[150];
            int type;

            cout << "Enter content: ";
            cin.ignore(); cin.getline(content, 150);
            cout << "Type:\n1. WARNING\n2. EMERGENCY\nEnter: ";
            cin >> type;

            NotificationType nt;
            if (type == 1) nt = WARNING;
            else if (type == 2) nt = EMERGENCY;
            else {
                cout << "[ERROR] Invalid type.\n";
                continue;
            }

            // Simulate 3 users to receive
            Junior j("junaid", "jjj");
            Employee e("ali", "emp");
            Director d("sana", "dir");

            User* allUsers[] = { &j, &e, &d };
            NotificationManager::sendGlobalNotification(user, content, nt, allUsers, 3);
        } 
        else if (choice == '2') {
            break;
        } 
        else {
            cout << "[ERROR] Invalid.\n";
        }
    } while (true);
}




void messagingMenu(User* user) {
    MessageManager msgManager;
    char choice;
    do {
        cout << "\n==================== MESSAGING SYSTEM ====================\n";
        cout << "1. 📤 Send Message\n";
        cout << "2. 📥 Read Inbox\n";
        cout << "3. 🔙 Back to Dashboard\n";
        cout << "==========================================================\n";
        cout << "Enter choice: ";
        cin >> choice;

        if (choice == '1') {
            char receiver[50], content[150];
            int type;

            cout << "Enter recipient username: ";
            cin >> receiver;
            cout << "Enter message content: ";
            cin.ignore();
            cin.getline(content, 150);
            cout << "Type:\n1. INFO\n2. PRIVATE (encrypted)\n3. ALERT\nChoice: ";
            cin >> type;

            MessageType msgType;
            if (type == 1) msgType = INFO;
            else if (type == 2) msgType = PRIVATE;
            else if (type == 3) msgType = ALERT;
            else {
                cout << "[ERROR] Invalid type.\n";
                continue;
            }

            // Simulate receiver creation (dummy logic for testing only)
            Executive fakeReceiver(receiver, "temp123");
            msgManager.sendMessage(user, &fakeReceiver, content, msgType);

            AuditLogger::logAction(user->getUsername(), "MESSAGE_SENT", content, "DELIVERED");
        } 
        else if (choice == '2') {
            msgManager.readInbox(user->getUsername());
        } 
        else if (choice == '3') {
            break;
        } 
        else {
            cout << "[ERROR] Invalid input.\n";
        }
    } while (true);
}




void taskMenu(User* user) {
    TaskManager taskManager;
    char choice;
    do {
        cout << "\n==================== TASK SYSTEM ====================\n";
        cout << "1. ➕ Create Task\n";
        cout << "2. 📜 View All Tasks by Priority\n";
        cout << "3. 🔄 Delegate Task\n";
        cout << "4. ⏳ Check & Expire Tasks\n";
        cout << "5. 🔙 Back to Dashboard\n";
        cout << "=====================================================\n";
        cout << "Enter choice: ";
        cin >> choice;

        if (choice == '1') {
            char title[100], content[100], assignee[50], priority[10];
            int ttl;

            cout << "Enter title: "; cin.ignore(); cin.getline(title, 100);
            cout << "Enter content: "; cin.getline(content, 100);
            cout << "Assign to (username): "; cin >> assignee;
            cout << "Priority (High/Medium/Low): "; cin >> priority;
            cout << "Time-to-live (seconds): "; cin >> ttl;

            taskManager.createTask(title, content, user->getUsername(), assignee, priority, ttl);
            AuditLogger::logAction(user->getUsername(), "TASK_CREATED", title, "CREATED");
        } 
        else if (choice == '2') {
            taskManager.listAllTasksByPriority();
        } 
        else if (choice == '3') {
            int id;
            char toUser[50];
            cout << "Enter Task ID to delegate: ";
            cin >> id;
            cout << "Delegate to (username): ";
            cin >> toUser;

            Task* t = taskManager.findTaskByID(id);
            if (!t) {
                cout << "Task not found.\n";
            } else {
                if (PolicyEngine::canDelegateTask(user, user)) { // Replace with proper lookup later
                    taskManager.delegateTask(t, user->getUsername(), toUser);
                    *t += toUser;
                    AuditLogger::logAction(user->getUsername(), "TASK_DELEGATED", toUser, "SUCCESS");
                } else {
                    cout << "You are not allowed to delegate to this user.\n";
                }
            }
        } 
        else if (choice == '4') {
            taskManager.checkAndExpireTasks();
            AuditLogger::logAction(user->getUsername(), "TASK_EXPIRY_CHECK", "System checked", "DONE");
        } 
        else if (choice == '5') {
            break;
        } 
        else {
            cout << "[ERROR] Invalid input.\n";
        }
    } while (true);
}



void showInstructions() {
    cout << "\n==================== SYSTEM OVERVIEW ====================\n";
    cout << "🔐 Login/Register:\n";
    cout << "  - Log in with your credentials (username/password)\n";
    cout << "  - Register as a new user and select your role\n";
    cout << "  - Multi-Factor Authentication via OTP is used\n\n";

    cout << "📋 Task System:\n";
    cout << "  - Create, assign, delegate, and expire tasks\n";
    cout << "  - Tasks have priorities: High, Medium, Low\n";
    cout << "  - Delegation follows clearance levels\n\n";

    cout << "💬 Messaging System:\n";
    cout << "  - Send INFO, PRIVATE (encrypted), or ALERT messages\n";
    cout << "  - Messages are governed by RBAC (Role-Based Access Control)\n\n";

    cout << "🔔 Notifications:\n";
    cout << "  - Managers/Executives can send WARNING/EMERGENCY alerts\n\n";

    cout << "🧾 Audit Logs:\n";
    cout << "  - All actions are logged securely in audit.txt\n\n";

    cout << "📊 Performance Reports:\n";
    cout << "  - Track completed, expired, and delegated tasks\n";

    cout << "🚨 Anomaly Detection:\n";
    cout << "  - Flags suspicious activities like repeated login failures\n";

    cout << "\n========================================================\n";
    cout << "🔄 You can explore different modules after logging in.\n";
    cout << "All actions are access-controlled based on your role.\n";
    cout << "If you're new, register and the system will guide you.\n";
    cout << "========================================================\n\n";
}




void mainDashboard(User* user) {
    char choice;
    do {
        cout << "\n==================== MAIN DASHBOARD ====================\n";
        cout << "Welcome, " << user->getUsername() << " [" << user->getRole() << "]\n";
        cout << "What would you like to do?\n";
        cout << "1. 📋 Task System\n";
        cout << "2. 💬 Messaging System\n";
        cout << "3. 🔔 Global Notifications\n";
        cout << "4. 🧾 Performance Report\n";
        cout << "5. 📂 Audit Logs\n";
        cout << "6. 🚨 Anomaly Reports\n";
        cout << "7. ❓ Help / System Info\n";
        cout << "8. 🔒 Logout\n";
        cout << "========================================================\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case '1': taskMenu(user); break;
            case '2': messagingMenu(user); break;
            case '3': notificationMenu(user); break;
            case '4': {
                PerformanceTracker perf(user->getUsername());
                perf.generateReport();
                break;
            }
            case '5': {
                ifstream fin("audit.txt");
                if (!fin) cout << "[ERROR] audit.txt not found.\n";
                else {
                    cout << "\n========== Audit Logs ==========\n";
                    char line[200];
                    while (fin.getline(line, 200))
                        cout << line << "\n";
                    fin.close();
                }
                break;
            }
            case '6': {
                ifstream fin("anomaly_log.txt");
                if (!fin) cout << "[INFO] No anomalies found.\n";
                else {
                    cout << "\n========== Anomaly Reports ==========\n";
                    char line[200];
                    while (fin.getline(line, 200))
                        cout << line << "\n";
                    fin.close();
                }
                break;
            }
            case '7': showInstructions(); break;
            case '8': cout << "Logging out...\n"; return;
            default: cout << "[ERROR] Invalid input.\n";
        }

    } while (true);
}




// === INTERFACE SETUP ===
void welcomeScreen() {
    cout << "===================================================\n";
    cout << "   WELCOME TO OSIM - Organizational Simulation\n";
    cout << "      and Internal Management System (v1.0)\n";
    cout << "===================================================\n";
    cout << "This system simulates a professional organization where\n";
    cout << "you interact based on your role: Junior, Employee, Manager,\n";
    cout << "Director, or Executive.\n\n";
    cout << "Type '1' to view instructions.\n";
    cout << "Type '2' to proceed to Login/Register.\n";
    cout << "Type '3' to exit.\n";
    cout << "===================================================\n";
}








void registerUser() {
    char newUsername[max_usernameLength];
    char newPassword[max_passwordLength];
    char hashed[max_passwordLength];
    int roleChoice;
    char roleName[max_roleLength];
    int clearance = 0;

    cout << "\n==================== USER REGISTRATION ====================\n";
    cout << "Enter desired username: ";
    cin >> newUsername;
    cout << "Enter desired password: ";
    cin >> newPassword;

    hashPassword(newPassword, hashed);

    cout << "\nSelect Role:\n";
    cout << "1. Junior\n2. Employee\n3. Manager\n4. Director\n5. Executive\n";
    cout << "Enter choice: ";
    cin >> roleChoice;

    switch (roleChoice) {
        case 1: strcpy(roleName, "Junior"); clearance = RoleSystem::JUNIOR; break;
        case 2: strcpy(roleName, "Employee"); clearance = RoleSystem::EMPLOYEE; break;
        case 3: strcpy(roleName, "Manager"); clearance = RoleSystem::MANAGER; break;
        case 4: strcpy(roleName, "Director"); clearance = RoleSystem::DIRECTOR; break;
        case 5: strcpy(roleName, "Executive"); clearance = RoleSystem::EXECUTIVE; break;
        default:
            cout << "[ERROR] Invalid role. Registration failed.\n";
            return;
    }

    ofstream fout("users.txt", ios::app);
    fout << newUsername << " " << hashed << " " << roleName << " " << clearance << "\n";
    fout.close();

    cout << "[SUCCESS] User registered successfully!\n";
}

User* createUserFromDetails(const char* uname, const char* hashedPwd, const char* roleName, int clearance) {
    if (strcmp(roleName, "Junior") == 0) return new Junior(uname, hashedPwd);
    if (strcmp(roleName, "Employee") == 0) return new Employee(uname, hashedPwd);
    if (strcmp(roleName, "Manager") == 0) return new Manager(uname, hashedPwd);
    if (strcmp(roleName, "Director") == 0) return new Director(uname, hashedPwd);
    if (strcmp(roleName, "Executive") == 0) return new Executive(uname, hashedPwd);
    return nullptr;
}






void loginMenu() {
    AuthenticationManager auth;
    char uname[max_usernameLength];
    char pwd[max_passwordLength];
    char hashedInput[max_passwordLength];

    cout << "\n==================== USER LOGIN ====================\n";

    cout << "Username: ";
    cin >> uname;
    cout << "Password: ";
    cin >> pwd;

    hashPassword(pwd, hashedInput);

    // Search user in users.txt
    ifstream fin("users.txt");
    char fileUsername[max_usernameLength];
    char fileHashed[max_passwordLength];
    char fileRole[max_roleLength];
    int clearance;
    bool found = false;

    while (fin >> fileUsername >> fileHashed >> fileRole >> clearance) {
        if (strcmp(uname, fileUsername) == 0 && strcmp(hashedInput, fileHashed) == 0) {
            found = true;
            break;
        }
    }

    fin.close();

    if (!found) {
        AnomalyDetector::reportLoginFailure(uname);
        cout << "[ERROR] Invalid username or password.\n";
        return;
    }

    // Simulate OTP
    char* otp = auth.generateOTP();
    cout << "Your OTP (simulated secure inbox): " << otp << "\n";
    char entered[10];
    cout << "Enter OTP: ";
    cin >> entered;

    if (!auth.verifyOTP(entered, otp)) {
        cout << "[ERROR] Incorrect OTP. Login failed.\n";
        return;
    }

    // Create actual user object
    User* loggedInUser = createUserFromDetails(fileUsername, fileHashed, fileRole, clearance);
    if (!loggedInUser) {
        cout << "[ERROR] Could not create user object.\n";
        return;
    }

    AuditLogger::logAction(loggedInUser->getUsername(), "LOGIN", "MFA SUCCESS", "OK");
    AnomalyDetector::flushAnomalies();

    cout << "\n[LOGIN SUCCESSFUL] Welcome, " << loggedInUser->getUsername() << " (" << loggedInUser->getRole() << ")\n";
    loggedInUser->showDashboard();

    // 🚀 Next: move to system menu/dashboard
    mainDashboard(loggedInUser);

    delete loggedInUser;
}






int main() {
    char topChoice;

    do {
        welcomeScreen();
        cout << "Enter your choice: ";
        cin >> topChoice;

        switch (topChoice) {
            case '1':
                showInstructions();
                break;

            case '2': {
                char subChoice;
                cout << "\n1. Login\n2. Register\nEnter your choice: ";
                cin >> subChoice;

                if (subChoice == '1') {
                    // Call loginMenu(), which will authenticate and take user to mainDashboard()
                    loginMenu();
                } else if (subChoice == '2') {
                    // Register a new user
                    registerUser();
                } else {
                    cout << "[ERROR] Invalid option.\n";
                }
                break;
            }

            case '3':
                cout << "\n[EXIT] Thank you for using OSIM. Goodbye!\n";
                return 0;

            default:
                cout << "[ERROR] Invalid input. Please try again.\n";
        }

    } while (topChoice != '3');

    return 0;
}

