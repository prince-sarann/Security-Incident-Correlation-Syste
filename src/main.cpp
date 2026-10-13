#include <algorithm>
#include <cctype>
#include <iostream>
#include <queue>
#include <set>
#include <stack>
#include <string>
#include <unordered_map>
#include <vector>
using namespace std;

struct Event {
    int id;
    string time, ip, user, type, details;
};
struct Incident {
    string ip, severity;
    int score, failures, accounts;
    bool critical;
};
struct HigherScore {
    bool operator()(const Incident& a, const Incident& b) const {
        if (a.score != b.score) return a.score < b.score;
        return a.ip > b.ip;
    }
};

// BST indexes events by their unique ID.
class EventBST {
    struct Node {
        Event event;
        Node *left = nullptr, *right = nullptr;
        explicit Node(const Event& e) : event(e) {}
    };
    Node* root = nullptr;
    Node* add(Node* n, const Event& e) {
        if (!n) return new Node(e);
        if (e.id < n->event.id) n->left = add(n->left, e);
        else if (e.id > n->event.id) n->right = add(n->right, e);
        return n;
    }
    const Event* search(Node* n, int id) const {
        if (!n) return nullptr;
        if (n->event.id == id) return &n->event;
        return id < n->event.id ? search(n->left, id) : search(n->right, id);
    }
    void clear(Node* n) {
        if (!n) return;
        clear(n->left); clear(n->right); delete n;
    }
public:
    ~EventBST() { clear(root); }
    void insert(const Event& e) { root = add(root, e); }
    const Event* find(int id) const { return search(root, id); }
};

string lower(string s) {
    transform(s.begin(), s.end(), s.begin(),
              [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return s;
}
bool failedLogin(const Event& e) {
    string t = lower(e.type);
    return t == "failed_login" || t == "login_failed";
}
bool criticalEvent(const Event& e) {
    string t = lower(e.type);
    return t == "malware_detected" || t == "privilege_escalation" ||
           t == "ransomware_alert";
}
string severity(int score) {
    if (score >= 6) return "CRITICAL";
    if (score >= 4) return "HIGH";
    if (score >= 2) return "MEDIUM";
    return "LOW";
}

vector<Event> demoEvents() {
    return {
        {1,"09:00:01","192.168.1.20","alex","failed_login","Incorrect password"},
        {2,"09:00:04","192.168.1.20","alex","failed_login","Incorrect password"},
        {3,"09:00:08","192.168.1.20","sam","failed_login","Incorrect password"},
        {4,"09:00:12","192.168.1.20","jordan","failed_login","Incorrect password"},
        {5,"09:01:03","10.0.0.15","mira","successful_login","Normal sign-in"},
        {6,"09:02:10","10.0.0.15","mira","file_access","Opened course notes"},
        {7,"09:03:20","172.16.0.9","service","malware_detected","Simulated malware signature"},
        {8,"09:03:25","172.16.0.9","admin","privilege_escalation","Unexpected admin privilege"},
        {9,"09:04:01","192.168.1.20","alex","successful_login","Sign-in after repeated failures"},
        {10,"09:05:11","10.0.0.21","lee","failed_login","Single failed attempt"}
    };
}

void analyze(const vector<Event>& events) {
    queue<Event> incoming;
    unordered_map<string, vector<Event>> byIp;
    unordered_map<string, int> failedCounts;
    stack<int> recentIds;
    EventBST eventIndex;

    for (const auto& e : events) {
        incoming.push(e);
        eventIndex.insert(e);
    }

    cout << "\n--- PROCESSING EVENTS (FIFO QUEUE) ---\n";
    while (!incoming.empty()) {
        Event e = incoming.front();
        incoming.pop();
        byIp[e.ip].push_back(e);
        if (failedLogin(e)) ++failedCounts[e.ip];
        recentIds.push(e.id);
        cout << "Processed #" << e.id << " from " << e.ip << '\n';
    }

    cout << "\nRecent event IDs (newest first, max 5): ";
    for (int i = 0; i < 5 && !recentIds.empty(); ++i) {
        cout << recentIds.top() << ' ';
        recentIds.pop();
    }
    cout << '\n';

    priority_queue<Incident, vector<Incident>, HigherScore> alerts;
    for (const auto& group : byIp) {
        const string& ip = group.first;
        set<string> targetedUsers;
        bool critical = false;
        for (const auto& e : group.second) {
            if (failedLogin(e)) targetedUsers.insert(e.user);
            if (criticalEvent(e)) critical = true;
        }
        int failures = failedCounts[ip];
        int accounts = static_cast<int>(targetedUsers.size());
        int score = 0;
        if (failures >= 3) score += 3;
        if (accounts >= 3) score += 2;
        if (critical) score += 4;
        if (score > 0)
            alerts.push({ip, severity(score), score, failures, accounts, critical});
    }

    cout << "\n--- CORRELATED INCIDENT REPORT ---\n";
    if (alerts.empty()) cout << "No incidents matched the rules.\n";
    while (!alerts.empty()) {
        Incident a = alerts.top(); alerts.pop();
        cout << "\n[" << a.severity << "] Source IP: " << a.ip << '\n'
             << "  Risk score: " << a.score << '\n'
             << "  Failed logins: " << a.failures << '\n'
             << "  Distinct usernames targeted: " << a.accounts << '\n'
             << "  Critical event observed: " << (a.critical ? "Yes" : "No") << '\n';
    }

    cout << "\nBST lookup demonstration (event ID 1): ";
    const Event* found = eventIndex.find(1);
    if (found) cout << found->type << " from " << found->ip << '\n';
    else cout << "not found\n";
    cout << "\nAnalysis complete. Educational simulator only.\n";
}

int main() {
    cout << "============================================\n"
         << " SECURITY INCIDENT CORRELATION SYSTEM\n"
         << "          C++17 EDUCATIONAL DEMO\n"
         << "============================================\n"
         << "1. Run built-in demo\n"
         << "2. Demo + add custom simulated events\n"
         << "Choose (1 or 2): ";
    string choice;
    getline(cin, choice);
    if (choice != "1" && choice != "2") {
        cout << "Invalid choice. Run again and enter 1 or 2.\n";
        return 0;
    }

    vector<Event> events = demoEvents();
    if (choice == "2") {
        cout << "Number of custom events to add (0-50): ";
        string countText;
        getline(cin, countText);
        int count = 0;
        try {
            size_t used = 0;
            count = stoi(countText, &used);
            if (used != countText.size() || count < 0 || count > 50) {
                cout << "Enter a whole number from 0 to 50.\n";
                return 0;
            }
        } catch (...) {
            cout << "Invalid number.\n";
            return 0;
        }
        for (int i = 0; i < count; ++i) {
            Event e;
            e.id = static_cast<int>(events.size()) + 1;
            cout << "\nEvent " << i + 1 << " timestamp: "; getline(cin, e.time);
            cout << "Source IP: "; getline(cin, e.ip);
            cout << "Username: "; getline(cin, e.user);
            cout << "Event type (failed_login, successful_login, malware_detected, "
                    "privilege_escalation, ransomware_alert, file_access): ";
            getline(cin, e.type);
            cout << "Details: "; getline(cin, e.details);
            if (e.time.empty() || e.ip.empty() || e.user.empty() || e.type.empty()) {
                cout << "Required field missing; event skipped.\n";
                continue;
            }
            events.push_back(e);
        }
    }

    cout << "\n--- SIMULATED SECURITY EVENTS ---\n";
    for (const auto& e : events)
        cout << '#' << e.id << " [" << e.time << "] " << e.ip << " | "
             << e.user << " | " << e.type << " | " << e.details << '\n';
    analyze(events);
    return 0;
}
