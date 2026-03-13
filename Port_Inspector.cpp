/*

Name: Odibendi Chukwuemelie Uchenna
Registration Number: 2024924004
Course Code: NAU-CYB 221
Level: 200l
Department: Cyber Security
Faculty: Physical Science

NAU-CYB 221 – Local Port Inspection Tool
Defensive – Local Machine Only
Linux Implementation using /proc filesystem
*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <unistd.h>     // getuid
#include <pwd.h>

using namespace std;

struct PortRecord {
    string proto;
    uint16_t port          = 0;
    string local_ip        = "?";
    string process_name    = "?";
    int    pid             = -1;
    string service         = "?";
    string risk            = "?";
    string flag            = "?";
    string state           = "";   // TCP only
};

set<uint16_t> SENSITIVE_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389,
    // add more if desired: 3306, 5432, 8080, 9200, etc.
};

bool is_root() {
    return getuid() == 0;
}

string trim(const string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

map<uint16_t, string> load_services() {
    map<uint16_t, string> svc;
    ifstream f("/etc/services");
    if (!f.is_open()) {
        cerr << "Warning: cannot open /etc/services\n";
        return svc;
    }

    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        stringstream ss(line);
        string name, portproto;
        if (!(ss >> name >> portproto)) continue;

        size_t slash = portproto.find('/');
        if (slash == string::npos) continue;

        string portstr = portproto.substr(0, slash);
        string proto   = portproto.substr(slash + 1);

        try {
            uint16_t port = static_cast<uint16_t>(stoi(portstr));
            if (proto == "tcp" || proto == "udp") {
                if (svc.find(port) == svc.end()) {  // prefer first entry
                    svc[port] = name;
                }
            }
        } catch (...) {
            // skip malformed lines
        }
    }
    return svc;
}

string hex_to_ip(const string& hexstr, uint16_t& port_out) {
    if (hexstr.length() < 13) return "?";

    string ip_hex   = hexstr.substr(0, 8);
    string port_hex = hexstr.substr(9, 4);

    uint32_t ip_num = 0;
    uint16_t port   = 0;

    stringstream ss_ip;
    ss_ip << hex << ip_hex;
    ss_ip >> ip_num;

    stringstream ss_port;
    ss_port << hex << port_hex;
    ss_port >> port;

    port_out = port;

    char buf[32]{};
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip_num      ) & 0xFF,
             (ip_num >>  8) & 0xFF,
             (ip_num >> 16) & 0xFF,
             (ip_num >> 24) & 0xFF);
    return string(buf);
}

string get_process_name(int pid) {
    if (pid <= 0) return "?";
    string path = "/proc/" + to_string(pid) + "/comm";
    ifstream f(path);
    string name;
    if (f && getline(f, name)) {
        return trim(name);
    }
    return "?";
}

// Very naive stub — real version needs /proc/*/fd parsing
map<string, int> inode_to_pid;  // inode → pid   (string because stol can fail)

vector<PortRecord> read_net_file(const string& proto, const map<uint16_t,string>& services) {
    vector<PortRecord> recs;
    string path = "/proc/net/" + proto;

    ifstream f(path);
    if (!f.is_open()) {
        cerr << "Cannot open " << path << "\n";
        return recs;
    }

    string line;
    getline(f, line); // skip header

    while (getline(f, line)) {
        stringstream ss(line);
        string sl, local_hex, remote_hex, state_hex, txq, rxq, tr, tm, inode_str;

        if (!(ss >> sl >> local_hex >> remote_hex >> state_hex >> txq >> rxq >> tr >> tm >> inode_str)) {
            continue;
        }

        if (inode_str.empty()) continue;

        PortRecord r;
        r.proto = (proto == "tcp") ? "TCP" : "UDP";

        uint16_t port = 0;
        r.local_ip = hex_to_ip(local_hex, port);
        r.port     = port;

        // Try to match PID (currently stub — needs real implementation)
        try {
            long inode = stol(inode_str);
            string key = to_string(inode);
            if (inode_to_pid.count(key)) {
                r.pid = inode_to_pid[key];
                r.process_name = get_process_name(r.pid);
            }
        } catch (...) {
            // ignore
        }

        auto it = services.find(port);
        r.service = (it != services.end()) ? it->second : "—";

        // Risk & flag
        bool is_local_only = (r.local_ip == "127.0.0.1" || r.local_ip == "0.0.0.0");
        r.risk = is_local_only ? "Local-only" : "Exposed";
        r.flag = SENSITIVE_PORTS.count(port) ? "High-Interest" : "Normal";

        // TCP state (basic)
        if (proto == "tcp" && !state_hex.empty()) {
            try {
                int st = stoi(state_hex, nullptr, 16);
                static const char* tcp_states[12] = {
                    "", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
                    "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
                    "LISTEN", "CLOSING"
                };
                if (st >= 1 && st <= 11) {
                    r.state = tcp_states[st];
                } else {
                    r.state = "STATE_" + state_hex;
                }
            } catch (...) {
                r.state = "?";
            }
        }

        recs.push_back(r);
    }

    return recs;
}

int main() {
    cout << "Local Listening Ports Scanner   (run as root to see PIDs/processes)\n\n";

    auto services = load_services();

    // TODO: implement real inode → pid mapping here (walk /proc/*/fd)
    //       currently all PIDs will show as -1 / "?"

    vector<PortRecord> all;

    auto tcp = read_net_file("tcp", services);
    auto udp = read_net_file("udp", services);

    all.reserve(tcp.size() + udp.size());
    all.insert(all.end(), tcp.begin(), tcp.end());
    all.insert(all.end(), udp.begin(), udp.end());

    // Sort: listening first, then by protocol, then by port
    sort(all.begin(), all.end(), [](const PortRecord& a, const PortRecord& b) {
        bool a_listen = (a.local_ip == "0.0.0.0" || a.local_ip == "::");
        bool b_listen = (b.local_ip == "0.0.0.0" || b.local_ip == "::");

        if (a_listen != b_listen) return a_listen > b_listen;  // listening first
        if (a.proto != b.proto)   return a.proto < b.proto;
        return a.port < b.port;
    });

    // ────────────────────────────────────────────────────────────────
    cout << left
         << setw(6)  << "Proto"
         << setw(6)  << "Port"
         << setw(16) << "Local Address"
         << setw(7)  << "PID"
         << setw(16) << "Process"
         << setw(14) << "Service"
         << setw(12) << "Risk"
         << setw(14) << "Flag"
         << setw(12) << "State"
         << "\n";

    cout << string(105, '-') << "\n";

    for (const auto& r : all) {
        string pid_str  = (r.pid > 0) ? to_string(r.pid) : "-";
        string proc_str = (r.pid > 0) ? r.process_name : "?";

        cout << left
             << setw(6)  << r.proto
             << setw(6)  << r.port
             << setw(16) << r.local_ip
             << setw(7)  << pid_str
             << setw(16) << proc_str
             << setw(14) << r.service
             << setw(12) << r.risk
             << setw(14) << r.flag
             << setw(12) << r.state
             << "\n";
    }

    if (!is_root()) {
        cout << "\nTip: run with sudo to attempt process name detection\n";
    }

    cout << "\nNote: PID/process detection is currently not implemented.\n";
    cout << "      To add it, parse /proc/[pid]/fd/* → socket:[inode]\n\n";

    return 0;
}
