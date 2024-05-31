#include <stdio.h>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <user.h>

using namespace std;

class Sdb {
public:
    sdb(){}
    void set_program(string pname) {
        program_name = pname;
        
        childpid = fork();
        if (childpid == 0) {
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            execlp(program_name.data(), program_name.data(), NULL);
            exit(0);
        }
        else {
            int wstatus;
            waitpid(childpid, &wstatus, 0);
            cout << "** program " << program_name << " loaded. entry point 0x401000." << endl;
        }
        
    }
    void start() {
        // condition for program not terminates yet
        while (true) {
            print_prompt();
            read_cmd();
        }
        
    }
private:
    string program_name = "";
    vector<pair<int, uint64_t>> breakpoints;
    int breakpoint_cnt = 0;
    int childpid = 0;

    void print_prompt() {
        cout << "(sdb) ";
    }
    void read_cmd() {
        string cmd;
        cin >> cmd;
        if (cmd == "load") {
            string pname;
            cin >> pname;
            set_program(pname);
        }
        else if (program_name == "") {
            cout << "** please load a program first." << endl;
            cin.clear();
            cin.sync();
            return;
        }
        else if (cmd == "info") {
            show_reg();
        }
        else if (cmd == "break") {
            set_breakpoint();
        }
        else if (cmd == "si") {
            step_exec();
        }
        else if (cmd == "cont") {
            cont_exec();
        }
        else if (cmd == "delete") {
            delete_breakpoint();
        }
        else if (cmd == "syscall") {
            syscall();
        }
        else if (cmd == "patch") {
            patch_mem();
        }

    }
    void show_reg() {
        if (program_name == "") {
            cout << "** please load a program first." << endl;
            return;
        }
        string target;
        cin >> target;
        if (target == "reg") {
            // print all registers information
            struct user_regs_struct regs;
            cout << "reg" << endl;
        }
        else if (target == "break") {
            // print all breakpoints information
            if (breakpoints.empty()) {
                cout << "** no breakpoints." << endl;
            }
            else {
                cout << "Num\t" << "Address\t" << endl;
                for (int i = 0; i < (int)breakpoints.size(); i++) {
                    cout << breakpoints[i].first << "\t" << std::hex << breakpoints[i].second << "\t" << endl; 
                }
            }
        }
    }
    void set_breakpoint() {
        uint64_t target_addr;
        cin >> target_addr;
        cout << "** set a breakpoint at " << target_addr << "." << endl;
        breakpoints.push_back(pair<int, uint64_t>(breakpoint_cnt, target_addr));
        breakpoint_cnt++;

    }
    void delete_breakpoint() {
        int id;
        cin >> id;
        for (int i = 0; i < (int)breakpoints.size(); i++) {
            // check whether this breakpoint exists 
            if (breakpoints[i].first == id) {
                cout << "** delete breakpoint " << id << "." << endl;
                breakpoints.erase(breakpoints.begin()+i);
                break;
            }
            else if (i == (int)breakpoints.size()-1) {
                cout << "** breakpoint " << id << "does not exist." << endl;
            }
        }
        return;
    }
    void cont_exec() {
        ptrace(PTRACE_CONT, childpid, NULL, NULL);
    }
    void step_exec() {
        ptrace(PTRACE_SINGLESTEP, childpid, NULL, NULL);
    }
    void patch_mem() {
        uint64_t hex_addr;
        string hex_value;
        int len;
        cin >> hex_addr >> hex_value >> len;
        cout << "** patch memory at address " << std::hex << hex_addr << endl;
        ptrace(PTRACE_POKETEXT, childpid, hex_addr, hex_value.data());
    }
    void syscall() {
        uint64_t hex_addr;
        int nr;
        int ret;
        ret = ptrace(PTRACE_SYSCALL, childpid, NULL, NULL);
        if (false) {
            cout << "** hit a breakpoint at " << std::hex << hex_addr << "." << endl;
        }
        else if (true) {
            cout << "** enter a syscall(" << nr << ") at " << std::hex << hex_addr << "." << endl;
        }
        else {
            cout << "** leave a syscall (" << nr << ") = " << ret << " at " << std::hex << hex_addr << "." << endl;
        }
    }
};

int main(int argc, char* argv[]) {
    Sdb debugger;

    if (argc == 2) {
        debugger.set_program(argv[1]);
    }
    debugger.start();

    return 0;
}