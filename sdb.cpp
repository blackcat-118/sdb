#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <inttypes.h>
#include <Zydis/Zydis.h>
using namespace std;

class Sdb {
public:
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
            struct user_regs_struct regs;
            ptrace(PTRACE_SETOPTIONS, childpid, NULL, PTRACE_O_TRACEFORK);
            ptrace(PTRACE_GETREGS, childpid, NULL, &regs);
            cout << "** program " << program_name << " loaded. entry point " << std::hex << regs.rip << "." << endl;
            disasm_code(regs.rip);
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
    vector<pair<int, unsigned char>> mapped_codes;  // mapping to the origin code for each breakpoint
    int breakpoint_cnt = 0;
    pid_t childpid = 0;

    void print_prompt() {
        cout << "(sdb) ";
    }
    void disasm_code(uint64_t addr) {
        uint64_t end_addr = 0;
        ZyanU8 data[64] = {'\0'};
        int data_cnt = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t word = ptrace(PTRACE_PEEKTEXT, childpid, addr+data_cnt, NULL);
            if (word == -1) {
                end_addr = addr+data_cnt;
                break;
            }
            for (int j = 0; j < 8; j++) {
                // cout << std::hex << (unsigned char)word << " ";
                data[data_cnt] = word%256;
                word /= 256;
                for (int b = 0; b < (int)breakpoints.size(); b++) {
                    if (addr+data_cnt == breakpoints[b].second) {
                        data[data_cnt] = mapped_codes[b].second;
                    }
                }
                data_cnt++;
            }
        }
        ZyanU64 runtime_address = addr;
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;
        int instruction_cnt = 0;
        while (ZYAN_SUCCESS(ZydisDisassembleIntel(
            /* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
            /* runtime_address: */ runtime_address,
            /* buffer:          */ data + offset,
            /* length:          */ sizeof(data) - offset,
            /* instruction:     */ &instruction
        )) && instruction_cnt < 5) {
            if (runtime_address == end_addr) {
                break;
            }
            cout << std::hex << setfill(' ') << setw(10) << runtime_address << ": ";
            for (ZyanU8 i = 0; i < instruction.info.length; i++) {
                cout << std::hex << setfill('0') << setw(2) << (int)data[i+offset] << " ";
            }
            cout << setw(30-instruction.info.length*3) << setfill(' ') << " ";
            cout << instruction.text << endl;
            offset += instruction.info.length;
            runtime_address += instruction.info.length;
            instruction_cnt++;
        }
        if (instruction_cnt < 5) {
            cout << "** the address is out of the range of the text section." << endl;
        }
        return;
    }
    void check_interrupt() {
        int wstatus;
        waitpid(childpid, &wstatus, 0);
        if (WIFEXITED(wstatus)) {
            cout << "** the target program terminated." << endl;
            exit(0);
        }
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, childpid, NULL, &regs);
        uint64_t cur_addr = regs.rip;
        uint64_t last_addr = cur_addr - 0x01;

        if (WIFSTOPPED(wstatus)) {
            siginfo_t info;
            memset(&info, 0, sizeof(siginfo_t));
            ptrace(PTRACE_GETSIGINFO, childpid, 0, &info);

            uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, last_addr, NULL);
            // if the last address is INT3 and it is a breakpoint
            if ((uint8_t)code == 0xcc) {
                for (int b = 0; b < (int)breakpoints.size(); b++) {
                    if (last_addr == breakpoints[b].second) {
                        cout << "** hit a breakpoint at " << std::hex << last_addr << "." << endl;
                        restore_breakpoint(last_addr);
                        struct user_regs_struct regs;
                        ptrace(PTRACE_GETREGS, childpid, NULL, &regs);
                        regs.rip -= 0x01;
                        // cout << regs.rip << endl;
                        ptrace(PTRACE_SETREGS, childpid, NULL, &regs);
                        // code = ptrace(PTRACE_PEEKTEXT, childpid, last_addr, NULL);
                        // cout << hex << code << endl;
                        reload_breakpoint(last_addr, b);
                        ptrace(PTRACE_GETREGS, childpid, NULL, &regs);
                        // cout << regs.rip << endl;
                        disasm_code(last_addr);
                        return;
                    }
                }
            }
            
            // if the current address(next executive instruction) is INT3 and it is a breakpoint
            // for step 
            code = ptrace(PTRACE_PEEKTEXT, childpid, cur_addr, NULL);
            if ((uint8_t)code == 0xcc) {
                for (int b = 0; b < (int)breakpoints.size(); b++) {
                    if (cur_addr == breakpoints[b].second) {
                        cout << "** hit a breakpoint at " << std::hex << cur_addr << "." << endl;
                        restore_breakpoint(cur_addr);
                        reload_breakpoint(cur_addr, b);
                        disasm_code(cur_addr);
                        return;
                    }
                }
            }
            code = ptrace(PTRACE_PEEKTEXT, childpid, cur_addr-0x02, NULL);
            if ((uint16_t)code == 0x050f) {
                auto opcode = ptrace(PTRACE_PEEKUSER, childpid, sizeof(uint64_t) * ORIG_RAX, NULL);
                auto ret = ptrace(PTRACE_PEEKUSER, childpid, sizeof(uint64_t) * RAX, NULL);
                uint64_t addr = cur_addr - 0x02;
                if (ret == -ENOSYS) {
                    cout << "** enter a syscall(" << std::dec << opcode << ") at " << std::hex << addr << "." << endl;
                    disasm_code(addr);
                }
                else {
                    cout << "** leave a syscall(" << std::dec << opcode << ") = " << ret << " at " << std::hex << addr << "." << endl;
                    disasm_code(addr);
                }
                return;
            }
            // step but no breakpoint
            disasm_code(cur_addr);
        }
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
            ptrace(PTRACE_GETREGS, childpid, NULL, &regs);
            cout << std::hex << "$rax 0x" << setw(16) << setfill('0') << regs.rax << "\t\t$rbx 0x" << setw(16) << setfill('0') << regs.rbx << "\t\t$rcx 0x" << setw(16) << setfill('0') << regs.rcx << endl;
            cout << std::hex << "$rdx 0x" << setw(16) << setfill('0') << regs.rdx << "\t\t$rsi 0x" << setw(16) << setfill('0') << regs.rsi << "\t\t$rdi 0x" << setw(16) << setfill('0') << regs.rdi << endl;
            cout << std::hex << "$rbp 0x" << setw(16) << setfill('0') << regs.rbp << "\t\t$rsp 0x" << setw(16) << setfill('0') << regs.rsp << "\t\t$r8  0x" << setw(16) << setfill('0') << regs.r8  << endl;
            cout << std::hex << "$r9  0x" << setw(16) << setfill('0') << regs.r9  << "\t\t$r10 0x" << setw(16) << setfill('0') << regs.r10 << "\t\t$r11 0x" << setw(16) << setfill('0') << regs.r11 << endl;
            cout << std::hex << "$r12 0x" << setw(16) << setfill('0') << regs.r12 << "\t\t$r13 0x" << setw(16) << setfill('0') << regs.r13 << "\t\t$r14 0x" << setw(16) << setfill('0') << regs.r14 << endl;
            cout << std::hex << "$r15 0x" << setw(16) << setfill('0') << regs.r15 << "\t\t$rip 0x" << setw(16) << setfill('0') << regs.rip << "\t\t$eflags 0x" << setw(16) << setfill('0') << regs.eflags << endl;
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
        cin >> std::hex >> target_addr;
        cout << "** set a breakpoint at " << target_addr << "." << endl;
        breakpoints.push_back(pair<int, uint64_t>(breakpoint_cnt, target_addr));

        // get and store original code
        uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, target_addr, NULL);
        unsigned char origin_code = (unsigned char)code;
        mapped_codes.push_back(pair<int, unsigned char>(breakpoint_cnt, origin_code));
        breakpoint_cnt++;

        // replace the code with soft interrupt 0xcc
        // cout << hex << ((code & 0xffffffffffffff00) | 0xcc) << endl;
        ptrace(PTRACE_POKETEXT, childpid, target_addr, ((code & 0xffffffffffffff00) | 0xcc));
        // code = ptrace(PTRACE_PEEKTEXT, childpid, target_addr, NULL);
        // cout << code << endl;

    }
    void restore_breakpoint(uint64_t addr) {
        int indx = -1;
        for (int i = 0; i < (int)breakpoints.size(); i++) {
            if (breakpoints[i].second == addr) {
                indx = i;
            }
        }
        if (indx == -1) {
            cerr << "this addr: " << std::hex << addr << "is not a breakpoint. " << endl;
            return;
        }
        uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, addr, NULL);
        unsigned char origin_code = mapped_codes[indx].second;
        // cout << hex << (int)origin_code << endl;
        // cout << hex << code << endl;
        // cout << hex << ((code & 0xffffffffffffff00) | origin_code) << endl;
        ptrace(PTRACE_POKETEXT, childpid, addr, ((code & 0xffffffffffffff00) | origin_code));
        return;
    }
    void reload_breakpoint(uint64_t addr, int indx) {
        // uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, addr, NULL);
        // cout << hex << code << endl;
        ptrace(PTRACE_SINGLESTEP, childpid, NULL, NULL);
        int wstatus;
        waitpid(childpid, &wstatus, 0);
        // reset breakpoint
        uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, addr, NULL);
        ptrace(PTRACE_POKETEXT, childpid, breakpoints[indx].second, (code & 0xffffffffffffff00) | 0xcc);
    }
    void delete_breakpoint() {
        int id;
        cin >> id;
        for (int i = 0; i < (int)breakpoints.size(); i++) {
            // check whether this breakpoint exists 
            if (breakpoints[i].first == id) {
                restore_breakpoint(breakpoints[i].second);
                cout << "** delete breakpoint " << id << "." << endl;
                breakpoints.erase(breakpoints.begin()+i);
                mapped_codes.erase(mapped_codes.begin()+i);
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
        check_interrupt();
    }
    void step_exec() {
        ptrace(PTRACE_SINGLESTEP, childpid, NULL, NULL);
        check_interrupt();
    }
    void patch_mem() {
        uint64_t hex_addr;
        uint64_t hex_value;
        int len;
        cin >> std::hex >> hex_addr >> hex_value;
        cin >> len;
        cout << "** patch memory at address " << std::hex << hex_addr << endl;
        uint64_t code = ptrace(PTRACE_PEEKTEXT, childpid, hex_addr, NULL);
        uint64_t offset;
        if (len == 1) {
            offset = 0xffffffffffffff00;
        }
        else if (len == 2) {
            offset = 0xffffffffffff0000;
        }
        else if (len == 4) {
            offset = 0xffffffff00000000;
        }
        else if (len == 2) {
            offset = 0x0000000000000000;
        }
        ptrace(PTRACE_POKETEXT, childpid, hex_addr, (code & offset) | hex_value);
    }
    void syscall() {
        uint64_t hex_addr;
        int nr;
        int ret;
        ptrace(PTRACE_SYSCALL, childpid, NULL, NULL);
        check_interrupt();
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