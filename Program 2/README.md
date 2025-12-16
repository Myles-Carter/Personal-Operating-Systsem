Tiny RISC-V Command-Line OS
Runs on QEMU virt platform · RISC-V 64-bit · Supports scheduling, semaphores, memory protection metadata, and a simple flat file system

================================================================================

Overview

This project implements a simple educational operating system for the RISC-V RV64 architecture.
It runs on the QEMU "virt" virtual machine and includes:

Cooperative scheduler running multiple kernel “processes”

Semaphores for synchronization

Basic memory protection model (per-process regions)

Simple in-memory flat file system

UART 8250 console with a command-line shell

Custom linker script, boot assembly, and context-switch code

This OS is small, understandable, and designed to teach core operating system concepts.

Project Structure

Program 2/
kernel.c – Core kernel (scheduler, semaphores, FS, shell)
start.S – Boot/startup code (entry point)
switch.S – Context-switch implementation
linker.ld – Custom RISC-V linker script
kernel.elf – Built kernel executable

Requirements

These tools must be installed inside WSL Ubuntu:

Install RISC-V GCC Compiler:
sudo apt update
sudo apt install -y gcc-riscv64-unknown-elf

If that package is unavailable:
sudo apt install -y gcc-riscv64-linux-gnu

Install QEMU for RISC-V:
sudo apt install -y qemu-system-misc

Build Instructions

Launch Ubuntu (WSL) and navigate to your project folder

Compile the OS kernel:

riscv64-unknown-elf-gcc -march=rv64gc -mabi=lp64 -mcmodel=medany
-nostdlib -nostartfiles -ffreestanding -O2
-Wl,-T,linker.ld
start.S switch.S kernel.c
-o kernel.elf

Or with alternate compiler:

riscv64-linux-gnu-gcc -march=rv64gc -mabi=lp64 -mcmodel=medany
-nostdlib -nostartfiles -ffreestanding -O2
-Wl,-T,linker.ld
start.S switch.S kernel.c
-o kernel.elf

A successful build generates: kernel.elf

Running the OS in QEMU

Start QEMU (using built-in OpenSBI firmware):

qemu-system-riscv64 -machine virt -nographic -kernel kernel.elf

You should see:

--- tiny RISC-V OS starting ---
Welcome to tiny RISC-V OS.
Commands: help, ls, cat <name>, ps, yield
os>

At this point, your OS is fully operational.

Shell Commands

help – Show help menu
ls – List files in the file system
cat <name> – Show contents of a file
ps – List processes
yield – Yield CPU (demonstrates scheduling)
touch <name> - Create empty file
write <name> - Add file
rm <name> - Remove file
append <name> <text> - Append text to file
rename <old> <new> - Rename file
spawn <name> <message> - Create worker with name; optional message
spawn print <message> - Special printer process

Example session:

os> help
help - show this help
ls - list files
cat <name> - show file contents
ps - list processes
yield - yield CPU

os> ls
Files:
readme.txt (0x18 bytes)
motd.txt (0x1b bytes)

os> cat readme.txt
Hello from tiny RISC-V OS!

os> ps
PID STATE NAME
0x1 RUNN shell
0x2 RUNN worker1
0x3 RUNN worker2

os> yield

Features Implemented
Scheduler

Cooperative round-robin scheduler

Context switching implemented in switch.S

Each process has:
PID
Stack
Register context
Memory region metadata

Semaphores

sem_wait() and sem_signal()

Workers demonstrate controlled access to critical sections

Memory Protection (Simplified)

Each process is assigned a unique memory region

check_user_ptr() enforces simple bounds checking

(Real OSes would use page tables; this is a demonstration)

Flat File System

Up to 8 files in memory

Supports:
ls
cat <name>

Includes:
readme.txt
motd.txt

UART Console

MMIO UART driver at 0x10000000

Supports input, output, and line editing

Backing the interactive OS shell

Exiting QEMU

Press:

Ctrl + C

This returns you to your Ubuntu terminal.