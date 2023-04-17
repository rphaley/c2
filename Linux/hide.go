package main

import (
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "syscall"
    "unsafe"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: myprogram <process name to hide>")
        os.Exit(1)
    }

    targetProcess := os.Args[1]

    out, err := exec.Command("pgrep", targetProcess).Output()
    if err != nil {
        fmt.Printf("Failed to find process: %v\n", err)
        return
    }
    pidStr := string(out[:len(out)-1])
    pid, err := strconv.Atoi(pidStr)
    if err != nil {
        fmt.Printf("Failed to convert PID to integer: %v\n", err)
        return
    }

    procDir := fmt.Sprintf("/proc/%d", pid)
    procTable, err := syscall.Open(procDir, syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Printf("Error opening directory: %s Error: %s\n", procDir, err.Error())
        return
    }
    defer syscall.Close(procTable)

    var buf [4096]byte
    for {
        n, err := syscall.Read(procTable, buf[:])
        if err != nil {
            fmt.Printf("Error reading directory: %s Error: %s\n", procDir, err.Error())
            return
        }
        if n == 0 {
            break // End of directory
        }

        for _, dirent := range *(*[]syscall.Dirent)(unsafe.Pointer(&buf)) {
            if dirent.Ino == 0 {
                continue // Skip null entries
            }
            pidDir := fmt.Sprintf("%s/%s", procDir, dirent.Name)
            stat, err := os.Lstat(pidDir)
            if err != nil {
                continue // Failed to stat the directory, skip to next
            }
            if stat.IsDir() {
                pidStr := dirent.Name
                if _, err := strconv.Atoi(pidStr); err != nil {
                    continue // Not a PID directory
                }
                statusFile := fmt.Sprintf("/proc/%s/status", pidStr)
                statusFd, err := syscall.Open(statusFile, syscall.O_RDONLY, 0)
                if err != nil {
                    continue // Failed to open status file, skip to next
                }
                defer syscall.Close(statusFd)
                var statusBuf [4096]byte
                n, err = syscall.Read(statusFd, statusBuf[:])
                if err != nil {
                    continue // Failed to read status file, skip to next
                }
                if strings.Contains(string(statusBuf[:n]), fmt.Sprintf("Pid:\t%d\n", pid)) {
                    processEntry := fmt.Sprintf("/proc/%s", pidStr)
                    err = syscall.Unlink(processEntry)
                    if err != nil {
                        fmt.Printf("Error hiding process with PID %d: %v\n", pid, err)
                        return
                    }
                    fmt.Printf("Process with PID %d successfully hidden\n", pid)
                    return
                }
            }
        }
    }
    fmt.Printf("Process with PID %d not found\n", pid)
}