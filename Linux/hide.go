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
    // // Get the process ID of the process to hide
    // pid := syscall.Getpid()
    // fmt.Printf("Hiding process with PID %d\n", pid)
    //Vaidate parameters
    if len(os.Args) < 2 {
            fmt.Println("Usage: myprogram <process name to hide>") 
            os.Exit(1)
     }

    // Specify the name of the target process to find
    targetProcess := os.Args[1]

    // Run the pgrep command to find the PID of the target process
    out, err := exec.Command("pgrep", targetProcess).Output()
    fmt.Printf("Process found: %v\n", out)
    if err != nil {
        fmt.Printf("Failed to find process: %v\n", err)
        return
    }

    // Convert the output to a string and extract the PID
    pidStr := string(out[:len(out)-1])
    fmt.Printf("PID Found: %v\n", pidStr)
    pid, err := strconv.Atoi(pidStr)
    if err != nil {
        fmt.Printf("Failed to convert PID to integer: %v\n", err)
        return
    }

    // Open the process table
    procDir := fmt.Sprintf("/proc/%d", pid)
    procTable, err := syscall.Open(procDir, syscall.O_RDONLY, 0)
    if err != nil {
        fmt.Printf("Error opening directory: %s\n", err.Error())
    }
    defer syscall.Close(procTable)

    // Loop through the process table looking for the target process ID
    var buf [4096]byte
    for {
        n, err := syscall.Read(procTable, buf[:])
        if err != nil {
            fmt.Printf("Error reading directory: %s\n", err.Error())
            return
        }
        if n == 0 {
            break // End of directory
        }

        fmt.Print(string(buf[:n]))

        for _, dirent := range *(*[]syscall.Dirent)(unsafe.Pointer(&buf)) {
            if dirent.Ino == 0 {
                continue // Skip null entries
            }
            tmp := dirent.Name
            //create new byte slice of same len as tmp
            b := make([]byte, len(tmp))
            for i, v := range tmp {
                b[i] = byte(v)
            }
            //debug
            for _, value := range tmp {
                fmt.Print(value, " ")
            }
            pidStr = string(b)
            if _, err := strconv.Atoi(pidStr); err != nil {
                        continue // Not a PID directory
                    }
            // Open the process status file to check if this is the target process
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
            fmt.Printf("poop")
            if strings.Contains(string(statusBuf[:n]), fmt.Sprintf("Pid:\t%d\n", pid)) {
                // Found the target process, hide it by modifying the process table entry
                processEntry := fmt.Sprintf("/proc/%s", pidStr)
                err = syscall.Unlink(processEntry)
                if err != nil {
                    panic(err)
                }
                fmt.Printf("Process with PID %d successfully hidden\n", pid)
                return
            }
        }
    }
    fmt.Printf("Process with PID %d not found\n", pid)
}