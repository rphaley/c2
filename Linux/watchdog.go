package main

import (
    "fmt"
    "os/exec"
    "time"
)

var debugCheck string = ""

func main() {

    // Get passed arguments
    // 1 = debug (any string)
        if len(os.Args) > 1 {
        debugCheck = os.Args[1]
    } 

    for {
        // Check if the process is running
        if !isProcessRunning("/sbin/bash") {
            // If not, start it
            err := startProcess("/sbin/bash", "")
            if err != nil {
                if debugCheck != "" { fmt.Println("Error starting process:", err) }
            }
        }
        // Wait for a minute before checking again
        time.Sleep(time.Minute)
    }
}

func isProcessRunning(processName string) bool {
    // Check if the process is running by running a command
    cmd := exec.Command("pgrep", "-f", processName)
    output, err := cmd.Output()
    if err != nil {
        if debugCheck != "" {
            fmt.Println("Error checking if process is running:", err)
        }
        return false
    }
    // Check if the output is empty (no PID found)
    if len(output) == 0 {
        return false
    }
    return true
}

func startProcess(processPath string, processArgs string) error {
    // Start the process by running a command
    cmd := exec.Command(processPath, processArgs)
    err := cmd.Start()
    if err != nil {
        if debugCheck != "" { fmt.Println("error starting process: %s", err) }
        return fmt.Errorf("error starting process: %s", err)
    }
    return nil
}