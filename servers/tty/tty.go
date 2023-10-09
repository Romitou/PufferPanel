//go:build !windows

package tty

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/pufferpanel/pufferpanel/v3"
	"github.com/pufferpanel/pufferpanel/v3/logging"
	"github.com/pufferpanel/pufferpanel/v3/messages"
	"github.com/shirou/gopsutil/process"
	"github.com/spf13/cast"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"
)

type tty struct {
	*pufferpanel.BaseEnvironment
	mainProcess *exec.Cmd
	stdInWriter io.Writer
}

func (t *tty) ttyExecuteAsync(steps pufferpanel.ExecutionData) (err error) {
	running, err := t.IsRunning()
	if err != nil {
		return
	}
	if running {
		err = pufferpanel.ErrProcessRunning
		return
	}

	pr := exec.Command(steps.Command, steps.Arguments...)
	pr.Dir = path.Join(t.GetRootDirectory(), steps.WorkingDirectory)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "PUFFER_") {
			pr.Env = append(pr.Env, v)
		}
	}
	pr.Env = append(pr.Env, "HOME="+t.GetRootDirectory(), "TERM=xterm-256color")
	for k, v := range steps.Environment {
		pr.Env = append(pr.Env, fmt.Sprintf("%s=%s", k, v))
	}

	t.Wait.Add(1)
	pr.SysProcAttr = &syscall.SysProcAttr{Setctty: true, Setsid: true}
	t.mainProcess = pr
	t.DisplayToConsole(true, "Starting process: %s %s", t.mainProcess.Path, strings.Join(t.mainProcess.Args[1:], " "))
	t.Log(logging.Info, "Starting process: %s %s", t.mainProcess.Path, strings.Join(t.mainProcess.Args[1:], " "))

	msg := messages.Status{Running: true, Installing: t.IsInstalling()}
	_ = t.StatusTracker.WriteMessage(msg)

	processTty, err := pty.Start(pr)
	if err != nil {
		t.Wait.Done()
		return
	}

	t.stdInWriter = processTty

	go func(proxy io.Writer) {
		_, _ = io.Copy(proxy, processTty)
	}(t.Wrapper)

	go t.handleClose(steps.Callback)
	return
}

func (t *tty) ExecuteInMainProcess(cmd string) (err error) {
	running, err := t.IsRunning()
	if err != nil {
		return err
	}
	if !running {
		err = pufferpanel.ErrServerOffline
		return
	}
	stdIn := t.stdInWriter
	_, err = io.WriteString(stdIn, cmd+"\n")
	return
}

func (t *tty) Kill() (err error) {
	running, err := t.IsRunning()
	if err != nil {
		return
	}
	if !running {
		return
	}
	return t.mainProcess.Process.Kill()
}

func (t *tty) IsRunning() (isRunning bool, err error) {
	isRunning = t.mainProcess != nil && t.mainProcess.Process != nil
	if isRunning {
		pr, pErr := os.FindProcess(t.mainProcess.Process.Pid)
		if pr == nil || pErr != nil {
			isRunning = false
		} else if pr.Signal(syscall.Signal(0)) != nil {
			isRunning = false
		}
	}
	return
}

func (t *tty) GetStats() (*pufferpanel.ServerStats, error) {
	running, err := t.IsRunning()
	if err != nil {
		return nil, err
	}
	if !running {
		return &pufferpanel.ServerStats{
			Cpu:    0,
			Memory: 0,
		}, nil
	}
	pr, err := process.NewProcess(int32(t.mainProcess.Process.Pid))
	if err != nil {
		return nil, err
	}

	memMap, _ := pr.MemoryInfo()
	cpu, _ := pr.Percent(time.Second * 1)

	return &pufferpanel.ServerStats{
		Cpu:    cpu,
		Memory: cast.ToFloat64(memMap.RSS),
	}, nil
}

func (t *tty) Create() error {
	return os.Mkdir(t.RootDirectory, 0755)
}

func (t *tty) WaitForMainProcess() error {
	return t.WaitForMainProcessFor(0)
}

func (t *tty) WaitForMainProcessFor(timeout time.Duration) error {
	running, err := t.IsRunning()
	if err != nil {
		return err
	}
	if running {
		if timeout > 0 {
			var timer = time.AfterFunc(timeout, func() {
				err = t.Kill()
			})
			t.Wait.Wait()
			timer.Stop()
		} else {
			t.Wait.Wait()
		}
	}
	return err
}

func (t *tty) SendCode(code int) error {
	running, err := t.IsRunning()

	if err != nil || !running {
		return err
	}

	return t.mainProcess.Process.Signal(syscall.Signal(code))
}

func (t *tty) handleClose(callback func(exitCode int)) {
	err := t.mainProcess.Wait()

	var exitCode int
	if t.mainProcess.ProcessState == nil || err != nil {
		exitCode = 1
	} else {
		exitCode = t.mainProcess.ProcessState.ExitCode()
	}
	t.LastExitCode = exitCode

	if err != nil {
		t.Log(logging.Error, "Error waiting on process: %s\n", err)
	}

	if t.mainProcess != nil && t.mainProcess.ProcessState != nil {
		t.Log(logging.Debug, "%s\n", t.mainProcess.ProcessState.String())
	}

	if t.mainProcess != nil && t.mainProcess.Process != nil {
		_ = t.mainProcess.Process.Release()
	}
	t.mainProcess = nil
	t.Wait.Done()

	msg := messages.Status{Running: false, Installing: t.IsInstalling()}
	_ = t.StatusTracker.WriteMessage(msg)

	if callback != nil {
		callback(exitCode)
	}
}