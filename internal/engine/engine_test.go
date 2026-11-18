package engine

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"phishforge/internal/engineconfig"
)

// TestMain doubles as the child helper: when re-executed with
// PF_ENGINE_HELPER=1 it runs the requested mode instead of the tests.
func TestMain(m *testing.M) {
	if os.Getenv("PF_ENGINE_HELPER") == "1" {
		switch os.Getenv("PF_ENGINE_MODE") {
		case "sleep":
			time.Sleep(60 * time.Second)
		case "echo":
			fmt.Fprintln(os.Stdout, "hello from helper")
			os.Stdout.Sync()
		case "crash":
			println("crashing")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

func helperEnv(mode string) map[string]string {
	return map[string]string{"PF_ENGINE_HELPER": "1", "PF_ENGINE_MODE": mode}
}

func cfgFor(mode string, restarts ...int) engineconfig.Config {
	c := engineconfig.Config{Kind: "helper", Env: helperEnv(mode), Args: []string{}}
	if len(restarts) > 0 {
		c.Restart.MaxAttempts = restarts[0]
		if len(restarts) > 1 {
			c.Restart.BackoffMs = restarts[1]
		}
	}
	return c
}

func TestStartEchoLogsAndExit(t *testing.T) {
	m := New(helperPath(t), 0, 10*time.Millisecond)
	id := "echo-1"
	if err := m.Start(id, cfgFor("echo")); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Wait for exit.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, ok := m.Status(id)
		if ok && st.State != StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stdout, _, ok := m.Logs(id)
	if !ok {
		t.Fatal("logs: not found")
	}
	if !strings.Contains(string(stdout), "hello from helper") {
		t.Fatalf("stdout missing hello: %q", stdout)
	}
	st, _ := m.Status(id)
	if st.State != StateExited {
		t.Fatalf("state = %q (exitErr %q)", st.State, st.ExitErr)
	}
}

func TestStopRunningProcess(t *testing.T) {
	m := New(helperPath(t), 0, 10*time.Millisecond)
	id := "sleep-1"
	if err := m.Start(id, cfgFor("sleep")); err != nil {
		t.Fatalf("start: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _ := m.Status(id); st.State == StateRunning {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := m.Stop(id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if m.Running(id) {
		t.Fatal("still running after Stop")
	}
	// Stop again -> not running error is fine either way, but status must exist.
	if _, ok := m.Status(id); !ok {
		t.Fatal("status missing after stop")
	}
}

func TestRestartPolicy(t *testing.T) {
	// crash exits 1; max 2 restarts, 10ms backoff => 3 total runs then failed.
	m := New(helperPath(t), 2, 10*time.Millisecond)
	id := "crash-1"
	if err := m.Start(id, cfgFor("crash", 2, 10)); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Wait for quiescence: failed state unchanged for 300ms, so we don't
	// observe the transient failed window between restart attempts.
	deadline := time.Now().Add(10 * time.Second)
	var last Status
	stableSince := time.Time{}
	for time.Now().Before(deadline) {
		st, ok := m.Status(id)
		if ok {
			if st.State != last.State || st.Restarts != last.Restarts {
				last = st
				stableSince = time.Now()
			} else if st.State == StateFailed && time.Since(stableSince) >= 300*time.Millisecond {
				if st.Restarts != 2 {
					t.Fatalf("restarts = %d, want 2", st.Restarts)
				}
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("never reached stable StateFailed")
}

func TestAlreadyRunningAndNoBinary(t *testing.T) {
	m := New(helperPath(t), 0, 10*time.Millisecond)
	id := "dup-1"
	if err := m.Start(id, cfgFor("sleep")); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := m.Start(id, cfgFor("sleep")); err != ErrAlreadyRunning {
		t.Fatalf("second start err = %v", err)
	}
	if err := m.Stop(id); err != nil {
		t.Fatalf("stop: %v", err)
	}

	none := New("", 0, time.Millisecond)
	if err := none.Start("x", cfgFor("echo")); err != ErrNoBinary {
		t.Fatalf("no-binary err = %v", err)
	}
}

func TestRemove(t *testing.T) {
	m := New(helperPath(t), 0, 10*time.Millisecond)
	id := "rm-1"
	if err := m.Start(id, cfgFor("sleep")); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := m.Remove(id); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, ok := m.Status(id); ok {
		t.Fatal("status exists after Remove")
	}
}