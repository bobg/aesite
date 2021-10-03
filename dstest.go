package aesite

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

var envInitRegex = regexp.MustCompile(`export\s+([^=]+)=(.*)`)

// DSTest starts the datastore emulator in a subprocess.
// It uses the gcloud binary, which must be found in PATH.
// (Further, the proper gcloud components must be installed;
// see https://cloud.google.com/datastore/docs/tools/datastore-emulator.)
// It gives the program two seconds to start,
// then sets this process's environment variables
// (again with gcloud)
// as needed for the datastore client library to use the emulator.
//
// Return value is a function that can be used to kill the emulator subprocess and return its Wait result.
func DSTest(ctx context.Context, projectID string) (func() error, error) {
	log.Print("starting datastore emulator")

	cmd := exec.CommandContext(ctx, "gcloud", "--project", projectID, "beta", "emulators", "datastore", "start")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		return nil, errors.Wrap(err, "starting datastore emulator")
	}

	time.Sleep(2 * time.Second)

	envLines, err := exec.Command("gcloud", "--project", projectID, "beta", "emulators", "datastore", "env-init").Output()
	if err != nil {
		return nil, errors.Wrap(err, "running env-init command")
	}

	s := bufio.NewScanner(bytes.NewReader(envLines))
	for s.Scan() {
		envLine := s.Text()
		m := envInitRegex.FindStringSubmatch(envLine)
		if len(m) >= 3 {
			err = os.Setenv(m[1], m[2])
			if err != nil {
				return nil, errors.Wrapf(err, "setting env var %s to %s", m[1], m[2])
			}
		}
	}

	return func() error {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // kill the whole process group
		return cmd.Wait()
	}, nil
}
