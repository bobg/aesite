package aesite

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/pkg/errors"
)

var envInitRegex = regexp.MustCompile(`export\s+([^=]+)=(.*)`)

// DSTest starts the datastore emulator in a subprocess.
// It uses the gcloud binary, which must be found in PATH.
// It gives the program two seconds to start,
// then sets this process's environment variables
// (again with gcloud)
// as needed for the datastore client library to use the emulator.
// When the given context is canceled,
// the emulator subprocess gets an interrupt signal.
func DSTest(ctx context.Context, projectID string) error {
	log.Print("starting datastore emulator")
	cmd := exec.Command("gcloud", "--project", projectID, "beta", "emulators", "datastore", "start")
	err := cmd.Start()
	if err != nil {
		return errors.Wrap(err, "starting datastore emulator")
	}

	go func() {
		ch := make(chan struct{})
		go func() {
			defer log.Print("datastore emulator exited")
			defer close(ch)
			err := cmd.Wait()
			if err != nil {
				log.Printf("datastore emulator: %s", err)
			}
		}()

		select {
		case <-ctx.Done():
			log.Print("sending interrupt to datastore emulator")
			err := cmd.Process.Signal(os.Interrupt)
			if err != nil {
				log.Printf("sending interrupt to datastore emulator: %s", err)
			}

		case <-ch:
		}
	}()

	time.Sleep(2 * time.Second)

	envLines, err := exec.Command("gcloud", "--project", projectID, "beta", "emulators", "datastore", "env-init").Output()
	if err != nil {
		return errors.Wrap(err, "running env-init command")
	}

	s := bufio.NewScanner(bytes.NewReader(envLines))
	for s.Scan() {
		envLine := s.Text()
		m := envInitRegex.FindStringSubmatch(envLine)
		if len(m) >= 3 {
			err = os.Setenv(m[1], m[2])
			if err != nil {
				return errors.Wrapf(err, "setting env var %s to %s", m[1], m[2])
			}
		}
	}

	return errors.Wrap(s.Err(), "scanning env-init output")
}
