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
// When the given context is canceled,
// the emulator subprocess gets an interrupt signal,
// then a TERM signal,
// then a KILL signal,
// in an attempt to ensure it exits.
// The return value is a channel that gets closed when the emulator subprocess exits.
// DSTest starts the datastore emulator in a subprocess.
// It uses the gcloud binary, which must be found in PATH.
// (Further, the proper gcloud components must be installed;
// see https://cloud.google.com/datastore/docs/tools/datastore-emulator.)
// It gives the program two seconds to start,
// then sets this process's environment variables
// (again with gcloud)
// as needed for the datastore client library to use the emulator.
// When the given context is canceled,
// the emulator subprocess gets an interrupt signal.
func DSTest(ctx context.Context, projectID string) error {
	_, err := DSTestWithDoneChan(ctx, projectID)
	return err
}

// DSTestWithDoneChan is the same as DSTest (qv)
// but it also returns a channel that closes when the emulator subprocess exits.
// The caller should block on this channel before exiting the main process.
func DSTestWithDoneChan(ctx context.Context, projectID string) (<-chan struct{}, error) {
	log.Print("starting datastore emulator")
	cmd := exec.CommandContext(ctx, "gcloud", "--project", projectID, "beta", "emulators", "datastore", "start")
	err := cmd.Start()
	if err != nil {
		return nil, errors.Wrap(err, "starting datastore emulator")
	}

	done := make(chan struct{})

	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("datastore emulator: %s", err)
		}
		log.Print("datastore emulator exited")
		close(done)
	}()

	go func() {
		<-ctx.Done()
		// Try to make sure the datastore emulator exits.
		cmd.Process.Signal(os.Interrupt)
		time.Sleep(time.Second)
		cmd.Process.Signal(syscall.SIGTERM)
		time.Sleep(time.Second)
		cmd.Process.Signal(os.Kill)
	}()

	time.Sleep(2 * time.Second)

	envLines, err := exec.Command("gcloud", "--project", projectID, "beta", "emulators", "datastore", "env-init").Output()
	if err != nil {
		return done, errors.Wrap(err, "running env-init command")
	}

	s := bufio.NewScanner(bytes.NewReader(envLines))
	for s.Scan() {
		envLine := s.Text()
		m := envInitRegex.FindStringSubmatch(envLine)
		if len(m) >= 3 {
			err = os.Setenv(m[1], m[2])
			if err != nil {
				return done, errors.Wrapf(err, "setting env var %s to %s", m[1], m[2])
			}
		}
	}

	return done, errors.Wrap(s.Err(), "scanning env-init output")
}
