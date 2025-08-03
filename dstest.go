package aesite

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/bobg/errors"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
// Returns a slice of option.ClientOptions that the caller should use in a call to datastore.NewClient,
// and a function that can be used to kill the emulator subprocess and return its Wait result.
//
// (The ClientOptions add interceptors that reset a thirty-second timer on each call.
// The kill function waits until that timer expires before actually killing the emulator.
// This is necessary because the emulator may have buffered changes not yet written to disk.
// There does not appear to be a way to flush them explicitly,
// but waiting thirty seconds after the last change seems to do the trick.)
func DSTest(ctx context.Context, projectID string) ([]option.ClientOption, func() error, error) {
	log.Print("starting datastore emulator")

	cmd := exec.CommandContext(ctx, "gcloud", "--project", projectID, "beta", "emulators", "datastore", "start")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err := cmd.Start()
	if err != nil {
		return nil, nil, errors.Wrap(err, "starting datastore emulator")
	}

	time.Sleep(2 * time.Second)

	envLines, err := exec.Command("gcloud", "--project", projectID, "beta", "emulators", "datastore", "env-init").Output()
	if err != nil {
		return nil, nil, errors.Wrap(err, "running env-init command")
	}

	s := bufio.NewScanner(bytes.NewReader(envLines))
	for s.Scan() {
		envLine := s.Text()
		m := envInitRegex.FindStringSubmatch(envLine)
		if len(m) >= 3 {
			err = os.Setenv(m[1], m[2])
			if err != nil {
				return nil, nil, errors.Wrapf(err, "setting env var %s to %s", m[1], m[2])
			}
		}
	}

	var (
		mu sync.Mutex
		t  = time.Now()
	)

	u := func() {
		mu.Lock()
		t = time.Now()
		mu.Unlock()
	}

	unaryInterceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		defer u()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
	streamInterceptor := func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		defer u()
		s, err := streamer(ctx, desc, cc, method, opts...)
		return &dstestClientStream{update: u, s: s}, err
	}
	opts := []option.ClientOption{
		option.WithGRPCDialOption(grpc.WithUnaryInterceptor(unaryInterceptor)),
		option.WithGRPCDialOption(grpc.WithStreamInterceptor(streamInterceptor)),
	}

	var killed bool
	k := func() error {
		if killed {
			return nil
		}
		d := time.Until(t.Add(30 * time.Second))
		if d > 0 {
			log.Printf("waiting %s to terminate the datastore emulator", d)
			time.Sleep(d)
		}
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) // kill the whole process group
		time.Sleep(time.Second)
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		killed = true
		return cmd.Wait()
	}

	return opts, k, nil
}

type dstestClientStream struct {
	update func()
	s      grpc.ClientStream
}

func (s *dstestClientStream) Header() (metadata.MD, error) {
	defer s.update()
	return s.s.Header()
}

func (s *dstestClientStream) Trailer() metadata.MD {
	defer s.update()
	return s.s.Trailer()
}

func (s *dstestClientStream) CloseSend() error {
	defer s.update()
	return s.s.CloseSend()
}

func (s *dstestClientStream) Context() context.Context {
	defer s.update()
	return s.s.Context()
}

func (s *dstestClientStream) SendMsg(m interface{}) error {
	defer s.update()
	return s.s.SendMsg(m)
}

func (s *dstestClientStream) RecvMsg(m interface{}) error {
	defer s.update()
	return s.s.RecvMsg(m)
}
