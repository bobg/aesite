package aesite

import (
	"context"
	"time"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"github.com/bobg/errors"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	taskspb "google.golang.org/genproto/googleapis/cloud/tasks/v2"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TaskService is a minimal interface to a cloudtasks service.
// It is intended to permit simple testing,
// and to make it possible to swap out a cloudtasks service for a local tasks service
// TODO: local tasks service not yet implemented.
type TaskService interface {
	IsQueueEmpty(ctx context.Context, queue string) (bool, error)
	Enqueue(ctx context.Context, queue, taskName, url string, when time.Time) error
}

// GCloudTasks is a Google cloudtasks client that satisfies the TaskService interface.
type GCloudTasks cloudtasks.Client

// NewGCloudTasks produces a new GCloudTasks object.
func NewGCloudTasks(ctx context.Context, options ...option.ClientOption) (*GCloudTasks, error) {
	client, err := cloudtasks.NewClient(ctx, options...)
	return (*GCloudTasks)(client), err
}

// IsQueueEmpty tells whether the queue with the given name is empty.
func (t *GCloudTasks) IsQueueEmpty(ctx context.Context, queue string) (bool, error) {
	req := &taskspb.ListTasksRequest{Parent: queue}
	iter := (*cloudtasks.Client)(t).ListTasks(ctx, req)
	_, err := iter.Next()
	if err != nil && err != iterator.Done {
		return false, errors.Wrapf(err, "gCloudTasks: checking queue %s for emptiness", queue)
	}
	return err == iterator.Done, nil
}

// EnqueueTask enqueues a task with the given name on the given queue,
// which at the given time will GET the given URL.
func (t *GCloudTasks) Enqueue(ctx context.Context, queue, taskName, url string, when time.Time) error {
	var (
		secs  = when.Unix()
		nanos = int32(when.UnixNano() % int64(time.Second))
	)
	_, err := (*cloudtasks.Client)(t).CreateTask(ctx, &cloudtaskspb.CreateTaskRequest{
		Parent: queue,
		Task: &cloudtaskspb.Task{
			Name: taskName,
			MessageType: &cloudtaskspb.Task_AppEngineHttpRequest{
				AppEngineHttpRequest: &cloudtaskspb.AppEngineHttpRequest{
					HttpMethod:  cloudtaskspb.HttpMethod_GET,
					RelativeUri: url,
				},
			},
			ScheduleTime: &timestamppb.Timestamp{
				Seconds: secs,
				Nanos:   nanos,
			},
		},
	})
	return errors.Wrapf(err, "enqueueing task %s, queue %s, url %s for %s", taskName, queue, url, when)
}
