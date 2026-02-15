package client

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/ppiankov/chainwatch/api/proto/chainwatch/v1"
	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/model"
)

// Client connects to a chainwatch gRPC policy server.
type Client struct {
	conn   *grpc.ClientConn
	client pb.ChainwatchServiceClient
}

// New creates a gRPC client connected to the given address.
// Fail-closed: if connection cannot be established, Evaluate returns Deny.
func New(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to policy server: %w", err)
	}
	return &Client{
		conn:   conn,
		client: pb.NewChainwatchServiceClient(conn),
	}, nil
}

// Evaluate sends an action to the remote policy server for evaluation.
// Fail-closed: returns Deny on any RPC error.
func (c *Client) Evaluate(action *model.Action, purpose string) (model.PolicyResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.client.Evaluate(ctx, &pb.EvalRequest{
		Action:  actionToProto(action),
		Purpose: purpose,
	})
	if err != nil {
		// Fail-closed: unreachable server → deny
		return model.PolicyResult{
			Decision: model.Deny,
			Reason:   fmt.Sprintf("policy server unreachable: %v", err),
			PolicyID: "failclosed.unreachable",
		}, nil
	}

	return model.PolicyResult{
		Decision:    model.Decision(resp.Decision),
		Reason:      resp.Reason,
		Tier:        int(resp.Tier),
		PolicyID:    resp.PolicyId,
		ApprovalKey: resp.ApprovalKey,
	}, nil
}

// Approve grants approval for a pending action via the remote server.
func (c *Client) Approve(key string, duration time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.ApproveRequest{Key: key}
	if duration > 0 {
		req.Duration = duration.String()
	}

	_, err := c.client.Approve(ctx, req)
	return err
}

// Deny rejects a pending approval via the remote server.
func (c *Client) Deny(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.client.Deny(ctx, &pb.DenyRequest{Key: key})
	return err
}

// ListPending returns all pending approvals from the remote server.
func (c *Client) ListPending() ([]approval.Approval, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.client.ListPending(ctx, &pb.ListPendingRequest{})
	if err != nil {
		return nil, err
	}

	result := make([]approval.Approval, len(resp.Approvals))
	for i, a := range resp.Approvals {
		createdAt, _ := time.Parse(time.RFC3339, a.CreatedAt)
		result[i] = approval.Approval{
			Key:       a.Key,
			Status:    approval.Status(a.Status),
			Resource:  a.Resource,
			Reason:    a.Reason,
			CreatedAt: createdAt,
		}
	}

	return result, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

func actionToProto(action *model.Action) *pb.Action {
	params := make(map[string]string, len(action.Params))
	for k, v := range action.Params {
		params[k] = fmt.Sprintf("%v", v)
	}
	meta := make(map[string]string, len(action.RawMeta))
	for k, v := range action.RawMeta {
		meta[k] = fmt.Sprintf("%v", v)
	}
	return &pb.Action{
		Tool:      action.Tool,
		Resource:  action.Resource,
		Operation: action.Operation,
		Params:    params,
		Meta:      meta,
	}
}
