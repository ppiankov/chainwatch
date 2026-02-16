package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"

	pb "github.com/ppiankov/chainwatch/api/proto/chainwatch/v1"
	"github.com/ppiankov/chainwatch/internal/alert"
	"github.com/ppiankov/chainwatch/internal/approval"
	"github.com/ppiankov/chainwatch/internal/audit"
	"github.com/ppiankov/chainwatch/internal/denylist"
	"github.com/ppiankov/chainwatch/internal/model"
	"github.com/ppiankov/chainwatch/internal/policy"
	"github.com/ppiankov/chainwatch/internal/profile"
	"github.com/ppiankov/chainwatch/internal/tracer"
)

// Config holds gRPC server configuration.
type Config struct {
	Port         int
	PolicyPath   string
	DenylistPath string
	ProfileName  string
	AuditLogPath string
}

// Server implements the ChainwatchService gRPC server.
type Server struct {
	pb.UnimplementedChainwatchServiceServer

	mu         sync.RWMutex
	policyCfg  *policy.PolicyConfig
	dl         *denylist.Denylist
	policyHash string
	approvals  *approval.Store
	dispatcher *alert.Dispatcher
	auditLog   *audit.Log
	sessions   sync.Map // trace_id → *tracer.TraceAccumulator
	cfg        Config

	grpcServer *grpc.Server
}

// New creates a gRPC server with loaded policy, denylist, and approval store.
func New(cfg Config) (*Server, error) {
	dl, err := denylist.Load(cfg.DenylistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load denylist: %w", err)
	}

	policyCfg, policyHash, err := policy.LoadConfigWithHash(cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy config: %w", err)
	}

	if cfg.ProfileName != "" {
		prof, err := profile.Load(cfg.ProfileName)
		if err != nil {
			return nil, fmt.Errorf("failed to load profile %q: %w", cfg.ProfileName, err)
		}
		profile.ApplyToDenylist(prof, dl)
		policyCfg = profile.ApplyToPolicy(prof, policyCfg)
	}

	approvalStore, err := approval.NewStore(approval.DefaultDir())
	if err != nil {
		return nil, fmt.Errorf("failed to create approval store: %w", err)
	}
	approvalStore.Cleanup()

	var auditLog *audit.Log
	if cfg.AuditLogPath != "" {
		auditLog, err = audit.Open(cfg.AuditLogPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit log: %w", err)
		}
	}

	s := &Server{
		policyCfg:  policyCfg,
		dl:         dl,
		policyHash: policyHash,
		approvals:  approvalStore,
		dispatcher: alert.NewDispatcher(policyCfg.Alerts),
		auditLog:   auditLog,
		cfg:        cfg,
		grpcServer: grpc.NewServer(),
	}

	pb.RegisterChainwatchServiceServer(s.grpcServer, s)
	return s, nil
}

// Serve starts the gRPC server on the configured port. Blocks until stopped.
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.cfg.Port, err)
	}
	return s.grpcServer.Serve(lis)
}

// ServeOn starts the gRPC server on the given listener. For testing.
func (s *Server) ServeOn(lis net.Listener) error {
	return s.grpcServer.Serve(lis)
}

// GracefulStop gracefully shuts down the gRPC server.
func (s *Server) GracefulStop() {
	s.grpcServer.GracefulStop()
}

// Close cleans up resources.
func (s *Server) Close() error {
	if s.auditLog != nil {
		return s.auditLog.Close()
	}
	return nil
}

// Evaluate implements the Evaluate RPC.
func (s *Server) Evaluate(ctx context.Context, req *pb.EvalRequest) (*pb.EvalResponse, error) {
	if req.Action == nil {
		return &pb.EvalResponse{
			Decision: "deny",
			Reason:   "missing action",
		}, nil
	}

	action := protoToAction(req.Action)
	purpose := req.Purpose
	if purpose == "" {
		purpose = "general"
	}

	traceID := req.TraceId
	if traceID == "" {
		traceID = tracer.NewTraceID()
	}
	ta := s.getOrCreateSession(traceID)

	s.mu.RLock()
	policyCfg := s.policyCfg
	dl := s.dl
	policyHash := s.policyHash
	s.mu.RUnlock()

	result := policy.Evaluate(action, ta.State, purpose, req.AgentId, dl, policyCfg)

	ta.RecordAction(
		map[string]any{"grpc": "chainwatch.v1.Evaluate"},
		purpose, action,
		map[string]any{
			"result":       string(result.Decision),
			"reason":       result.Reason,
			"policy_id":    result.PolicyID,
			"approval_key": result.ApprovalKey,
		}, "",
	)

	s.recordAudit(action, string(result.Decision), result.Reason, result.Tier, policyHash, traceID)
	s.dispatchAlert(action, string(result.Decision), result.Reason, result.Tier, policyHash, traceID)

	// Handle require_approval: create pending request if needed
	if result.Decision == model.RequireApproval && result.ApprovalKey != "" {
		status, _ := s.approvals.Check(result.ApprovalKey)
		if status == approval.StatusApproved {
			s.approvals.Consume(result.ApprovalKey)
			result.Decision = model.Allow
			result.Reason = "approved: " + result.Reason
		} else if status != approval.StatusPending && status != approval.StatusDenied {
			s.approvals.Request(result.ApprovalKey, result.Reason, result.PolicyID, action.Resource)
		}
	}

	return &pb.EvalResponse{
		Decision:    string(result.Decision),
		Reason:      result.Reason,
		Tier:        int32(result.Tier),
		PolicyId:    result.PolicyID,
		ApprovalKey: result.ApprovalKey,
		TraceId:     traceID,
	}, nil
}

// Approve implements the Approve RPC.
func (s *Server) Approve(ctx context.Context, req *pb.ApproveRequest) (*pb.ApproveResponse, error) {
	var duration time.Duration
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			return nil, fmt.Errorf("invalid duration %q: %w", req.Duration, err)
		}
	}

	if err := s.approvals.Approve(req.Key, duration); err != nil {
		return nil, err
	}

	return &pb.ApproveResponse{
		Key:    req.Key,
		Status: "approved",
	}, nil
}

// Deny implements the Deny RPC.
func (s *Server) Deny(ctx context.Context, req *pb.DenyRequest) (*pb.DenyResponse, error) {
	if err := s.approvals.Deny(req.Key); err != nil {
		return nil, err
	}

	return &pb.DenyResponse{
		Key:    req.Key,
		Status: "denied",
	}, nil
}

// ListPending implements the ListPending RPC.
func (s *Server) ListPending(ctx context.Context, req *pb.ListPendingRequest) (*pb.ListPendingResponse, error) {
	list, err := s.approvals.List()
	if err != nil {
		return nil, err
	}

	approvals := make([]*pb.PendingApproval, len(list))
	for i, a := range list {
		approvals[i] = &pb.PendingApproval{
			Key:       a.Key,
			Status:    string(a.Status),
			Resource:  a.Resource,
			Reason:    a.Reason,
			CreatedAt: a.CreatedAt.Format(time.RFC3339),
		}
	}

	return &pb.ListPendingResponse{Approvals: approvals}, nil
}

// ReloadPolicy atomically swaps policy and denylist config.
// Called by the hot-reloader on file change.
func (s *Server) ReloadPolicy() error {
	dl, err := denylist.Load(s.cfg.DenylistPath)
	if err != nil {
		return fmt.Errorf("failed to reload denylist: %w", err)
	}

	policyCfg, policyHash, err := policy.LoadConfigWithHash(s.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to reload policy config: %w", err)
	}

	if s.cfg.ProfileName != "" {
		prof, err := profile.Load(s.cfg.ProfileName)
		if err != nil {
			return fmt.Errorf("failed to reload profile %q: %w", s.cfg.ProfileName, err)
		}
		profile.ApplyToDenylist(prof, dl)
		policyCfg = profile.ApplyToPolicy(prof, policyCfg)
	}

	s.mu.Lock()
	s.policyCfg = policyCfg
	s.dl = dl
	s.policyHash = policyHash
	s.dispatcher = alert.NewDispatcher(policyCfg.Alerts)
	s.mu.Unlock()

	return nil
}

func (s *Server) getOrCreateSession(traceID string) *tracer.TraceAccumulator {
	if v, ok := s.sessions.Load(traceID); ok {
		return v.(*tracer.TraceAccumulator)
	}
	ta := tracer.NewAccumulator(traceID)
	actual, _ := s.sessions.LoadOrStore(traceID, ta)
	return actual.(*tracer.TraceAccumulator)
}

func (s *Server) recordAudit(action *model.Action, decision, reason string, tier int, policyHash, traceID string) {
	if s.auditLog != nil {
		s.auditLog.Record(audit.AuditEntry{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    traceID,
			Action:     audit.AuditAction{Tool: action.Tool, Resource: action.Resource},
			Decision:   decision,
			Reason:     reason,
			Tier:       tier,
			PolicyHash: policyHash,
		})
	}
}

func (s *Server) dispatchAlert(action *model.Action, decision, reason string, tier int, policyHash, traceID string) {
	s.mu.RLock()
	d := s.dispatcher
	s.mu.RUnlock()
	if d != nil {
		d.Dispatch(alert.AlertEvent{
			Timestamp:  time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			TraceID:    traceID,
			Tool:       action.Tool,
			Resource:   action.Resource,
			Decision:   decision,
			Reason:     reason,
			Tier:       tier,
			PolicyHash: policyHash,
		})
	}
}

// protoToAction converts a protobuf Action to a model.Action.
func protoToAction(pb *pb.Action) *model.Action {
	params := make(map[string]any, len(pb.Params))
	for k, v := range pb.Params {
		params[k] = v
	}
	rawMeta := make(map[string]any, len(pb.Meta))
	for k, v := range pb.Meta {
		rawMeta[k] = v
	}
	return &model.Action{
		Tool:      pb.Tool,
		Resource:  pb.Resource,
		Operation: pb.Operation,
		Params:    params,
		RawMeta:   rawMeta,
	}
}
