package sd

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/elastic/go-freelru"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type DiscoveryTarget map[string]string

func (t *DiscoveryTarget) DebugString() string {
	var b strings.Builder
	b.WriteByte('{')
	for k, v := range *t {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte(',')
	}
	b.WriteByte('}')
	return b.String()
}

const (
	labelContainerID      = "__container_id__"
	labelPID              = "__process_pid__"
	labelServiceName      = "service_name"
	labelServiceNameK8s   = "__meta_kubernetes_pod_annotation_pyroscope_io_service_name"
	MetricValueProcessCPU = "process_cpu"
	MetricValueOffCPU     = "offcpu"
)

type Target struct {
	// todo make keep it a map until Append happens
	labels      labels.Labels
	serviceName string
	fingerprint uint64
}

func NewTarget(cid containerID, pid uint32, target DiscoveryTarget) *Target {
	serviceName := target[labelServiceName]
	if serviceName == "" {
		serviceName = inferServiceName(target)
	}

	lset := make(map[string]string, len(target))
	for k, v := range target {
		if strings.HasPrefix(k, model.ReservedLabelPrefix) &&
			k != labels.MetricName {
			continue
		}
		lset[k] = v
	}
	if lset[labelServiceName] == "" {
		lset[labelServiceName] = serviceName
	}
	if cid != "" {
		lset[labelContainerID] = string(cid)
	}
	if pid != 0 {
		lset[labelPID] = strconv.Itoa(int(pid))
	}
	ls := labels.FromMap(lset)
	return &Target{
		labels:      ls,
		fingerprint: ls.Hash(),
		serviceName: serviceName,
	}
}

func (t *Target) ServiceName() string {
	return t.serviceName
}

func inferServiceName(target DiscoveryTarget) string {
	k8sServiceName := target[labelServiceNameK8s]
	if k8sServiceName != "" {
		return k8sServiceName
	}
	k8sNamespace := target["__meta_kubernetes_namespace"]
	k8sContainer := target["__meta_kubernetes_pod_container_name"]
	if k8sNamespace != "" && k8sContainer != "" {
		return fmt.Sprintf("ebpf/%s/%s", k8sNamespace, k8sContainer)
	}
	dockerContainer := target["__meta_docker_container_name"]
	if dockerContainer != "" {
		return dockerContainer
	}
	if swarmService := target["__meta_dockerswarm_container_label_service_name"]; swarmService != "" {
		return swarmService
	}
	if swarmService := target["__meta_dockerswarm_service_name"]; swarmService != "" {
		return swarmService
	}
	return "unspecified"
}

func (t *Target) Labels() (uint64, labels.Labels) {
	return t.fingerprint, t.labels
}

func (t *Target) String() string {
	return t.labels.String()
}

func (t *Target) Get(k string) (string, bool) {
	v := t.labels.Get(k)
	return v, v != ""
}

func (t *Target) GetFlag(k string) (bool, bool) {
	v := t.labels.Get(k)
	return v == "true", v != ""
}

type containerID string

type TargetFinder interface {
	FindTarget(pid uint32) *Target
	Update(args TargetsOptions)
}
type TargetsOptions struct {
	Targets       []DiscoveryTarget
	TargetsOnly   bool
	DefaultTarget DiscoveryTarget
}

type targetFinder struct {
	l          log.Logger
	cid2target map[containerID]*Target
	pid2target map[uint32]*Target

	cgroups       *freelru.SyncedLRU[libpf.PID, string]
	defaultTarget *Target

	sync sync.Mutex
}

func NewTargetFinder(l log.Logger, cgroups *freelru.SyncedLRU[libpf.PID, string], options TargetsOptions) (TargetFinder, error) {
	res := &targetFinder{
		l:       l,
		cgroups: cgroups,
	}
	res.setTargets(options)
	return res, nil
}

func (tf *targetFinder) FindTarget(pid uint32) *Target {
	tf.sync.Lock()
	defer tf.sync.Unlock()
	res := tf.findTarget(pid)
	if res != nil {
		return res
	}
	return tf.defaultTarget
}

func (tf *targetFinder) Update(args TargetsOptions) {
	tf.sync.Lock()
	defer tf.sync.Unlock()
	tf.setTargets(args)
}

func (tf *targetFinder) setTargets(opts TargetsOptions) {
	_ = level.Debug(tf.l).Log("msg", "set targets", "count", len(opts.Targets))
	containerID2Target := make(map[containerID]*Target)
	pid2Target := make(map[uint32]*Target)
	oco := func(prev, next *Target) *Target {
		if prev != nil && prev.fingerprint == next.fingerprint {
			return prev
		}
		return next
	}
	for _, target := range opts.Targets {
		if pid := pidFromTarget(target); pid != 0 {
			t := NewTarget("", pid, target)
			pid2Target[pid] = oco(tf.pid2target[pid], t)
		} else if cid := containerIDFromTarget(target); cid != "" {
			t := NewTarget(cid, 0, target)
			containerID2Target[cid] = oco(tf.cid2target[cid], t)
		}
	}
	if len(opts.Targets) > 0 && len(containerID2Target) == 0 && len(pid2Target) == 0 {
		_ = level.Warn(tf.l).Log("msg", "No targets found")
	}
	tf.cid2target = containerID2Target
	tf.pid2target = pid2Target
	if opts.TargetsOnly {
		tf.defaultTarget = nil
	} else {
		t := NewTarget("", 0, opts.DefaultTarget)
		tf.defaultTarget = oco(tf.defaultTarget, t)
	}
	_ = level.Debug(tf.l).Log("msg", "created targets", "cid2target", len(tf.cid2target), "pid2target", len(tf.pid2target))
}

func (tf *targetFinder) findTarget(pid uint32) *Target {
	if target, ok := tf.pid2target[pid]; ok {
		return target
	}
	cgroup, err := libpf.LookupCgroupv2(tf.cgroups, libpf.PID(pid))
	if err != nil {
		return nil
	}
	cid := getContainerIDFromCGroup(cgroup)
	if cid == "" {
		return nil
	}

	return tf.cid2target[containerID(cid)]
}

func pidFromTarget(target DiscoveryTarget) uint32 {
	t, ok := target[labelPID]
	if !ok {
		return 0
	}
	var pid uint64
	var err error
	pid, err = strconv.ParseUint(t, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(pid)
}

func containerIDFromTarget(target DiscoveryTarget) containerID {
	cid, ok := target[labelContainerID]
	if ok && cid != "" {
		return containerID(cid)
	}
	cid, ok = target["__meta_kubernetes_pod_container_id"]
	if ok && cid != "" {
		return getContainerIDFromK8S(cid)
	}
	cid, ok = target["__meta_docker_container_id"]
	if ok && cid != "" {
		return containerID(cid)
	}
	if cid, ok = target["__meta_dockerswarm_task_container_id"]; ok && cid != "" {
		return containerID(cid)
	}
	return ""
}
