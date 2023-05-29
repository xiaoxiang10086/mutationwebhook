package webhook

import (
	log "github.com/sirupsen/logrus"
	"github.com/xiaoxiang10086/mutationwebhook/internal/admission"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	admissionWebhookLabelInjectKey = "mosn.io/sidecar-inject"
)

// SidecarInjectorPatcher Sidecar Injector patcher
type SidecarInjectorPatcher struct {
	K8sClient kubernetes.Interface
}

// shouldInjectSidecar check if the sidecar should be injected
func (patcher *SidecarInjectorPatcher) shouldInjectSidecar(pod *corev1.Pod) bool {
	labels := pod.GetLabels()

	shouldInject := true
	if labels != nil {
		if value, ok := labels[admissionWebhookLabelInjectKey]; ok && value == "false" {
			shouldInject = false
		}
	}

	return shouldInject
}

// addContainer add container to pod
func addContainer(pod corev1.Pod) admission.PatchOperation {
	value := corev1.Container{
		Name:  "injected-container",
		Image: "busybox",
		Command: []string{
			"sh",
			"-c",
			"echo 'Hello from the injected container!' && sleep 3600",
		},
	}

	path := "/spec/containers"
	first := len(pod.Spec.Containers) == 0
	if !first {
		path = path + "/-"
	}

	patch := admission.PatchOperation{
		Op:    "add",
		Path:  path,
		Value: value,
	}

	return patch
}

// PatchPodCreate Handle Pod Create Patch
func (patcher *SidecarInjectorPatcher) PatchPodCreate(namespace string, pod corev1.Pod) ([]admission.PatchOperation, error) {
	podName := pod.GetName()
	if podName == "" {
		podName = pod.GetGenerateName()
	}
	var patches []admission.PatchOperation

	if patcher.shouldInjectSidecar(&pod) {
		patches = append(patches, addContainer(pod))
	}

	log.Debugf("sidecar patches being applied for %v/%v: patches: %v", namespace, podName, patches)
	return patches, nil
}

// PatchPodUpdate not supported, only support create
func (patcher *SidecarInjectorPatcher) PatchPodUpdate(_ string, _ corev1.Pod, _ corev1.Pod) ([]admission.PatchOperation, error) {
	return nil, nil
}

// PatchPodDelete not supported, only support create
func (patcher *SidecarInjectorPatcher) PatchPodDelete(_ string, _ corev1.Pod) ([]admission.PatchOperation, error) {
	return nil, nil
}
