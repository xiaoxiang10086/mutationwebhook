package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CertFile = "/etc/webhook/certs/tls.crt"
	KeyFile  = "/etc/webhook/certs/tls.key"
)

var clientset *kubernetes.Clientset

// Webhook implements a mutating webhook for automatic container injection.
type Webhook struct {
	certFile string
	keyFile  string
	cert     *tls.Certificate

	server *http.Server
}

func (wh *Webhook) getCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return wh.cert, nil
}

// WebhookParameters configures parameters for the mutation webhook.
type WebhookParameters struct {
	// CertFile is the path to the x509 certificate for https.
	CertFile string

	// KeyFile is the path to the x509 private key matching `CertFile`.
	KeyFile string

	// Port is the webhook port, e.g. typically 443 for https.
	Port int
}

// NewWebhook creates a new instance of a mutating webhook for automatic sidecar injection.
func NewWebhook(p WebhookParameters) (*Webhook, error) {
	pair, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}

	wh := &Webhook{
		certFile: p.CertFile,
		keyFile:  p.KeyFile,
		cert:     &pair,
	}

	clientset, err = CreateKubernetesClient()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
		return wh, err
	}

	mux := http.NewServeMux()
	wh.server = &http.Server{
		Addr:      fmt.Sprintf(":%v", p.Port),
		TLSConfig: &tls.Config{GetCertificate: wh.getCert},
	}
	mux.HandleFunc("/mutate", wh.serveMutate)
	wh.server.Handler = mux

	return wh, nil
}

func (wh *Webhook) Run() {
	if err := wh.server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("failed to listen and serve webhook server: %v", err)
	}
}

func CreateKubernetesClient() (*kubernetes.Clientset, error) {
	// create a Kubernetes client config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client config: %v", err)
	}

	return kubernetes.NewForConfig(config)
}

func main() {
	parameters := WebhookParameters{
		CertFile: CertFile,
		KeyFile:  KeyFile,
		Port:     8443,
	}

	wh, err := NewWebhook(parameters)
	if err != nil {
		fmt.Errorf("failed to create mutate webhook: %v", err)
		return
	}

	wh.Run()
}

func (wh *Webhook) serveMutate(w http.ResponseWriter, r *http.Request) {
	var admissionReviewReq v1beta1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&admissionReviewReq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	pod := corev1.Pod{}
	if err := json.Unmarshal(admissionReviewReq.Request.Object.Raw, &pod); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	patchBytes, err := createPatch(&pod)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admissionReviewResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			UID:     admissionReviewReq.Request.UID,
			Allowed: true,
			Patch:   patchBytes,
			PatchType: func() *v1beta1.PatchType {
				pt := v1beta1.PatchTypeJSONPatch
				return &pt
			}(),
		},
		TypeMeta: admissionReviewReq.TypeMeta,
	}

	if err := json.NewEncoder(w).Encode(admissionReviewResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createPatch(pod *corev1.Pod) ([]byte, error) {
	var patch []patchOperation

	if shouldInjectSidecar(pod) {
		fmt.Printf("should inject sidecar\n")

		container := corev1.Container{
			Name:  "injected-container",
			Image: "busybox",
			Command: []string{
				"sh",
				"-c",
				"echo 'Hello from the injected container!' && sleep 3600",
			},
		}
		pod.Spec.Containers = append(pod.Spec.Containers, container)

		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  "/spec/containers/-",
			Value: container,
		})

	} else {
		fmt.Printf("should not inject sidecar\n")
	}

	return json.Marshal(patch)
}

func shouldInjectSidecar(pod *corev1.Pod) bool {
	labels := pod.GetLabels()
	namespace := pod.GetNamespace()

	if labels != nil {
		if value, ok := labels["mosn.io/sidecar-inject"]; ok && value == "false" {
			return false
		}
	}

	ns, err := clientset.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		log.Printf("Failed to get namespace %s: %v\n", namespace, err)
		return false
	}

	if ns.Labels != nil {
		if value, ok := ns.Labels["mosn.io/layotto-inject"]; ok && value == "true" {
			return true
		}
	}

	return false
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
