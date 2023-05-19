package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
)

const (
	CertFile = "/etc/webhook/certs/tls.crt"
	KeyFile  = "/etc/webhook/certs/tls.key"
)

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

func main() {
	parameters := WebhookParameters{
		CertFile: CertFile,
		KeyFile:  KeyFile,
		Port:     8443,
	}

	wh, err := NewWebhook(parameters)
	if err != nil {
		fmt.Errorf("failed to create mutate webhook: %v", err)
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

	labels := pod.GetLabels()
	if labels != nil {
		if value, ok := labels["ossp"]; ok && value == "2023" {
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
		}
	}

	return json.Marshal(patch)
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
