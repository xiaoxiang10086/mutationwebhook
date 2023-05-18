package main

import (
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

func main() {
	fmt.Println("Hello World!")
	http.HandleFunc("/mutate", mutateHandler)
	log.Fatal(http.ListenAndServeTLS(":8443", CertFile, KeyFile, nil))
}

func mutateHandler(w http.ResponseWriter, r *http.Request) {
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

	annotations := pod.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	if annotations["ossp"] == "2023" {
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
	}

	patchBytes, err := createPatch(&pod)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	admissionReviewResponse := v1beta1.AdmissionReview{
		Response: &v1beta1.AdmissionResponse{
			Allowed: true,
			Patch:   patchBytes,
			PatchType: func() *v1beta1.PatchType {
				pt := v1beta1.PatchTypeJSONPatch
				return &pt
			}(),
		},
	}

	if err := json.NewEncoder(w).Encode(admissionReviewResponse); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createPatch(pod *corev1.Pod) ([]byte, error) {
	var patch []patchOperation

	container := corev1.Container{
		Name:  "injected-container",
		Image: "busybox",
		Command: []string{
			"sh",
			"-c",
			"echo 'Hello from the injected container!' && sleep 3600",
		},
	}

	patch = append(patch, patchOperation{
		Op:    "add",
		Path:  "/spec/containers/-",
		Value: container,
	})

	return json.Marshal(patch)
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}
