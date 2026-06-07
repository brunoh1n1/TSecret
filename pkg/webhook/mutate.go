// Package webhook implements the mutating admission webhook for TSecret injection.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/brunoh1n1/tsecret/pkg/apis/v1alpha1"
)

const (
	tsecretMountRoot     = "/var/run/tsecret"
	tsecretInitPrefix    = "tsecret-init-"
	defaultInjectorImage = "tsecret:latest"

	// AnnotExportEnv enables runtime env export via load-env.sh (pod or per-container).
	AnnotExportEnv = "tsecret.io/export-env"
	// AnnotEntrypoint is the shell command to exec after sourcing load-env.sh.
	AnnotEntrypoint = "tsecret.io/entrypoint"
)

// TSecretInjector handles mutating admission requests for pods.
type TSecretInjector struct {
	Client         client.Client
	Log            logr.Logger
	Decoder        admission.Decoder
	InjectorImage  string
}

type tsecretInjection struct {
	secretName  string
	volumeName  string
	mountPath   string
	prefix      string
	exportEnv   bool
	containers  map[string]struct{}
}

type containerExportPlan struct {
	loaders []string
}

// Handle processes admission requests for pod creation/update.
func (i *TSecretInjector) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := i.Decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("failed to decode pod: %w", err))
	}

	log := i.Log.WithValues("pod", pod.Name, "namespace", req.Namespace)
	injectorImage := i.InjectorImage
	if injectorImage == "" {
		injectorImage = defaultInjectorImage
	}

	plans, resp := i.collectInjections(ctx, pod, req.Namespace)
	if resp != nil {
		return *resp
	}

	if len(plans) == 0 {
		return admission.Allowed("no TSecret references found")
	}

	exportPlans := make(map[string]*containerExportPlan)

	for _, plan := range plans {
		i.ensurePodFSGroup(pod)
		i.ensureMemoryVolume(pod, plan.volumeName)

		for containerName := range plan.containers {
			if exportEnvEnabled(pod, containerName) {
				plan.exportEnv = true
				ep, ok := exportPlans[containerName]
				if !ok {
					ep = &containerExportPlan{}
					exportPlans[containerName] = ep
				}
				ep.loaders = appendUnique(ep.loaders, plan.mountPath+"/load-env.sh")
			}
		}

		i.ensureRuntimeInitContainer(pod, plan, injectorImage, req.Namespace)

		for containerName := range plan.containers {
			container := findContainer(pod, containerName)
			if container == nil {
				continue
			}
			i.ensureVolumeMount(container, plan.volumeName, plan.mountPath)
		}

		log.V(1).Info("Scheduled runtime TSecret injection",
			"tsecret", plan.secretName,
			"volume", plan.volumeName,
			"mountPath", plan.mountPath,
			"exportEnv", plan.exportEnv,
		)
	}

	for containerName, exportPlan := range exportPlans {
		container := findContainer(pod, containerName)
		if container == nil {
			continue
		}
		entrypoint, err := resolveEntrypoint(pod, container)
		if err != nil {
			return admission.Denied(err.Error())
		}
		wrapContainerForEnvLoader(container, exportPlan.loaders, entrypoint)
		log.V(1).Info("Enabled optional runtime env export",
			"container", containerName,
			"loaders", len(exportPlan.loaders),
		)
	}

	marshaledPod, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError,
			fmt.Errorf("failed to marshal modified pod: %w", err))
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

func (i *TSecretInjector) collectInjections(
	ctx context.Context,
	pod *corev1.Pod,
	namespace string,
) (map[string]*tsecretInjection, *admission.Response) {
	plans := make(map[string]*tsecretInjection)

	getPlan := func(volumeName, secretName, mountPath, prefix string) *tsecretInjection {
		key := volumeName + "\x00" + secretName
		plan, ok := plans[key]
		if !ok {
			plan = &tsecretInjection{
				secretName: secretName,
				volumeName: volumeName,
				mountPath:  mountPath,
				prefix:     prefix,
				containers: make(map[string]struct{}),
			}
			plans[key] = plan
		}
		if prefix != "" && plan.prefix == "" {
			plan.prefix = prefix
		}
		if plan.mountPath == "" {
			plan.mountPath = mountPath
		}
		return plan
	}

	for vi := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[vi]
		if vol.Secret == nil {
			continue
		}

		if _, err := i.getTSecret(ctx, vol.Secret.SecretName, namespace); err != nil {
			continue
		}

		mountPath := tsecretMountPath(vol.Secret.SecretName)
		for ci := range pod.Spec.Containers {
			for _, mount := range pod.Spec.Containers[ci].VolumeMounts {
				if mount.Name == vol.Name && mount.MountPath != "" {
					mountPath = mount.MountPath
					break
				}
			}
		}

		plan := getPlan(vol.Name, vol.Secret.SecretName, mountPath, "")
		vol.Secret = nil
		vol.EmptyDir = &corev1.EmptyDirVolumeSource{
			Medium: corev1.StorageMediumMemory,
		}

		for ci := range pod.Spec.Containers {
			for _, mount := range pod.Spec.Containers[ci].VolumeMounts {
				if mount.Name == vol.Name {
					plan.containers[pod.Spec.Containers[ci].Name] = struct{}{}
				}
			}
		}
	}

	collectFromContainer := func(container *corev1.Container) {
		remainingEnvFrom := make([]corev1.EnvFromSource, 0, len(container.EnvFrom))
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef == nil {
				remainingEnvFrom = append(remainingEnvFrom, envFrom)
				continue
			}

			if _, err := i.getTSecret(ctx, envFrom.SecretRef.Name, namespace); err != nil {
				remainingEnvFrom = append(remainingEnvFrom, envFrom)
				continue
			}

			volumeName := tsecretVolumeName(envFrom.SecretRef.Name)
			mountPath := tsecretMountPath(envFrom.SecretRef.Name)
			plan := getPlan(volumeName, envFrom.SecretRef.Name, mountPath, envFrom.Prefix)
			plan.containers[container.Name] = struct{}{}
		}
		container.EnvFrom = remainingEnvFrom

		remainingEnv := make([]corev1.EnvVar, 0, len(container.Env))
		for _, env := range container.Env {
			if env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil {
				remainingEnv = append(remainingEnv, env)
				continue
			}

			ref := env.ValueFrom.SecretKeyRef
			if _, err := i.getTSecret(ctx, ref.Name, namespace); err != nil {
				remainingEnv = append(remainingEnv, env)
				continue
			}

			volumeName := tsecretVolumeName(ref.Name)
			mountPath := tsecretMountPath(ref.Name)
			plan := getPlan(volumeName, ref.Name, mountPath, "")
			plan.containers[container.Name] = struct{}{}
		}
		container.Env = remainingEnv
	}

	for ci := range pod.Spec.Containers {
		collectFromContainer(&pod.Spec.Containers[ci])
	}
	for ci := range pod.Spec.InitContainers {
		if strings.HasPrefix(pod.Spec.InitContainers[ci].Name, tsecretInitPrefix) {
			continue
		}
		collectFromContainer(&pod.Spec.InitContainers[ci])
	}

	return plans, nil
}

func (i *TSecretInjector) ensurePodFSGroup(pod *corev1.Pod) {
	if pod.Spec.SecurityContext == nil {
		pod.Spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if pod.Spec.SecurityContext.FSGroup == nil {
		group := int64(65532)
		pod.Spec.SecurityContext.FSGroup = &group
	}
}

func (i *TSecretInjector) ensureMemoryVolume(pod *corev1.Pod, volumeName string) {
	for _, vol := range pod.Spec.Volumes {
		if vol.Name == volumeName {
			return
		}
	}

	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: volumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory,
			},
		},
	})
}

func (i *TSecretInjector) ensureRuntimeInitContainer(
	pod *corev1.Pod,
	plan *tsecretInjection,
	injectorImage, podNamespace string,
) {
	initName := tsecretInitPrefix + plan.volumeName
	for _, init := range pod.Spec.InitContainers {
		if init.Name == initName {
			return
		}
	}

	args := []string{
		fmt.Sprintf("--secret=%s", plan.secretName),
		fmt.Sprintf("--mount=%s", plan.mountPath),
		fmt.Sprintf("--namespace=%s", podNamespace),
	}
	if plan.prefix != "" {
		args = append(args, fmt.Sprintf("--prefix=%s", plan.prefix))
	}
	if plan.exportEnv {
		args = append(args, "--export-env")
	}

	pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{
		Name:            initName,
		Image:           injectorImage,
		Command:         []string{"/tsecret-inject"},
		Args:            args,
		ImagePullPolicy: corev1.PullIfNotPresent,
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      plan.volumeName,
				MountPath: plan.mountPath,
			},
		},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			ReadOnlyRootFilesystem:   boolPtr(true),
			RunAsNonRoot:             boolPtr(true),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		},
	})
}

func (i *TSecretInjector) ensureVolumeMount(container *corev1.Container, volumeName, mountPath string) {
	for _, mount := range container.VolumeMounts {
		if mount.Name == volumeName {
			return
		}
	}

	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
		Name:      volumeName,
		MountPath: mountPath,
		ReadOnly:  true,
	})
}

func (i *TSecretInjector) getTSecret(ctx context.Context, name, namespace string) (*v1alpha1.TSecret, error) {
	tsecret := &v1alpha1.TSecret{}
	key := client.ObjectKey{Name: name, Namespace: namespace}
	if err := i.Client.Get(ctx, key, tsecret); err != nil {
		return nil, err
	}
	return tsecret, nil
}

func findContainer(pod *corev1.Pod, name string) *corev1.Container {
	for ci := range pod.Spec.Containers {
		if pod.Spec.Containers[ci].Name == name {
			return &pod.Spec.Containers[ci]
		}
	}
	for ci := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[ci].Name == name {
			return &pod.Spec.InitContainers[ci]
		}
	}
	return nil
}

func tsecretVolumeName(secretName string) string {
	return "tsecret-" + secretName
}

func tsecretMountPath(secretName string) string {
	return tsecretMountRoot + "/" + secretName
}

func boolPtr(v bool) *bool {
	return &v
}

func exportEnvEnabled(pod *corev1.Pod, containerName string) bool {
	if pod.Annotations == nil {
		return false
	}
	if v, ok := pod.Annotations[AnnotExportEnv+"."+containerName]; ok {
		return strings.EqualFold(v, "true")
	}
	if v, ok := pod.Annotations[AnnotExportEnv]; ok {
		return strings.EqualFold(v, "true")
	}
	return false
}

func resolveEntrypoint(pod *corev1.Pod, container *corev1.Container) (string, error) {
	if pod.Annotations != nil {
		if v, ok := pod.Annotations[AnnotEntrypoint+"."+container.Name]; ok && strings.TrimSpace(v) != "" {
			return v, nil
		}
		if v, ok := pod.Annotations[AnnotEntrypoint]; ok && strings.TrimSpace(v) != "" {
			return v, nil
		}
	}
	if len(container.Command) > 0 || len(container.Args) > 0 {
		return shellJoin(append(append([]string{}, container.Command...), container.Args...)), nil
	}
	return "", fmt.Errorf(
		"tsecret.io/export-env enabled for container %q but no entrypoint found: set annotation %s.%s or %s, or define container command/args",
		container.Name, AnnotEntrypoint, container.Name, AnnotEntrypoint,
	)
}

func wrapContainerForEnvLoader(container *corev1.Container, loaders []string, entrypoint string) {
	if alreadyWrapped(container) {
		return
	}

	source := ""
	for _, loader := range loaders {
		source += fmt.Sprintf(". %s; ", loader)
	}

	container.Command = []string{"/bin/sh", "-c"}
	container.Args = []string{fmt.Sprintf(
		"set -a; %sset +a; exec %s",
		source, entrypoint,
	)}
}

func alreadyWrapped(container *corev1.Container) bool {
	if len(container.Args) == 0 {
		return false
	}
	return strings.Contains(container.Args[0], "load-env.sh")
}

func shellJoin(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	quoted := make([]string, len(parts))
	for i, part := range parts {
		quoted[i] = shellQuote(part)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
