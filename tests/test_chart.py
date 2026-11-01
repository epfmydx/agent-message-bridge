"""Helm render checks for the independent bridge workload contract."""
from pathlib import Path
import shutil
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts" / "agent-message-bridge"
HELM = shutil.which("helm") or "helm"


def render(*args):
    result = subprocess.run([HELM, "template", "bridge-test", str(CHART), "--namespace", "bridge-test", *args], capture_output=True, text=True, check=True)
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def pod_spec(doc):
    return doc["spec"]["template"]["spec"]


def test_chart_metadata_and_default_independent_image():
    metadata = yaml.safe_load((CHART / "Chart.yaml").read_text())
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert metadata["name"] == "agent-message-bridge"
    assert metadata["version"] == metadata["appVersion"]
    assert values["image"]["repository"] == "agent-message-bridge/app"


def test_api_worker_and_init_share_image_config_and_security():
    docs = render()
    workloads = [doc for doc in docs if doc["kind"] in ("Deployment", "Job")]
    assert len(workloads) == 3
    commands = {}
    for doc in workloads:
        pod = pod_spec(doc)
        container = pod["containers"][0]
        component = doc["metadata"]["labels"]["app.kubernetes.io/component"]
        commands[component] = container.get("command")
        assert container["image"] == "agent-message-bridge/app:dev"
        assert container["envFrom"] == [{"secretRef": {"name": "agent-message-bridge-env"}}]
        expected_env = [{"name": "BRIDGE_CONFIG", "value": "/run/bridge/config.json"}]
        if component == "api":
            expected_env += [{"name": "CLOUDFLARE_ORIGIN_SECRET", "valueFrom": {"secretKeyRef": {
                "name": "agent-message-bridge-admin-origin", "key": "CLOUDFLARE_ORIGIN_SECRET", "optional": True}}},
                {"name": "TRUSTED_PROXY_CIDRS", "value": ""}]
        assert container["env"] == expected_env
        assert pod["volumes"][0] == {"name": "bridge-config", "secret": {
            "secretName": "agent-message-bridge-config", "items": [{"key": "config.json", "path": "config.json"}]}}
        mount = next(item for item in container["volumeMounts"] if item["name"] == "bridge-config")
        assert mount == {"name": "bridge-config", "mountPath": "/run/bridge", "readOnly": True}
        assert {"name": "tmp", "emptyDir": {}} in pod["volumes"]
        assert pod["automountServiceAccountToken"] is False
        assert pod["securityContext"]["runAsUser"] == 10001
        assert pod["securityContext"]["runAsNonRoot"] is True
        assert container["securityContext"] == {"allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    assert commands["worker"] == ["python", "-m", "bridge", "worker"]
    assert commands["init-db"] == ["python", "-m", "bridge", "init-db"]
    assert next(doc for doc in workloads if doc["metadata"]["labels"]["app.kubernetes.io/component"] == "api")["spec"]["template"]["spec"]["containers"][0].get("command") is None


def test_cluster_internal_api_readiness_no_ingress_or_database_resources():
    docs = render()
    service = next(doc for doc in docs if doc["kind"] == "Service")
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"] == [{"name": "http", "port": 8000, "targetPort": "http", "protocol": "TCP"}]
    api = next(doc for doc in docs if doc["kind"] == "Deployment")
    container = api["spec"]["template"]["spec"]["containers"][0]
    assert container["readinessProbe"]["httpGet"] == {"path": "/healthz", "port": "http"}
    assert "livenessProbe" not in container
    assert not any(doc["kind"] in ("Ingress", "HTTPRoute", "StatefulSet", "PersistentVolumeClaim", "Secret") for doc in docs)


def test_digest_pins_all_workloads_and_rejects_bad_digest():
    digest = "sha256:" + "a" * 64
    docs = render("--set", "image.repository=registry.example.com/bridge/agent-message-bridge/app", "--set", f"image.digest={digest}")
    for doc in (doc for doc in docs if doc["kind"] in ("Deployment", "Job")):
        assert pod_spec(doc)["containers"][0]["image"] == "registry.example.com/bridge/agent-message-bridge/app@" + digest
    result = subprocess.run([HELM, "template", "bridge", str(CHART), "--set", "image.digest=sha256:bad"], capture_output=True, text=True)
    assert result.returncode != 0
    result = subprocess.run([HELM, "template", "bridge", str(CHART), "--set", "image.tag="], capture_output=True, text=True)
    assert result.returncode != 0


def test_chart_source_and_docker_are_owned_by_this_project():
    dockerfile = (ROOT / "Dockerfile").read_text()
    compose = (ROOT / "compose.yaml").read_text()
    assert "FROM python:3.15-slim" in dockerfile
    assert "COPY bridge ./bridge" in dockerfile
    assert "COPY requirements.txt requirements.lock" in dockerfile
    assert "agent-message-bridge:local" in compose


def test_long_fullname_override_reserves_space_for_resource_suffixes():
    docs = render("--set", "fullnameOverride=" + "r" * 63)
    assert docs
    for doc in docs:
        assert len(doc["metadata"]["name"]) <= 63
    workload_names = {doc["metadata"]["name"] for doc in docs if doc["kind"] in ("Deployment", "Job")}
    assert workload_names == {"r" * 55 + "-api", "r" * 55 + "-worker", "r" * 55 + "-init-db"}


def test_long_prerelease_truncation_keeps_chart_label_valid(tmp_path):
    import re

    staged = tmp_path / "chart"
    shutil.copytree(CHART, staged)
    metadata = yaml.safe_load((staged / "Chart.yaml").read_text())
    version = "0.1.0-" + "a" * 45 + ".b"
    metadata.update(version=version, appVersion=version)
    (staged / "Chart.yaml").write_text(yaml.safe_dump(metadata))
    result = subprocess.run([HELM, "template", "bridge-test", str(staged)], capture_output=True, text=True, check=True)
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc]
    for doc in docs:
        label = doc["metadata"]["labels"]["helm.sh/chart"]
        assert len(label) <= 63
        assert re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", label)


def test_docker_context_is_whitelisted_to_independent_application_inputs():
    rules = (ROOT / ".dockerignore").read_text().splitlines()
    assert rules[:6] == ["**", "!Dockerfile", "!requirements.txt", "!requirements.lock", "!bridge/", "!bridge/**"]
    assert "**/__pycache__/" in rules
    assert "**/*.py[cod]" in rules
    assert "**/.pytest_cache/" in rules
