import pytest

from g9_backend.executor.worker_manager import (
    ContainerWorkerManager, IsolationError, KvmWorkerManager, WorkerRouter,
    CONTAINER_PROFILE, KVM_GUEST_PROFILE,
)

SPEC = {
    "action_id": "ACT-W1", "tool_id": "httpx",
    "sandbox_profile": "restricted-analysis",
    "normalized_arguments": {"url": "http://lab-api.g9.local/"},
}


@pytest.fixture()
def router():
    return WorkerRouter(ContainerWorkerManager(), KvmWorkerManager())


class TestWorkerRouter:
    def test_restricted_analysis_goes_to_container(self, router):
        route = router.route(SPEC)
        assert route.technology == "container"
        assert route.worker_class == "restricted-analysis"
        assert route.profile["capabilities"] == "drop=ALL"
        assert route.profile["security_opt"] == ["no-new-privileges"]
        assert route.profile["read_only_rootfs"] is True

    def test_hostile_research_goes_to_kvm_and_refuses_to_fake(self, router):
        spec = {**SPEC, "sandbox_profile": "hostile-research-vm"}
        with pytest.raises(NotImplementedError, match="refusing to fake"):
            router.route(spec)

    def test_hard_rule_hostile_never_downgrades_to_container(self, router):
        """A hostile workload must never be routable to a container — the
        untrusted-binary path is forced to the VM class, which (without a
        real runtime) refuses to fake execution rather than downgrading."""
        with pytest.raises(NotImplementedError, match="refusing to fake"):
            router.route_untrusted_binary({**SPEC, "untrusted_code": True})
        # with the stub explicitly allowed, the forced class is VM — never container
        route = router.route_untrusted_binary({**SPEC, "untrusted_code": True, "allow_stub": True})
        assert route.worker_class == "hostile-research-vm"
        assert route.technology == "kvm"
        assert route.profile["credentials"].startswith("none")

    def test_unknown_sandbox_class_refused(self, router):
        with pytest.raises(IsolationError, match="unknown sandbox class"):
            router.route({**SPEC, "sandbox_profile": "bare-metal"})

    def test_trusted_service_not_dispatched_via_worker_plane(self, router):
        with pytest.raises(IsolationError, match="hardened host processes"):
            router.route({**SPEC, "sandbox_profile": "trusted-service"})

    def test_kvm_stub_dispatch_when_explicitly_allowed(self, router):
        spec = {**SPEC, "sandbox_profile": "hostile-research-vm", "allow_stub": True}
        route = router.route(spec)
        assert route.technology == "kvm"
        assert route.profile["disposable"] is True
        assert KVM_GUEST_PROFILE["network"].startswith("VM-layer")

    def test_container_profile_never_grants_privileges(self):
        assert CONTAINER_PROFILE["capabilities"] == "drop=ALL"
        assert "no-new-privileges" in CONTAINER_PROFILE["security_opt"]
        assert CONTAINER_PROFILE["readonly_mounts_only"] is True
