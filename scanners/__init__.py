from . import disk_encryption, firewall, password_policy, virtualization

# Registry of every scanner module to run. Add a new check by writing a
# module with a run() -> CheckResult function and listing it here.
CHECKS = [firewall, disk_encryption, password_policy, virtualization]


def run_all():
    return [module.run() for module in CHECKS]
