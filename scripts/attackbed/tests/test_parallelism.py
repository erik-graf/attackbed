"""The CLI override must not conflict with Terragrunt's apply arguments."""

import os
from pathlib import Path
import unittest
from unittest import mock


from attackbed import deploy


class ParallelismTests(unittest.TestCase):
    def test_tofu_parallelism(self):
        for action in ("apply", "plan", "destroy"):
            for override in (None, 3):
                with self.subTest(action=action, override=override):
                    with mock.patch.dict(os.environ, {"TF_VAR_parallelism": "1"}):
                        with mock.patch.object(deploy.subprocess, "Popen") as popen:
                            process = popen.return_value.__enter__.return_value
                            process.stdout = []
                            process.wait.return_value = 0
                            result = deploy.TerragruntDeployment(
                                Path("/tmp"), "lab-001", ["bootstrap"],
                                tofu_parallelism=override,
                            ).run_unit("bootstrap", action)
                    self.assertIsNone(result)
                    cmd = popen.call_args.args[0]
                    if action in ("apply", "destroy"):
                        self.assertIn("-auto-approve", cmd)
                    env = popen.call_args.kwargs["env"]
                    self.assertEqual(env["TF_VAR_parallelism"],
                                     "3" if action == "apply" and override == 3 else "1")
                    flags = [arg for arg in cmd if arg.startswith("-parallelism=")]
                    self.assertEqual(flags, ["-parallelism=3"] if action != "apply" and override == 3 else [])

    def test_unset_override_preserves_hcl_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(deploy.subprocess, "Popen") as popen:
                process = popen.return_value.__enter__.return_value
                process.stdout = []
                process.wait.return_value = 0
                deployment = deploy.TerragruntDeployment(Path("/tmp"), "lab-001", ["bootstrap"])
                deployment.run_unit("bootstrap", "apply")
        self.assertNotIn("TF_VAR_parallelism", popen.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
