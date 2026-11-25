# Deploy scenarios

Select scenarios and their Terragrunt units in `config/config.yaml` and deploy through the [AttackBed CLI](../tools/attackbed.md).

```sh
uv run attackbed deploy core                    # Bootstrap only
uv run attackbed deploy videoserver -c 2        # Two copies of Scenario 1
uv run attackbed deploy -a -v -p 7              # All seven documented attack scenarios, without provider VLANs
uv run attackbed destroy RUN_ID -s              # Destroy a saved run and delete empty Terraform states
```

`all` is a union of all Terragrunt units for `attackbed build all`. `core` deploys only bootstrap. Both are excluded from `deploy --all-scenarios`.

Bootstrap runs before scenario units; the order is reversed during destruction.

![Videoserver](../images/AttackBed-Videoserver.png)
