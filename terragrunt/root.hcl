locals {
  deployment_id = get_env("ATTACKBED_DEPLOYMENT_ID")

  # Paths are relative to the repository, not the Terragrunt cache or unit folder.
  # Tracked defaults.tfvars are overridden by optional, gitignored terraform.tfvars.
  config_dir     = "${get_repo_root()}/terragrunt"
  defaults_file  = "${local.config_dir}/defaults.tfvars"
  overrides_file = "${local.config_dir}/terraform.tfvars"
  defaults       = jsondecode(read_tfvars_file(local.defaults_file))
  overrides      = fileexists(local.overrides_file) ? jsondecode(read_tfvars_file(local.overrides_file)) : {}
  settings       = merge(local.defaults, local.overrides)

  # Only these VMs receive default_flavor; others retain their module flavor defaults.
  # Explicit *_flavor settings in terraform.tfvars override these assignments.
  small_flavor_vars = [
    "adminpc_flavor", "client_flavor", "corpdns_flavor", "docker_flavor",
    "inetdns_flavor", "inetfw_flavor", "mgmt_flavor", "videoserver_flavor",
    "wazuh_flavor", "webcam_flavor",
  ]

  flavor_defaults = {
    for name in local.small_flavor_vars : name => local.settings.default_flavor
  }

  # CLI selects latest, Packer-built or supplied Glance images in runs/<id>/images.json.
  # It passes the JSON path via ATTACKBED_IMAGES_FILE; Terraform receives image names.
  # The run's images.tfvars is an output artifact, not automatically loaded here.
  image_file    = get_env("ATTACKBED_IMAGES_FILE", "")
  image_choices = local.image_file == "" ? {} : jsondecode(file(local.image_file))

  selected_images = {
    for name, image in local.image_choices : name => image.name
  }

  # The CLI may override provider VLANs per run; otherwise use the tfvars setting.
  provider_vlans = get_env("ATTACKBED_USE_PROVIDER_VLANS", tostring(lookup(local.settings, "use_provider_vlans", true))) == "true"

  state_name = join("_", [
    get_env("OS_PROJECT_NAME"),
    get_env("OS_USER_DOMAIN_NAME"),
    get_env("OS_REGION_NAME", "default"),
    local.deployment_id,
    path_relative_to_include(),
  ])
  state_address = "${get_env("GITLAB_STATE_REPOSITORY")}/${local.state_name}"
}

download_dir = "${get_repo_root()}/.terragrunt-cache/${local.deployment_id}/${path_relative_to_include()}"

terraform {
  copy_terraform_lock_file = false
}

# Later maps override earlier ones. CLI image names win over both tfvars files;
# without a CLI selection, image values from tfvars are kept.
inputs = merge(
  local.flavor_defaults,
  local.settings,
  local.selected_images,
  {
    deployment_id     = local.deployment_id
    use_provider_vlans = local.provider_vlans
  }
)

remote_state {
  backend = "http"

  config = {
    address        = local.state_address
    lock_address   = "${local.state_address}/lock"
    unlock_address = "${local.state_address}/lock"
    username       = get_env("GITLAB_USERNAME")
    password       = get_env("CR_GITLAB_ACCESS_TOKEN")
    lock_method    = "POST"
    unlock_method  = "DELETE"
    retry_wait_min = "5"
  }
}
