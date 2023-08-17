# PolkaDot validator
MVP for polkadot project


## Requirements:
- Create a repository on GitLab or GitHub for version control and collaboration.
- Use Terraform to create IAC files for provisioning two instances on your preferred provider (for example on AWS). You can find the requirements of a Polkadot node here: https://wiki.polkadot.network/docs/maintain-guides-how-to-validate-polkadot#reference-hardware
- Write an Ansible playbook to automate the deployment of the Polkadot binary v0.9.39-1 to the two instances. You can find information on it here: https://wiki.polkadot.network/docs/maintain-guides-how-to-validate-polkadot#installing-the-polkadot-binary
- Configure the playbook to create and manage a systemd service file that will run the Polkadot Fullnode.
- Write a brief description explaining how you would update the Polkadot nodes to v0.9.41 using your playbook


## Pre-req

Please adjust backend based on your own configuration.
```terraform
terraform {
  backend "s3" {
    bucket       = "poc-bucket"
    key          = "mvp-test"
    region       = "eu-west-1"
    session_name = "dot-poc"
    profile       = "poc-profile"
  }
}
```


### Teraform run
0. Navigate into terraform/configuration/polkadot
1. Run terraform init for getting all needed plugins and module.
2. Command to run:

```shell
TF_WORKSPACE=dev tfa --var-file=env/dev.tfvars
```


Output:
```terraform

  # data.template_file.vpc_flowlogs will be read during apply
  # (config refers to values not yet known)
 <= data "template_file" "vpc_flowlogs" {
      + id       = (known after apply)
      + rendered = (known after apply)
      + template = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "logs:CreateLogGroup",
                          + "logs:CreateLogStream",
                          + "logs:PutLogEvents",
                          + "logs:DescribeLogGroups",
                          + "logs:DescribeLogStreams",
                        ]
                      + Effect   = "Allow"
                      + Resource = "arn:aws:logs:${region}:${account_id}:log-group:${env_id}-vpc-flow-logs*:*"
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + vars     = {
          + "account_id" = "12345678900"
          + "env_id"     = "dev"
          + "region"     = "eu-west-1"
          + "vpc_id"     = (known after apply)
        }
    }

  # aws_cloudwatch_log_group.vpc_flowlogs will be created
  + resource "aws_cloudwatch_log_group" "vpc_flowlogs" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + name              = "dev-vpc-flow-logs-log-group"
      + retention_in_days = 0
      + tags_all          = (known after apply)
    }

  # aws_iam_instance_profile.bastion_profile will be created
  + resource "aws_iam_instance_profile" "bastion_profile" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "bastion-machine-profile_poc"
      + path        = "/"
      + role        = "bastion-machine-role-poc"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_instance_profile.target_profile will be created
  + resource "aws_iam_instance_profile" "target_profile" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "target-instance-poc"
      + path        = "/"
      + role        = "target-ec2-role"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_policy.policy will be created
  + resource "aws_iam_policy" "policy" {
      + arn         = (known after apply)
      + description = "Policy to access secrets manager"
      + id          = (known after apply)
      + name        = "secrets_manager_access_poc"
      + path        = "/"
      + policy      = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = [
                          + "secretsmanager:GetResourcePolicy",
                          + "secretsmanager:GetSecretValue",
                          + "secretsmanager:DescribeSecret",
                          + "secretsmanager:ListSecretVersionIds",
                          + "secretsmanager:GetSecretValue",
                        ]
                      + Effect   = "Allow"
                      + Resource = [
                          + "arn:aws:secretsmanager:eu-west-1:12345678900:secret:keys",
                        ]
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_policy.vpc_flowlogs will be created
  + resource "aws_iam_policy" "vpc_flowlogs" {
      + arn       = (known after apply)
      + id        = (known after apply)
      + name      = "dev-cloudwatch-flowlogs"
      + path      = "/"
      + policy    = (known after apply)
      + policy_id = (known after apply)
      + tags_all  = (known after apply)
    }

  # aws_iam_policy_attachment.vpc_flowlogs will be created
  + resource "aws_iam_policy_attachment" "vpc_flowlogs" {
      + id         = (known after apply)
      + name       = "iam-role-attachment-dev-cw-flowlogs"
      + policy_arn = (known after apply)
      + roles      = [
          + "dev-cloudwatch-flowlogs",
        ]
    }

  # aws_iam_role.bastion_role will be created
  + resource "aws_iam_role" "bastion_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "bastion-machine-role-poc"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role.target_ec2_role will be created
  + resource "aws_iam_role" "target_ec2_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "target-ec2-role"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role.vpc_flowlogs will be created
  + resource "aws_iam_role" "vpc_flowlogs" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "vpc-flow-logs.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "dev-cloudwatch-flowlogs"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy_attachment.attachment will be created
  + resource "aws_iam_role_policy_attachment" "attachment" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "bastion-machine-role-poc"
    }

  # aws_iam_role_policy_attachment.target_attachment will be created
  + resource "aws_iam_role_policy_attachment" "target_attachment" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = "target-ec2-role"
    }

  # aws_instance.bastion will be created
  + resource "aws_instance" "bastion" {
      + ami                                  = "ami-02055fd83fff2f267"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = (known after apply)
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_termination              = false
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + iam_instance_profile                 = "bastion-machine-profile_poc"
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.micro"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "12345678900-eu-west-1-dev"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tenancy                              = (known after apply)
      + user_data                            = "55a28be5c323795b46f0182d1b8fb734f90f6721"
      + user_data_base64                     = (known after apply)
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
          + instance_metadata_tags      = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_instance.target[0] will be created
  + resource "aws_instance" "target" {
      + ami                                  = "ami-0f29c8402f8cce65c"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = false
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_termination              = false
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + iam_instance_profile                 = "target-instance-poc"
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.micro"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "12345678900-eu-west-1-dev"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tenancy                              = (known after apply)
      + user_data                            = "c10d638f3e25474b4f388a6f152eccc8f71fd726"
      + user_data_base64                     = (known after apply)
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
          + instance_metadata_tags      = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = true
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = 64
          + volume_type           = "gp2"
        }
    }

  # aws_instance.target[1] will be created
  + resource "aws_instance" "target" {
      + ami                                  = "ami-0f29c8402f8cce65c"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = false
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_termination              = false
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + iam_instance_profile                 = "target-instance-poc"
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.micro"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "12345678900-eu-west-1-dev"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tenancy                              = (known after apply)
      + user_data                            = "c10d638f3e25474b4f388a6f152eccc8f71fd726"
      + user_data_base64                     = (known after apply)
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
          + instance_metadata_tags      = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = true
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = 64
          + volume_type           = "gp2"
        }
    }

  # aws_key_pair.generated_key will be created
  + resource "aws_key_pair" "generated_key" {
      + arn             = (known after apply)
      + fingerprint     = (known after apply)
      + id              = (known after apply)
      + key_name        = "12345678900-eu-west-1-dev"
      + key_name_prefix = (known after apply)
      + key_pair_id     = (known after apply)
      + public_key      = (known after apply)
      + tags_all        = (known after apply)
    }

  # aws_route53_record.servers_ssh[0] will be created
  + resource "aws_route53_record" "servers_ssh" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "dev-poc-1"
      + records         = (known after apply)
      + ttl             = 3600
      + type            = "A"
      + zone_id         = (known after apply)
    }

  # aws_route53_record.servers_ssh[1] will be created
  + resource "aws_route53_record" "servers_ssh" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "dev-poc-2"
      + records         = (known after apply)
      + ttl             = 3600
      + type            = "A"
      + zone_id         = (known after apply)
    }

  # aws_route53_zone.private_zone will be created
  + resource "aws_route53_zone" "private_zone" {
      + arn           = (known after apply)
      + comment       = "Managed by Terraform"
      + force_destroy = false
      + id            = (known after apply)
      + name          = "poc.cloud"
      + name_servers  = (known after apply)
      + tags          = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all      = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + zone_id       = (known after apply)

      + vpc {
          + vpc_id     = (known after apply)
          + vpc_region = (known after apply)
        }
    }

  # aws_secretsmanager_secret.bastion_secret_key will be created
  + resource "aws_secretsmanager_secret" "bastion_secret_key" {
      + arn                            = (known after apply)
      + description                    = "PrivateKey to enter Environment: dev for 12345678900 account number, within region:eu-west-1"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = "/bastion/dev-private-key"
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags                           = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                       = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret_version.bastion_secret_key_version will be created
  + resource "aws_secretsmanager_secret_version" "bastion_secret_key_version" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_security_group.sg_bastion will be created
  + resource "aws_security_group" "sg_bastion" {
      + arn                    = (known after apply)
      + description            = "This SG will be responsible for Bastion network on instance level"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "bastion-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all               = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.sg_target will be created
  + resource "aws_security_group" "sg_target" {
      + arn                    = (known after apply)
      + description            = "Allow Target inbound traffic"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "10.0.0.0/16",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
        ]
      + name                   = "allow_sg_target"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # local_file.pem_file will be created
  + resource "local_file" "pem_file" {
      + content_base64sha256 = (known after apply)
      + content_base64sha512 = (known after apply)
      + content_md5          = (known after apply)
      + content_sha1         = (known after apply)
      + content_sha256       = (known after apply)
      + content_sha512       = (known after apply)
      + directory_permission = "0777"
      + file_permission      = "600"
      + filename             = "/Users/eugeniugoncearuc/.ssh/12345678900-eu-west-1-dev.pem"
      + id                   = (known after apply)
      + sensitive_content    = (sensitive value)
    }

  # tls_private_key.ssh-generator will be created
  + resource "tls_private_key" "ssh-generator" {
      + algorithm                     = "RSA"
      + ecdsa_curve                   = "P224"
      + id                            = (known after apply)
      + private_key_openssh           = (sensitive value)
      + private_key_pem               = (sensitive value)
      + private_key_pem_pkcs8         = (sensitive value)
      + public_key_fingerprint_md5    = (known after apply)
      + public_key_fingerprint_sha256 = (known after apply)
      + public_key_openssh            = (known after apply)
      + public_key_pem                = (known after apply)
      + rsa_bits                      = 4096
    }

  # module.vpc.aws_default_security_group.this[0] will be created
  + resource "aws_default_security_group" "this" {
      + arn                    = (known after apply)
      + description            = (known after apply)
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all               = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                 = (known after apply)
    }

  # module.vpc.aws_eip.nat[0] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc                  = true
    }

  # module.vpc.aws_eip.nat[1] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc                  = true
    }

  # module.vpc.aws_eip.nat[2] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc                  = true
    }

  # module.vpc.aws_flow_log.this[0] will be created
  + resource "aws_flow_log" "this" {
      + arn                      = (known after apply)
      + iam_role_arn             = (known after apply)
      + id                       = (known after apply)
      + log_destination          = (known after apply)
      + log_destination_type     = "cloud-watch-logs"
      + log_format               = (known after apply)
      + log_group_name           = (known after apply)
      + max_aggregation_interval = 600
      + tags                     = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "dev-vpc-flow-logs"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "dev-vpc-flow-logs"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + traffic_type             = "ALL"
      + vpc_id                   = (known after apply)
    }

  # module.vpc.aws_internet_gateway.this[0] will be created
  + resource "aws_internet_gateway" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id   = (known after apply)
    }

  # module.vpc.aws_nat_gateway.this[0] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
    }

  # module.vpc.aws_nat_gateway.this[1] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
    }

  # module.vpc.aws_nat_gateway.this[2] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[0] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[1] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.private_nat_gateway[2] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route.public_internet_gateway[0] will be created
  + resource "aws_route" "public_internet_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + gateway_id             = (known after apply)
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.vpc.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all         = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.private[1] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all         = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.private[2] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all         = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table.public[0] will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all         = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id           = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.private[2] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_route_table_association.public[2] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.vpc.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "AZ"          = "eu-west-1a"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "AZ"          = "eu-west-1a"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "AZ"          = "eu-west-1b"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "AZ"          = "eu-west-1b"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.private[2] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "AZ"          = "eu-west-1c"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "AZ"          = "eu-west-1c"
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.101.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.102.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_subnet.public[2] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-west-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.103.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                                       = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.vpc.aws_vpc.this[0] will be created
  + resource "aws_vpc" "this" {
      + arn                                  = (known after apply)
      + assign_generated_ipv6_cidr_block     = false
      + cidr_block                           = "10.0.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_classiclink                   = (known after apply)
      + enable_classiclink_dns_support       = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
      + tags_all                             = {
          + "Application" = "MVP"
          + "Environment" = "dev"
          + "Name"        = "poc"
          + "Scope"       = "test"
          + "TagVersion"  = "1"
        }
    }

Plan: 54 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + bastion_public_ip = (known after apply)

Do you want to perform these actions in workspace "dev"?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.


```


Once the infrastructure has been created, we will login into the bastion via the provided IP:
```shell
Outputs after run:
bastion_public_ip = "34.243.242.45"
```

2. Login via bash:
```shell
 ssh ec2-user@34.243.242.45 -i ~/.ssh/12345678900-eu-west-1-dev.pem
The authenticity of host '34.243.242.45 (34.243.242.45)' can't be established.
ED25519 key fingerprint is SHA256:rK0u9wwvnWSPiRn61Pgk6W0l7GbKS8BryXlCfbe9JS4.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:510: 52.212.248.250
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '34.243.242.45' (ED25519) to the list of known hosts.
Last login: Thu Aug 17 07:30:45 2023 from 188.25.175.53

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-2/
[ec2-user@ip-10-0-101-35 ~]$ 
```

3. We can check now if we have connection to the servers from bastion:
```shell
[ec2-user@ip-10-0-101-35 ~]$ ssh dev-poc-1.poc.cloud -i ~/.ssh/12345678900-eu-west-1-dev.pem

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-2/
[ec2-user@ip-10-0-1-78 ~]$ 

```
3. Clone project locally and navigate into ansible directory.

4. Connection is in place, we can now test connection via ansible classic way (ping):
```shell
[ec2-user@ip-10-0-101-35 ansible]$ ansible  all -m ping -i inventory/dev-env.yaml -e -e ansible_ssh_private_key_file=~/.ssh/ACCOUNT-eu-west-1-dev.pem 
https://docs.ansible.com/ansible-core/2.11/reference_appendices/interpreter_discovery.html for more information.

dev-poc-1.poc.cloud | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": false,
    "ping": "pong"
}

dev-poc-2.poc.cloud | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python"
    },
    "changed": false,
    "ping": "pong"
}
```

5. Connection is in place, we can deploy now Polkadot code.

Terraform will create:
1. VPC: 
2. Bastion deployed in public subnet for connection from outside.
3. Route53 Private zone: Will have a mapping between servers and domain itself for easy ansible deployment
4. Secrets Manager: Place where team/you can find the private key and login to the server. 

## Ansible Deployments
1. Command to run for default version (`v0.9.39-1`)
```shell
ansible-playbook -i inventory/dev-env.yaml deploy.yaml
```

2. If we would like to upgrade to newer version ( `v0.9.41` ),we update value of `dot_version` in DEV environment (group_vars/dev/main.yaml)
3. This variable `dot_version` usually it's externalised into a wrapper such as Jenkins/Github/CodeBuild and so on and we would have on the fly all variables directly in UI (it depends on the infra scope we have in mind).
4. In the end, validator will be deployed and running via systemd service with desired version in place.



## Conclusion :
In the end we could perform deployment even via Terraform with user data, and we change the variable for node version. 
Depends always what is the scope.
