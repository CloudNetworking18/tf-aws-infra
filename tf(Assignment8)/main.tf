provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

resource "random_string" "unique" {
  length  = 8
  special = false
  upper   = false
}

##############################
# AWS KMS Keys for Encryption and Secrets
##############################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "ec2_key_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow EC2 Service"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow current user access"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "Allow User Management"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/demo-aws"]
    }
    actions = [
      "kms:EnableKeyRotation",
      "kms:ScheduleKeyDeletion",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "ec2_key" {
  description             = "KMS key for EC2 encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  policy                  = data.aws_iam_policy_document.ec2_key_policy.json
  is_enabled              = true

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "ec2-key"
  }
}

resource "aws_kms_alias" "ec2_key_alias" {
  name          = "alias/ec2-encryption-key-${random_string.unique.result}"
  target_key_id = aws_kms_key.ec2_key.key_id
}

data "aws_iam_policy_document" "rds_key_policy" {
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Give full access to the account that's running Terraform
  statement {
    sid    = "Allow current user access"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Specifically grant permissions to RDS service
  statement {
    sid    = "Allow RDS Service Access"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  # Allow creation of grants
  statement {
    sid    = "Allow grant creation"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["rds.${data.aws_region.current.name}.amazonaws.com"]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  policy                  = data.aws_iam_policy_document.rds_key_policy.json
  is_enabled              = true

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "rds-key"
  }
}

resource "aws_kms_alias" "rds_key_alias" {
  name          = "alias/rds-encryption-key-${random_string.unique.result}"
  target_key_id = aws_kms_key.rds_key.key_id
}

data "aws_iam_policy_document" "s3_key_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow S3 Service"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow current user access"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "Allow User Management"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/demo-aws"]
    }
    actions = [
      "kms:EnableKeyRotation",
      "kms:ScheduleKeyDeletion",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  policy                  = data.aws_iam_policy_document.s3_key_policy.json
  is_enabled              = true

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "s3-key"
  }
}

resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/s3-encryption-key-${random_string.unique.result}"
  target_key_id = aws_kms_key.s3_key.key_id
}

data "aws_iam_policy_document" "secrets_key_policy" {
  statement {
    sid       = "Enable IAM User Permissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "Allow Secrets Manager Service"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "Allow current user access"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "Allow User Management"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/demo-aws"]
    }
    actions = [
      "kms:EnableKeyRotation",
      "kms:ScheduleKeyDeletion",
      "kms:DescribeKey"
    ]
    resources = ["*"]
  }
}

resource "aws_kms_key" "secrets_key" {
  description             = "KMS key for Secrets Manager (DB password & Email credentials)"
  enable_key_rotation     = true
  deletion_window_in_days = 10
  policy                  = data.aws_iam_policy_document.secrets_key_policy.json
  is_enabled              = true

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "secrets-key"
  }
}

resource "aws_kms_alias" "secrets_key_alias" {
  name          = "alias/secrets-encryption-key-${random_string.unique.result}"
  target_key_id = aws_kms_key.secrets_key.key_id
}

##############################
# Generate Random Passwords
##############################

resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%^&*()-_=+[]{};:,.?" # Only allowed special characters; excludes '/', '@', '"' and space.
}

# resource "random_password" "email_password" {
#   length  = 16
#   special = true
# }

##############################
# Secrets Manager for Database Password
##############################

resource "aws_secretsmanager_secret" "db_secret" {
  name        = "db_password_secret-${random_uuid.s3_bucket_name.result}" # Use UUID for more uniqueness
  description = "Secret for RDS database password"
  kms_key_id  = aws_kms_key.secrets_key.arn

  depends_on = [
    aws_kms_key.secrets_key,
    aws_kms_alias.secrets_key_alias
  ]
}

resource "aws_secretsmanager_secret_version" "db_secret_version" {
  secret_id     = aws_secretsmanager_secret.db_secret.id
  secret_string = random_password.db_password.result
}

##############################
# Secrets Manager for Email Service Credentials
##############################
# resource "aws_secretsmanager_secret" "email_secret" {
#   name        = "email_service_credentials"
#   description = "Secret for Email Service credentials"
#   kms_key_id  = aws_kms_key.secrets_key.arn
# }
#
# resource "aws_secretsmanager_secret_version" "email_secret_version" {
#   secret_id     = aws_secretsmanager_secret.email_secret.id
#   secret_string = jsonencode({
#     username = var.email_username,
#     password = random_password.email_password.result
#   })
# }

##############################
# VPC, Subnets, IG, and Routes
##############################

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = element(var.public_subnet_cidrs, count.index)
  map_public_ip_on_launch = true
  availability_zone       = element(var.availability_zones, count.index)
  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = element(var.private_subnet_cidrs, count.index)
  availability_zone = element(var.availability_zones, count.index)
  tags = {
    Name = "private-subnet-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = var.ig_name
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = var.public_route_table_name
  }
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = var.internet_cidr
  gateway_id             = aws_internet_gateway.gw.id
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = var.private_route_table_name
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

##############################
# Security Groups for App and DB
##############################

resource "aws_security_group" "app_sg" {
  name        = var.app_sg_name
  description = "Security group for the application server"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = var.app_ingress_cidrs
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_ingress_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.app_egress_cidrs
  }
  tags = var.app_sg_tags
}

resource "aws_security_group" "db_sg" {
  name        = var.db_sg_name
  description = "Security group for the RDS instance"
  vpc_id      = aws_vpc.main.id
  ingress {
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.db_egress_cidrs
  }
  tags = var.db_sg_tags
}

##############################
# S3 Bucket and Encryption
##############################

resource "random_uuid" "s3_bucket_name" {}

resource "aws_s3_bucket" "app_bucket" {
  bucket        = "my-app-bucket-${random_uuid.s3_bucket_name.result}"
  force_destroy = true
  tags          = var.s3_bucket_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
  }

  depends_on = [
    aws_kms_key.s3_key,
    aws_kms_alias.s3_key_alias
  ]
}

##############################
# IAM Roles, Policies, and Instance Profile
##############################

data "aws_iam_policy_document" "ec2_assume_role_doc" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [var.ec2_service_principal]
    }
  }
}

resource "aws_iam_role" "ec2_s3_role" {
  name               = "${var.ec2_role_name}-${random_string.unique.result}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_doc.json
}

resource "aws_iam_role_policy" "s3_access" {
  name = var.ec2_role_policy_name
  role = aws_iam_role.ec2_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_s3_profile" {
  name = "${var.ec2_instance_profile_name}-${random_string.unique.result}"
  role = aws_iam_role.ec2_s3_role.name
}

##############################
# EC2 Instance for the Application Server
##############################

resource "aws_instance" "app_server" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  key_name             = var.key_name
  subnet_id            = aws_subnet.public[0].id
  security_groups      = [aws_security_group.app_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name

  user_data = templatefile(var.user_data_template, {
    DB_ENDPOINT   = split(":", aws_db_instance.app_db.endpoint)[0],
    DB_PORT       = split(":", aws_db_instance.app_db.endpoint)[1],
    DB_USERNAME   = var.db_username,
    DB_PASSWORD   = random_password.db_password.result,
    DB_SECRET_ARN = aws_secretsmanager_secret.db_secret.arn,
    DB_NAME       = var.db_name,
    S3_BUCKET     = aws_s3_bucket.app_bucket.bucket,
    CUSTOM_DOMAIN = var.custom_domain
  })

  root_block_device {
    volume_size           = var.app_root_volume_size
    volume_type           = var.app_root_volume_type
    delete_on_termination = true
    encrypted             = true
    kms_key_id            = aws_kms_key.ec2_key.arn
  }

  tags = var.app_server_tags

  depends_on = [
    aws_kms_key.ec2_key,
    aws_kms_alias.ec2_key_alias,
    aws_db_instance.app_db
  ]
}

##############################
# RDS Database Resources
##############################

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${var.db_subnet_group_name}-${random_string.unique.result}"
  subnet_ids = aws_subnet.private[*].id
  tags       = var.db_subnet_group_tags
}

resource "aws_db_parameter_group" "app_db_params" {
  name   = "${var.db_parameter_group_name}-${random_string.unique.result}"
  family = var.db_parameter_family

  parameter {
    name         = "max_connections"
    value        = var.db_max_connections
    apply_method = "pending-reboot"
  }

  tags = var.db_parameter_group_tags
}

resource "aws_db_instance" "app_db" {
  db_name             = var.db_name
  identifier          = "${var.db_identifier}-${random_string.unique.result}" # Add unique suffix
  allocated_storage   = var.db_allocated_storage
  engine              = var.db_engine
  engine_version      = var.db_engine_version
  instance_class      = var.db_instance_class
  username            = var.db_username
  password            = random_password.db_password.result
  skip_final_snapshot = true
  publicly_accessible = false
  multi_az            = var.db_multi_az

  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  parameter_group_name   = aws_db_parameter_group.app_db_params.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_key.arn

  tags = var.db_instance_tags

  # Make sure to wait for everything needed
  depends_on = [
    aws_db_subnet_group.db_subnet_group,
    aws_db_parameter_group.app_db_params,
    aws_kms_key.rds_key,
    aws_kms_alias.rds_key_alias
  ]

  # Add a lifecycle policy to handle recreation properly
  lifecycle {
    create_before_destroy = false
  }
}

##############################
# CloudWatch and SES Resources
##############################

resource "aws_iam_role_policy" "cloudwatch_agent_policy" {
  name = "cloudwatch-agent-policy-${random_string.unique.result}"
  role = aws_iam_role.ec2_s3_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "cloudwatch:PutMetricData"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "app_log_group" {
  name              = "/aws/myapp/application-logs"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "error_log_group" {
  name              = "/aws/myapp/error-logs"
  retention_in_days = 14
}

resource "aws_cloudwatch_metric_alarm" "api_call_count_alarm" {
  alarm_name          = "HighAPICallCount"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "APICallCount"
  namespace           = "MyApp/API"
  period              = 60
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Alarm when API call count exceeds 100 in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

resource "aws_cloudwatch_metric_alarm" "db_query_duration_alarm" {
  alarm_name          = "HighDBQueryDuration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DBQueryDuration"
  namespace           = "MyApp/Database"
  period              = 60
  statistic           = "Average"
  threshold           = 200
  alarm_description   = "Alarm when average database query duration exceeds 200ms in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_call_duration_alarm" {
  alarm_name          = "HighS3CallDuration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "S3CallDuration"
  namespace           = "MyApp/S3"
  period              = 60
  statistic           = "Average"
  threshold           = 300
  alarm_description   = "Alarm when average S3 call duration exceeds 300ms in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

###############################################
# Additional Resources for Load Balancer, Auto Scaling, and DNS Updates
###############################################

resource "aws_security_group" "lb_sg" {
  name        = "lb-sg-${random_string.unique.result}"
  description = "Security group for the load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lb-sg"
  }
}

resource "aws_security_group_rule" "app_ingress_from_lb" {
  type                     = "ingress"
  from_port                = var.app_port
  to_port                  = var.app_port
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app_sg.id
  source_security_group_id = aws_security_group.lb_sg.id
}

resource "aws_security_group_rule" "ssh_ingress_from_lb" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = aws_security_group.app_sg.id
  source_security_group_id = aws_security_group.lb_sg.id
}

resource "aws_lb" "app_lb" {
  name               = "app-lb-${random_string.unique.result}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = aws_subnet.public[*].id
  tags = {
    Name = "app-lb"
  }
}

resource "aws_lb_target_group" "app_tg" {
  name     = "app-tg-${random_string.unique.result}"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/healthz"
    matcher             = "200"
  }

  tags = {
    Name = "app-tg"
  }
}

resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

##############################
# Create HTTPS Listener for the Load Balancer with the SSL Certificate
##############################

resource "aws_lb_listener" "app_listener_https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = var.acm_certificate_arn # Certificate imported from Namecheap or another vendor
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

# Launch Template for Auto Scaling: uses the same configuration as the current EC2 instance.
resource "aws_launch_template" "app_lt" {
  name_prefix   = "csye6225_asg-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_s3_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }

  user_data = base64encode(templatefile(var.user_data_template, {
    DB_ENDPOINT   = split(":", aws_db_instance.app_db.endpoint)[0],
    DB_PORT       = split(":", aws_db_instance.app_db.endpoint)[1],
    DB_USERNAME   = var.db_username,
    DB_PASSWORD   = random_password.db_password.result,
    DB_SECRET_ARN = aws_secretsmanager_secret.db_secret.arn,
    DB_NAME       = var.db_name,
    S3_BUCKET     = aws_s3_bucket.app_bucket.bucket,
    CUSTOM_DOMAIN = var.custom_domain
  }))

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = var.app_root_volume_size
      volume_type           = var.app_root_volume_type
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_key.arn
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.app_server_tags, {
      AutoScalingGroup = "csye6225_asg"
    })
  }

  depends_on = [
    aws_kms_key.ec2_key,
    aws_kms_alias.ec2_key_alias
  ]
}

resource "aws_autoscaling_group" "app_asg" {
  name                      = "csye6225_asg"
  max_size                  = 5
  min_size                  = 3
  desired_capacity          = 3
  health_check_type         = "EC2"
  health_check_grace_period = 300
  vpc_zone_identifier       = aws_subnet.public[*].id
  target_group_arns         = [aws_lb_target_group.app_tg.arn]

  launch_template {
    id      = aws_launch_template.app_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "AutoScalingGroup"
    value               = "csye6225_asg"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale-up-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 60
}

resource "aws_cloudwatch_metric_alarm" "cpu_high_alarm" {
  alarm_name          = "cpu-high-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "MyApp/API"
  period              = 60
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Alarm when API call count exceeds 100 in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

resource "aws_cloudwatch_metric_alarm" "cpu_low_alarm" {
  alarm_name          = "cpu-low-alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 3
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

###############################################
# Updated Route53 Configuration using Data Sources
###############################################

# Look up existing hosted zones by ID.
# data "aws_route53_zone" "primary" {
#   zone_id = var.primary_zone_id
# }
#
# data "aws_route53_zone" "dev" {
#   zone_id = var.dev_zone_id
# }

data "aws_route53_zone" "demo" {
  zone_id = var.demo_zone_id
}

# # Create an alias record for the dev subdomain (dev.cloud18.biz)
# resource "aws_route53_record" "dev_alias" {
#   zone_id = data.aws_route53_zone.dev.zone_id
#   name    = ""  # Apex record for the dev zone (e.g., dev.cloud18.biz)
#   type    = "A"
#
#   alias {
#     name                   = aws_lb.app_lb.dns_name
#     zone_id                = aws_lb.app_lb.zone_id
#     evaluate_target_health = true
#   }
# }

# Create an alias record for the demo subdomain (demo.cloud18.biz)
resource "aws_route53_record" "demo_alias" {
  zone_id = data.aws_route53_zone.demo.zone_id
  name    = "" # Apex record for the demo zone (e.g., demo.cloud18.biz)
  type    = "A"
  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}