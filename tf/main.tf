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

  tags = var.s3_bucket_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.s3_encryption_algorithm
    }
  }
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
    DB_PASSWORD   = var.db_password,
    DB_NAME       = var.db_name,
    S3_BUCKET     = aws_s3_bucket.app_bucket.bucket,
    CUSTOM_DOMAIN = var.custom_domain
  })

  root_block_device {
    volume_size           = var.app_root_volume_size
    volume_type           = var.app_root_volume_type
    delete_on_termination = true
  }

  tags = var.app_server_tags
}

##############################
# RDS Database Resources
##############################

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${var.db_subnet_group_name}-${random_string.unique.result}"
  subnet_ids = aws_subnet.private[*].id

  tags = var.db_subnet_group_tags
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
  identifier          = var.db_identifier
  allocated_storage   = var.db_allocated_storage
  engine              = var.db_engine
  engine_version      = var.db_engine_version
  instance_class      = var.db_instance_class
  username            = var.db_username
  password            = var.db_password
  skip_final_snapshot = true
  publicly_accessible = false
  multi_az            = var.db_multi_az

  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  parameter_group_name   = aws_db_parameter_group.app_db_params.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  storage_encrypted = true

  tags = var.db_instance_tags
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

# resource "aws_ses_domain_identity" "email_identity" {
#   domain = var.custom_domain
# }

# resource "aws_ses_domain_dkim" "dkim" {
#   domain = aws_ses_domain_identity.email_identity.domain
# }

# resource "aws_route53_record" "ses_dkim" {
#   count   = 3
#   zone_id = data.aws_route53_zone.primary.zone_id
#   name    = "${aws_ses_domain_dkim.dkim.dkim_tokens[count.index]}._domainkey.${var.custom_domain}"
#   type    = "CNAME"
#   ttl     = 300
#   records = ["${aws_ses_domain_dkim.dkim.dkim_tokens[count.index]}.dkim.amazonses.com"]
# }

# resource "aws_route53_record" "ses_spf" {
#   zone_id = data.aws_route53_zone.primary.zone_id
#   name    = var.custom_domain
#   type    = "TXT"
#   ttl     = 300
#   records = ["v=spf1 include:amazonses.com -all"]
# }

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

# Load Balancer Security Group: allows HTTP (80) and HTTPS (443) from anywhere.
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

# Update App Security Group so that the EC2 instances only allow application and SSH traffic from the LB.
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

# Application Load Balancer (ALB)
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

# Target Group for the ALB: forwards traffic to your web application on var.app_port.
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

# Listener for the ALB: listens on HTTP port 80 and forwards requests to the target group.
resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "80"
  protocol          = "HTTP"

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
    DB_PASSWORD   = var.db_password,
    DB_NAME       = var.db_name,
    S3_BUCKET     = aws_s3_bucket.app_bucket.bucket,
    CUSTOM_DOMAIN = var.custom_domain
  }))

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.app_server_tags, {
      AutoScalingGroup = "csye6225_asg"
    })
  }
}

# Auto Scaling Group for Application Instances
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

# Auto Scaling Policies
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

# CloudWatch Metric Alarms to trigger the scaling policies.
resource "aws_cloudwatch_metric_alarm" "cpu_high_alarm" {
  alarm_name          = "cpu-high-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 5

  alarm_actions = [aws_autoscaling_policy.scale_up.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
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

  alarm_actions = [aws_autoscaling_policy.scale_down.arn]
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

# data "aws_route53_zone" "dev" {
#   zone_id = var.dev_zone_id
# }

data "aws_route53_zone" "demo" {
  zone_id = var.demo_zone_id
}

# # Create an alias record for the dev subdomain (dev.cloud18.biz)
# resource "aws_route53_record" "dev_alias" {
#   zone_id = data.aws_route53_zone.dev.zone_id
#   name    = "" # Apex record for the dev zone (e.g., dev.cloud18.biz)
#   type    = "A"

#   alias {
#     name                   = aws_lb.app_lb.dns_name
#     zone_id                = aws_lb.app_lb.zone_id
#     evaluate_target_health = true
#   }
# }

# Create an alias record for the demo subdomain (demo.cloud18.biz)
resource "aws_route53_record" "demo_alias" {
  zone_id = data.aws_route53_zone.demo.zone_id
  name    = ""  # Apex record for the demo zone (e.g., demo.cloud18.biz)
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}
