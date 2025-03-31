
# provider "aws" { 
#   region  = var.aws_region
#   profile = var.aws_profile
# }

# # Generate a unique suffix to avoid naming conflicts
# resource "random_string" "unique" {
#   length  = 8
#   special = false
#   upper   = false
# }


# resource "aws_vpc" "main" {
#   cidr_block           = var.vpc_cidr
#   enable_dns_support   = true
#   enable_dns_hostnames = true

#   tags = {
#     Name = var.vpc_name
#   }
# }

# resource "aws_subnet" "public" {
#   count                   = length(var.public_subnet_cidrs)
#   vpc_id                  = aws_vpc.main.id
#   cidr_block              = element(var.public_subnet_cidrs, count.index)
#   map_public_ip_on_launch = true
#   availability_zone       = element(var.availability_zones, count.index)

#   tags = {
#     Name = "public-subnet-${count.index + 1}"
#   }
# }

# resource "aws_subnet" "private" {
#   count             = length(var.private_subnet_cidrs)
#   vpc_id            = aws_vpc.main.id
#   cidr_block        = element(var.private_subnet_cidrs, count.index)
#   availability_zone = element(var.availability_zones, count.index)

#   tags = {
#     Name = "private-subnet-${count.index + 1}"
#   }
# }


# resource "aws_internet_gateway" "gw" {
#   vpc_id = aws_vpc.main.id

#   tags = {
#     Name = var.ig_name
#   }
# }

# resource "aws_route_table" "public" {
#   vpc_id = aws_vpc.main.id

#   tags = {
#     Name = var.public_route_table_name
#   }
# }

# resource "aws_route" "public" {
#   route_table_id         = aws_route_table.public.id
#   destination_cidr_block = var.internet_cidr
#   gateway_id             = aws_internet_gateway.gw.id
# }

# resource "aws_route_table_association" "public" {
#   count          = length(var.public_subnet_cidrs)
#   subnet_id      = aws_subnet.public[count.index].id
#   route_table_id = aws_route_table.public.id
# }

# resource "aws_route_table" "private" {
#   vpc_id = aws_vpc.main.id

#   tags = {
#     Name = var.private_route_table_name
#   }
# }

# resource "aws_route_table_association" "private" {
#   count          = length(var.private_subnet_cidrs)
#   subnet_id      = aws_subnet.private[count.index].id
#   route_table_id = aws_route_table.private.id
# }



# resource "aws_security_group" "app_sg" {
#   name        = var.app_sg_name
#   description = "Security group for the application server"
#   vpc_id      = aws_vpc.main.id

#   ingress {
#     from_port   = var.app_port
#     to_port     = var.app_port
#     protocol    = "tcp"
#     cidr_blocks = var.app_ingress_cidrs
#   }

#   ingress {
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = var.ssh_ingress_cidrs
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = var.app_egress_cidrs
#   }

#   tags = var.app_sg_tags
# }

# resource "aws_security_group" "db_sg" {
#   name        = var.db_sg_name
#   description = "Security group for the RDS instance"
#   vpc_id      = aws_vpc.main.id

#   ingress {
#     from_port       = var.db_port
#     to_port         = var.db_port
#     protocol        = "tcp"
#     security_groups = [aws_security_group.app_sg.id]
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = var.db_egress_cidrs
#   }

#   tags = var.db_sg_tags
# }



# resource "random_uuid" "s3_bucket_name" {}

# resource "aws_s3_bucket" "app_bucket" {
#   bucket        = "my-app-bucket-${random_uuid.s3_bucket_name.result}"
#   force_destroy = true

#   tags = var.s3_bucket_tags
# }

# resource "aws_s3_bucket_server_side_encryption_configuration" "app_bucket_encryption" {
#   bucket = aws_s3_bucket.app_bucket.id

#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = var.s3_encryption_algorithm
#     }
#   }
# }


# data "aws_iam_policy_document" "ec2_assume_role_doc" {
#   statement {
#     effect    = "Allow"
#     actions   = ["sts:AssumeRole"]
#     principals {
#       type        = "Service"
#       identifiers = [var.ec2_service_principal]
#     }
#   }
# }

# resource "aws_iam_role" "ec2_s3_role" {
#   name               = "${var.ec2_role_name}-${random_string.unique.result}"
#   assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_doc.json
# }

# resource "aws_iam_role_policy" "s3_access" {
#   name = var.ec2_role_policy_name
#   role = aws_iam_role.ec2_s3_role.id
#   policy = jsonencode({
#     Version   = "2012-10-17",
#     Statement = [
#       {
#         Effect = "Allow",
#         Action = [
#           "s3:GetObject",
#           "s3:PutObject",
#           "s3:DeleteObject"
#         ],
#         Resource = [
#           aws_s3_bucket.app_bucket.arn,
#           "${aws_s3_bucket.app_bucket.arn}/*"
#         ]
#       }
#     ]
#   })
# }

# resource "aws_iam_instance_profile" "ec2_s3_profile" {
#   name = "${var.ec2_instance_profile_name}-${random_string.unique.result}"
#   role = aws_iam_role.ec2_s3_role.name
# }


# resource "aws_instance" "app_server" {
#   ami                  = var.ami_id
#   instance_type        = var.instance_type
#   key_name             = var.key_name
#   subnet_id            = aws_subnet.public[0].id
#   security_groups      = [aws_security_group.app_sg.id]
#   iam_instance_profile = aws_iam_instance_profile.ec2_s3_profile.name

#   user_data = templatefile(var.user_data_template, {
#     DB_ENDPOINT = split(":", aws_db_instance.app_db.endpoint)[0],
#     DB_PORT     = split(":", aws_db_instance.app_db.endpoint)[1],
#     DB_USERNAME = var.db_username,
#     DB_PASSWORD = var.db_password,
#     DB_NAME     = var.db_name,
#     S3_BUCKET   = aws_s3_bucket.app_bucket.bucket
#   })

#   root_block_device {
#     volume_size           = var.app_root_volume_size
#     volume_type           = var.app_root_volume_type
#     delete_on_termination = true
#   }

#   tags = var.app_server_tags
# }



# resource "aws_db_subnet_group" "db_subnet_group" {
#   name       = "${var.db_subnet_group_name}-${random_string.unique.result}"
#   subnet_ids = aws_subnet.private[*].id

#   tags = var.db_subnet_group_tags
# }

# resource "aws_db_parameter_group" "app_db_params" {
#   name   = "${var.db_parameter_group_name}-${random_string.unique.result}"
#   family = var.db_parameter_family

#   parameter {
#     name         = "max_connections"
#     value        = var.db_max_connections
#     apply_method = "pending-reboot"
#   }

#   tags = var.db_parameter_group_tags
# }

# resource "aws_db_instance" "app_db" {
#   db_name             = var.db_name
#   identifier          = var.db_identifier
#   allocated_storage   = var.db_allocated_storage
#   engine              = var.db_engine
#   engine_version      = var.db_engine_version
#   instance_class      = var.db_instance_class
#   username            = var.db_username
#   password            = var.db_password
#   skip_final_snapshot = true
#   publicly_accessible = false
#   multi_az            = var.db_multi_az

#   db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
#   parameter_group_name   = aws_db_parameter_group.app_db_params.name
#   vpc_security_group_ids = [aws_security_group.db_sg.id]

#   storage_encrypted = true

#   tags = var.db_instance_tags
# }
#############################
# DNS & Domain Delegation
#############################


provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# Generate a unique suffix to avoid naming conflicts
resource "random_string" "unique" {
  length  = 8
  special = false
  upper   = false
}


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
# Primary hosted zone for your root domain (e.g., domain.tld)
resource "aws_route53_zone" "primary" {
  name = var.domain_name
}

# Create separate hosted zones for the sub-domains (dev and demo)
resource "aws_route53_zone" "dev" {
  name          = "dev.${var.domain_name}"
  comment       = "Hosted zone for development environment"
  force_destroy = true
}
# resource "aws_route53_zone" "demo" {
#   name    = "demo.${var.domain_name}"
#   comment = "Hosted zone for demo environment"
# }

# Delegate the dev sub-domain to its hosted zone
resource "aws_route53_record" "dev_delegation" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "dev.${var.domain_name}"
  type    = "NS"
  ttl     = 300
  records = aws_route53_zone.dev.name_servers
}

# Delegate the demo sub-domain to its hosted zone
# resource "aws_route53_record" "demo_delegation" {
#   zone_id = aws_route53_zone.primary.zone_id
#   name    = "demo.${var.domain_name}"
#   type    = "NS"
#   ttl     = 300
#   records = aws_route53_zone.demo.name_servers
# }

##############################
# Type A Record for EC2 Instance
##############################

# Ensure that when a new stack is created the A record for demo.domain.tld is updated with the EC2 public IP.
# resource "aws_route53_record" "demo_a_record" {
#   zone_id = aws_route53_zone.demo.zone_id
#   name    = var.demo_domain   # e.g. "demo.${var.domain_name}"
#   type    = "A"
#   ttl     = 300
#   records = [aws_instance.app_server.public_ip]
# }

##############################
# CloudWatch IAM for Agent
##############################

# Attach additional CloudWatch permissions to the existing EC2 role so that the CloudWatch Agent can:
# - Create log groups/streams,
# - Put log events, and
# - Publish custom metrics.
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

##############################
# CloudWatch Log Group for Application Logs
##############################

resource "aws_cloudwatch_log_group" "app_log_group" {
  name              = "/aws/myapp/application-logs"
  retention_in_days = 14
}
resource "aws_cloudwatch_log_group" "error_log_group" {
  name              = "/aws/myapp/error-logs"
  retention_in_days = 14
}


##############################
# Email Service Setup (SES)
##############################

# Verify that the email service is set up for the custom domain.
resource "aws_ses_domain_identity" "email_identity" {
  domain = var.custom_domain
}

resource "aws_ses_domain_dkim" "dkim" {
  domain = aws_ses_domain_identity.email_identity.domain
}

resource "aws_route53_record" "ses_dkim" {
  count   = 3
  zone_id = aws_route53_zone.primary.zone_id

  name    = "${aws_ses_domain_dkim.dkim.dkim_tokens[count.index]}._domainkey.${var.custom_domain}"
  type    = "CNAME"
  ttl     = 300
  records = ["${aws_ses_domain_dkim.dkim.dkim_tokens[count.index]}.dkim.amazonses.com"]
}


# Create an SPF record for your domain
resource "aws_route53_record" "ses_spf" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = var.custom_domain
  type    = "TXT"
  ttl     = 300
  records = ["v=spf1 include:amazonses.com -all"]
}

##############################
# (Optional) CloudWatch Metric Alarm
##############################

# Example alarm for API call count
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

# Example alarm for Database query duration
resource "aws_cloudwatch_metric_alarm" "db_query_duration_alarm" {
  alarm_name          = "HighDBQueryDuration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DBQueryDuration"
  namespace           = "MyApp/Database"
  period              = 60
  statistic           = "Average"
  threshold           = 200  # milliseconds (adjust as needed)
  alarm_description   = "Alarm when average database query duration exceeds 200ms in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

# Example alarm for S3 call duration
resource "aws_cloudwatch_metric_alarm" "s3_call_duration_alarm" {
  alarm_name          = "HighS3CallDuration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "S3CallDuration"
  namespace           = "MyApp/S3"
  period              = 60
  statistic           = "Average"
  threshold           = 300  # milliseconds (adjust as needed)
  alarm_description   = "Alarm when average S3 call duration exceeds 300ms in 1 minute"
  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}
