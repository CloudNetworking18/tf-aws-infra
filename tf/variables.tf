# variable "aws_region" {
#   description = "AWS region"
#   default     = "us-east-1"
# }

# variable "aws_profile" {
#   description = "AWS CLI profile"
#   default     = "default"
# }

# variable "vpc_cidr" {
#   description = "CIDR block for the VPC"
#   default     = "10.0.0.0/16"
# }

# variable "vpc_name" {
#   description = "Name tag for the VPC"
#   default     = "my-vpc"
# }

# variable "public_subnet_cidrs" {
#   description = "List of CIDR blocks for public subnets"
#   type        = list(string)
#   default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
# }

# variable "private_subnet_cidrs" {
#   description = "List of CIDR blocks for private subnets"
#   type        = list(string)
#   default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
# }

# variable "availability_zones" {
#   description = "List of availability zones"
#   type        = list(string)
#   default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
# }

# variable "ig_name" {
#   description = "Internet Gateway name"
#   default     = "my-igw"
# }

# variable "public_route_table_name" {
#   description = "Name of the public route table"
#   default     = "public-rt"
# }

# variable "private_route_table_name" {
#   description = "Name of the private route table"
#   default     = "private-rt"
# }

# variable "internet_cidr" {
#   description = "CIDR for internet routes"
#   default     = "0.0.0.0/0"
# }

# variable "app_sg_name" {
#   description = "Security group name for the application server"
#   default     = "app-sg"
# }

# variable "app_port" {
#   description = "Port on which the application listens"
#   default     = 5000
# }

# variable "app_ingress_cidrs" {
#   description = "Ingress CIDRs for the application security group"
#   type        = list(string)
#   default     = ["0.0.0.0/0"]
# }

# variable "ssh_ingress_cidrs" {
#   description = "SSH ingress CIDRs"
#   type        = list(string)
#   default     = ["0.0.0.0/0"]
# }

# variable "app_egress_cidrs" {
#   description = "Egress CIDRs for the application security group"
#   type        = list(string)
#   default     = ["0.0.0.0/0"]
# }

# variable "app_sg_tags" {
#   description = "Tags for the application security group"
#   type        = map(string)
#   default     = {
#     Environment = "dev"
#     Name        = "app-sg"
#   }
# }

# variable "db_sg_name" {
#   description = "Security group name for the DB/RDS instance"
#   default     = "db-sg"
# }

# variable "db_port" {
#   description = "Database port"
#   default     = 5432
# }

# variable "db_egress_cidrs" {
#   description = "Egress CIDRs for the DB security group"
#   type        = list(string)
#   default     = ["0.0.0.0/0"]
# }

# variable "db_sg_tags" {
#   description = "Tags for the DB security group"
#   type        = map(string)
#   default     = {
#     Environment = "dev"
#     Name        = "db-sg"
#   }
# }

# variable "s3_encryption_algorithm" {
#   description = "S3 encryption algorithm"
#   default     = "AES256"
# }

# variable "s3_bucket_tags" {
#   description = "Tags for the S3 bucket"
#   type        = map(string)
#   default     = {
#     Environment = "dev"
#     Name        = "app-bucket"
#   }
# }

# variable "ec2_service_principal" {
#   description = "IAM service principal for EC2"
#   default     = "ec2.amazonaws.com"
# }

# variable "ec2_role_name" {
#   description = "Name of the IAM role for EC2"
#   default     = "ec2_s3_role"
# }

# variable "ec2_role_policy_name" {
#   description = "Name of the IAM role policy for EC2"
#   default     = "ec2-s3-access"
# }

# variable "ec2_instance_profile_name" {
#   description = "Name of the IAM instance profile for EC2"
#   default     = "ec2-s3-instance-profile"
# }

# variable "db_subnet_group_name" {
#   description = "Name of the RDS DB subnet group"
#   default     = "db-subnet-group"
# }

# variable "db_subnet_group_tags" {
#   description = "Tags for the DB subnet group"
#   type        = map(string)
#   default     = {
#     Environment = "demo"
#     Name        = "db-subnet-group"
#   }
# }

# variable "db_parameter_group_name" {
#   description = "Name of the DB parameter group"
#   default     = "csye6225-param-group"
# }

# variable "db_parameter_family" {
#   description = "DB parameter group family"
#   default     = "postgres17"  # Adjust based on your engine and version
# }

# variable "db_max_connections" {
#   description = "Maximum number of DB connections"
#   default     = "100"
# }

# variable "db_parameter_group_tags" {
#   description = "Tags for the DB parameter group"
#   type        = map(string)
#   default     = {
#     Environment = "demo"
#     Name        = "db-param-group"
#   }
# }

# variable "db_name" {
#   description = "Database name"
#   default     = "csye6225"
# }

# variable "db_identifier" {
#   description = "DB instance identifier"
#   default     = "csye6225-db"
# }

# variable "db_allocated_storage" {
#   description = "Allocated storage for the DB instance (in GB)"
#   default     = 20
# }

# variable "db_engine" {
#   description = "Database engine"
#   default     = "postgres"
# }

# variable "db_engine_version" {
#   description = "Database engine version"
#   default     = "12.7"  # Adjust as needed
# }

# variable "db_instance_class" {
#   description = "DB instance class"
#   default     = "db.t3.micro"
# }

# variable "db_username" {
#   description = "Master username for the DB"
#   default     = "csye6225"
# }

# variable "db_password" {
#   description = "Master password for the DB"
#   default     = "your-db-password"  # Change this to a strong password
# }

# variable "db_multi_az" {
#   description = "Multi-AZ deployment for the DB instance"
#   default     = false
# }

# variable "db_instance_tags" {
#   description = "Tags for the DB instance"
#   type        = map(string)
#   default     = {
#     Environment = "demo"
#     Name        = "csye6225-db"
#   }
# }

# variable "ami_id" {
#   description = "AMI ID for the EC2 instance"
#   default     = ""  # Update as needed
# }

# variable "instance_type" {
#   description = "Instance type for the EC2 instance"
#   default     = "t2.micro"
# }

# variable "key_name" {
#   description = "Key pair name for the EC2 instance"
#   default     = "your-keypair"
# }

# variable "user_data_template" {
#   description = "Path to the user data script"
#   default     = "user_data.sh"
# }

# variable "app_root_volume_size" {
#   description = "Root volume size for the EC2 instance (in GB)"
#   default     = 25
# }

# variable "app_root_volume_type" {
#   description = "Root volume type for the EC2 instance"
#   default     = "gp2"
# }

# variable "app_server_tags" {
#   description = "Tags for the EC2 instance"
#   type        = map(string)
#   default     = {
#     Environment = "dev"
#     Name        = "app-server"
#   }
# }

# variable "s3_actions" {
#   description = "List of allowed S3 actions"
#   type        = list(string)
#   default     = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
# }

variable "aws_region" {
  default = "us-east-1"
}

variable "aws_profile" {
  default = "default"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "vpc_name" {
  default = "my-vpc"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.101.0/24", "10.0.102.0/24"]
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}

variable "ig_name" {
  default = "my-igw"
}

variable "public_route_table_name" {
  default = "public-rt"
}

variable "private_route_table_name" {
  default = "private-rt"
}

variable "app_sg_name" {
  default = "app-sg"
}

variable "app_ingress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "ssh_ingress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "app_egress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "app_sg_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "app-sg"
  }
}

variable "db_sg_name" {
  default = "db-sg"
}

variable "db_port" {
  default = 5432
}

variable "db_egress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "db_sg_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "db-sg"
  }
}

variable "s3_encryption_algorithm" {
  default = "AES256"
}

variable "s3_bucket_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "app-bucket"
  }
}

variable "ec2_service_principal" {
  default = "ec2.amazonaws.com"
}

variable "ec2_role_name" {
  default = "ec2_s3_role"
}

variable "ec2_role_policy_name" {
  default = "ec2-s3-access"
}

variable "ec2_instance_profile_name" {
  default = "ec2-s3-instance-profile"
}

variable "db_subnet_group_name" {
  default = "db-subnet-group"
}

variable "db_subnet_group_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "db-subnet-group"
  }
}

variable "db_parameter_group_name" {
  default = "csye6225-param-group"
}

variable "db_parameter_family" {
  default = "postgres17" # Adjust based on your engine and version
}

variable "db_max_connections" {
  default = "100"
}

variable "db_parameter_group_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "db-param-group"
  }
}

variable "db_name" {
  default = "csye6225"
}

variable "db_identifier" {
  default = "csye6225-db"
}

variable "db_allocated_storage" {
  default = 20
}

variable "db_engine" {
  default = "postgres"
}

variable "db_engine_version" {
  default = "12.7" # Adjust as needed
}

variable "db_instance_class" {
  default = "db.t3.micro"
}

variable "db_username" {
  default = "csye6225"
}

variable "db_password" {
  default = "your-db-password" # Change to a strong password
}

variable "db_multi_az" {
  default = false
}

variable "db_instance_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "csye6225-db"
  }
}

variable "ami_id" {
  default = "ami-0f9de6e2d2f067fca" # Update as needed
}

variable "instance_type" {
  default = "t2.micro"
}

variable "key_name" {
  default = "your-keypair"
}

variable "user_data_template" {
  default = "user_data.sh"
}

variable "app_root_volume_size" {
  default = 25
}

variable "app_root_volume_type" {
  default = "gp2"
}

variable "app_server_tags" {
  type = map(string)
  default = {
    Environment = "dev"
    Name        = "app-server"
  }
}

variable "internet_cidr" {
  description = "CIDR block for internet routes"
  default     = "0.0.0.0/0"
}

variable "app_port" {
  description = "Port on which the application listens"
  default     = 5000
}

variable "s3_actions" {
  description = "List of allowed S3 actions"
  type        = list(string)
  default     = ["s3:ListBucket", "s3:GetObject", "s3:PutObject"]
}

# New variables for additional code

variable "domain_name" {
  description = "The primary domain name (e.g. cloud18.biz)"
  default     = "cloud18.biz"
}

# variable "demo_domain" {
#   description = "The demo subdomain (e.g. demo.cloud18.biz)"
#   default     = "demo.cloud18.biz"
# }

variable "custom_domain" {
  description = "The custom domain used for email/SES (e.g. dev.cloud18.biz)"
  default     = "dev.cloud18.biz"
}

