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
  default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

variable "availability_zones" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b", "us-east-1c"]
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
  default = "postgres17"
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
  default = "17"
}

variable "db_instance_class" {
  default = "db.t3.micro"
}

variable "db_username" {
  default = "csye6225"
}

variable "db_password" {
  default = "your-db-password"
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
  default = "ami-0e4113512eae9fbcb"
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

# DNS Variables
variable "domain_name" {
  description = "The primary domain name (e.g. cloud18.biz)"
  default     = "cloud18.biz"
}

variable "custom_domain" {
  description = "The custom domain used for email/SES (e.g. dev.cloud18.biz)"
  default     = "dev.cloud18.biz"
}

variable "dev_zone_id" {
  description = "The ID of the Route53 hosted zone for the dev subdomain"
  type        = string
}