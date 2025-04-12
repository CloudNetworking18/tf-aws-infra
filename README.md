# tf-aws-infra

# Infrastructure as Code with Terraform for AWS Cloud Deployment

This project implements a secure, scalable cloud infrastructure on AWS using Terraform. It includes a web application server, database, and all necessary security configurations including custom KMS keys for encryption.

## Architecture Overview

The infrastructure includes:

1. **Networking**: VPC with public and private subnets
2. **Compute**: EC2 instances managed by Auto Scaling Groups
3. **Database**: RDS MySQL instance
4. **Storage**: S3 bucket for application data
5. **Security**: Custom KMS keys for encryption, security groups, IAM roles
6. **Load Balancing**: Application Load Balancer with HTTPS support
7. **DNS**: Route53 for domain management

## Prerequisites

- AWS Account
- Terraform v1.0+ installed
- AWS CLI configured with appropriate permissions
- Certificate for HTTPS (imported into AWS Certificate Manager)

## Key Features

### Security

- **Custom KMS Keys**: Separate encryption keys for EC2, RDS, S3, and Secrets Manager
- **Key Rotation**: Enabled with 365-day rotation (requires manual adjustment to 90 days in AWS Console)
- **Encrypted Storage**: All data at rest is encrypted
- **Secrets Management**: Database credentials stored in AWS Secrets Manager
- **Network Segmentation**: Private subnets for database tier

### Scalability

- **Auto Scaling**: Dynamic adjustment of resources based on demand
- **Load Balancing**: Even distribution of traffic across instances
- **Multi-AZ Deployment**: Resources distributed across multiple availability zones for high availability

### Maintainability

- **Infrastructure as Code**: Complete AWS environment defined in Terraform
- **Parameterized Configuration**: Variables for environment-specific settings
- **Random Resource Names**: Prevents naming conflicts during deployment

## Usage

### Initialization

```bash
terraform init
```

### Deployment

```bash
terraform apply
```

### Destruction

```bash
terraform destroy
```

## Important Configuration Files

- **main.tf**: Main Terraform configuration
- **variables.tf**: Input variables
- **outputs.tf**: Output values
- **user_data.sh**: EC2 instance initialization script

## Custom KMS Key Configuration

The infrastructure uses four separate custom KMS keys:

1. **EC2 Key**: Encrypts EC2 instance EBS volumes
2. **RDS Key**: Encrypts the RDS database
3. **S3 Key**: Encrypts objects in the S3 bucket
4. **Secrets Key**: Encrypts secrets in AWS Secrets Manager

Each key is configured with appropriate permissions for the corresponding AWS service.

## SSL/TLS Certificate

For the demo environment, a certificate from a third-party provider (not AWS Certificate Manager) is imported and used with the Application Load Balancer. The command to import the certificate:

```bash
aws acm import-certificate \
  --certificate fileb://certificate.pem \
  --private-key fileb://privatekey.pem \
  --certificate-chain fileb://chain.pem
```

## DNS Configuration

The infrastructure sets up a Route53 record for the demo subdomain (demo.cloud18.biz) pointing to the Application Load Balancer.

## Post-Deployment Configuration

After deployment, manually configure KMS key rotation to 90 days:

1. Navigate to the AWS KMS console
2. Select each custom key
3. Under "Key rotation", change the rotation period to 90 days



## Security Considerations

- EC2 instances in public subnets are protected by security groups
- RDS instances in private subnets are only accessible from application servers
- All data at rest is encrypted with custom KMS keys
- All passwords are randomly generated and stored in Secrets Manager
- HTTPS is enforced for all client connections

##terraform workflow check

Terraform workflow check for Format and Validate