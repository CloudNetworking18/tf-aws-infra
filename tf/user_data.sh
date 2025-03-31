#!/bin/bash
# Install dependencies globally (including statsd)
sudo python3 -m pip install flask gunicorn boto3 psycopg2-binary flask_sqlalchemy python-dotenv statsd

# Create logs directory for the application
sudo mkdir -p /opt/myapp/logs
sudo chown csye6225:csye6225 /opt/myapp/logs

# Create the .env file with dynamic values for the application
ENV_FILE="/opt/myapp/application/Health_check_api/.env"
cat <<EOF > "$ENV_FILE"
DATABASE_URL=postgresql://${DB_USERNAME}:${DB_PASSWORD}@${DB_ENDPOINT}:${DB_PORT}/${DB_NAME}
S3_BUCKET=${S3_BUCKET}
CUSTOM_DOMAIN=${CUSTOM_DOMAIN}
EOF

# Adjust ownership and permissions for the .env file
sudo chown csye6225:csye6225 "$ENV_FILE"
sudo chmod 644 "$ENV_FILE"

# Ensure the CloudWatch Agent configuration directory exists with proper permissions
sudo mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
sudo chown root:root /opt/aws/amazon-cloudwatch-agent/etc
sudo chmod 755 /opt/aws/amazon-cloudwatch-agent/etc

# Remove conflicting configuration files (if any)
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml*
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.yaml*
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/env-config.json
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/log-config.json

# Create a backup copy of the configuration file for reference
sudo tee /root/amazon-cloudwatch-agent.json.backup > /dev/null <<'EOF'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "root"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/myapp/logs/app.log",
            "log_group_name": "/aws/myapp/application-logs",
            "log_stream_name": "{instance_id}-app",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/myapp/logs/error.log",
            "log_group_name": "/aws/myapp/error-logs",
            "log_stream_name": "{instance_id}-error",
            "timezone": "UTC"
          }
        ]
      }
    }
  },
  "metrics": {
    "metrics_collected": {
      "statsd": {
        "service_address": ":8125",
        "metrics_collection_interval": 60,
        "metrics_aggregation_interval": 60
      }
    }
  },
  "outputs": {
    "cloudwatchlogs": {
      "force_flush_interval": "5s"
    }
  }
}
EOF

# Create the CloudWatch Agent JSON configuration file
sudo tee /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json > /dev/null <<'EOF'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "csye6225"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/opt/myapp/logs/app.log",
            "log_group_name": "/aws/myapp/application-logs",
            "log_stream_name": "{instance_id}-app",
            "timezone": "UTC"
          },
          {
            "file_path": "/opt/myapp/logs/error.log",
            "log_group_name": "/aws/myapp/error-logs",
            "log_stream_name": "{instance_id}-error",
            "timezone": "UTC"
          }
        ]
      }
    }
  },
  "metrics": {
    "metrics_collected": {
      "statsd": {
        "service_address": ":8125",
        "metrics_collection_interval": 60,
        "metrics_aggregation_interval": 60
      }
    }
  },
  "outputs": {
    "cloudwatchlogs": {
      "force_flush_interval": "5s"
    }
  }
}
EOF

# Set proper permissions for the configuration file
sudo chown -R root:csye6225 /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sudo chmod 644 /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json

# Clear any cached temporary configuration files
sudo rm -f /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.d/*

# Restart the CloudWatch Agent with the new configuration
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# Reload systemd and restart your application service
sudo systemctl daemon-reload
sudo systemctl restart myapp.service
