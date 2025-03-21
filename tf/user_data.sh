#!/bin/bash
# Install dependencies and create the .env file with dynamic values
sudo python3 -m pip install flask gunicorn boto3 psycopg2-binary flask_sqlalchemy python-dotenv

ENV_FILE="/opt/myapp/application/Health_check_api/.env"

cat <<EOF > "$ENV_FILE"
DATABASE_URL=postgresql://${DB_USERNAME}:${DB_PASSWORD}@${DB_ENDPOINT}:${DB_PORT}/${DB_NAME}
S3_BUCKET=${S3_BUCKET}
EOF

sudo chown csye6225:csye6225 "$ENV_FILE"
sudo chmod 644 "$ENV_FILE"

sudo systemctl restart myapp.service
