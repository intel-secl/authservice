#!/bin/bash

# READ .env file 
echo PWD IS $(pwd)
if [ -f ~/authservice.env ]; then 
    echo Reading Installation options from `realpath ~/authservice.env`
    source ~/authservice.env
elif [ -f ../authservice.env ]; then
    echo Reading Installation options from `realpath ../authservice.env`
    source ../authservice.env
else
    echo No .env file found
    AAS_NOSETUP="true"
fi

# Export all known variables
export AAS_DB_HOSTNAME
export AAS_DB_PORT
export AAS_DB_USERNAME
export AAS_DB_PASSWORD
export AAS_DB_NAME
export AAS_DB_SSLMODE
export AAS_DB_SSLCERT
export AAS_DB_SSLCERTSRC
export AAS_DB_REPORT_MAX_ROWS
export AAS_DB_REPORT_NUM_ROTATIONS

export AAS_PORT

export AAS_ADMIN_USERNAME
export AAS_ADMIN_PASSWORD

export AAS_REG_HOST_USERNAME
export AAS_REG_HOST_PASSWORD

export AAS_TLS_HOSTS

if [[ $EUID -ne 0 ]]; then 
    echo "This installer must be run as root"
    exit 1
fi

echo "Setting up Auth Service Linux User..."
id -u aas 2> /dev/null || useradd aas

echo "Installing Auth Service..."

COMPONENT_NAME=authservice
PRODUCT_HOME=/opt/$COMPONENT_NAME
BIN_PATH=$PRODUCT_HOME/bin
DB_SCRIPT_PATH=$PRODUCT_HOME/dbscripts
LOG_PATH=/var/log/$COMPONENT_NAME/
CONFIG_PATH=/etc/$COMPONENT_NAME/

mkdir -p $BIN_PATH && chown aas:aas $BIN_PATH/
cp $COMPONENT_NAME $BIN_PATH/ && chown aas:aas $BIN_PATH/*
chmod 750 $BIN_PATH/*
ln -sfT $BIN_PATH/$COMPONENT_NAME /usr/bin/$COMPONENT_NAME

mkdir -p $DB_SCRIPT_PATH && chown aas:aas $DB_SCRIPT_PATH/
cp db_rotation.sql $DB_SCRIPT_PATH/ && chown aas:aas $DB_SCRIPT_PATH/*

# Create configuration directory in /etc
mkdir -p $CONFIG_PATH && chown aas:aas $CONFIG_PATH
chmod 700 $CONFIG_PATH
chmod g+s $CONFIG_PATH

# Create logging dir in /var/log
mkdir -p $LOG_PATH && chown aas:aas $LOG_PATH
chmod 661 $LOG_PATH
chmod g+s $LOG_PATH

# Install systemd script
cp authservice.service $PRODUCT_HOME && chown aas:aas $PRODUCT_HOME/authservice.service && chown aas:aas $PRODUCT_HOME

# Enable systemd service
systemctl disable authservice.service > /dev/null 2>&1
systemctl enable $PRODUCT_HOME/authservice.service
systemctl daemon-reload

# check if AAS_NOSETUP is defined
if [ "${AAS_NOSETUP,,}" == "true" ]; then
    echo "AAS_NOSETUP is true, skipping setup"
    echo "Installation completed successfully!"
else 
    $COMPONENT_NAME setup all
    SETUPRESULT=$?
    if [ ${SETUPRESULT} == 0 ]; then 
        systemctl start $COMPONENT_NAME
        echo "Waiting for daemon to settle down before checking status"
        sleep 3
        systemctl status $COMPONENT_NAME 2>&1 > /dev/null
        if [ $? != 0 ]; then
            echo "Installation completed with Errors - $COMPONENT_NAME daemon not started."
            echo "Please check errors in syslog using \`journalctl -u $COMPONENT_NAME\`"
            exit 1
        fi
        echo "$COMPONENT_NAME daemon is running"
        echo "Installation completed successfully!"
    else 
        echo "Installation completed with errors"
    fi
fi
