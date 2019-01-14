#!/bin/bash
# Please run this file with root privilege and collect  the files in  /tmp/pciScript
mkdir /tmp/pciScript
cd /tmp/pciScript

FILENAME=`hostname`.txt
if (test -e ${FILENAME}) then
	mv ${FILENAME} ${FILENAME}.old
fi

echo "-----START ${HOSTNAME}-----" > $FILENAME
echo "DATE: `date`" >> $FILENAME

echo "UNAME: `uname -a`" >> $FILENAME
echo "---------------------------" >> $FILENAME

echo "-----START /etc/passwd-----" >> $FILENAME
cat /etc/passwd >> $FILENAME
echo "-----END /etc/passwd-----" >> $FILENAME

echo "-----START /etc/ssh/sshd_config-----" >> $FILENAME
cat /etc/ssh/sshd_config >> $FILENAME
echo "-----END /etc/ssh/sshd_config-----" >> $FILENAME

# echo "-----START /etc/shadow----" >> $FILENAME
# echo `cat /etc/shadow` >> $FILENAME
# echo "-----END /etc/shadow-----" >> $FILENAME

# echo "-----START /etc/default/password-----" >> $FILENAME
# echo `cat /etc/default/password` >> $FILENAME
# echo "-----END /etc/default/password-----" >> $FILENAME

echo "-----START /etc/rsyslog.conf-----" >> $FILENAME
cat /etc/rsyslog.conf >> $FILENAME
echo "-----END /etc/rsyslog.conf-----" >> $FILENAME

echo "-----START /etc/ntp.conf (in case the server uses ntp)-----" >> $FILENAME
cat /etc/ntp.conf >> $FILENAME
echo "-----END /etc/ntp.conf-----" >> $FILENAME

echo "-----START /etc/chrony.conf (in case the server uses chrony for ntp)-----" >> $FILENAME
cat /etc/chrony.conf >> $FILENAME
echo "-----END /etc/chrony.conf-----" >> $FILENAME

echo "-----START PACKAGE LIST-----" >> $FILENAME
rpm -qa|sort >> $FILENAME
echo "-----END PACKAGE LIST-----" >> $FILENAME

echo "-----START AVAILABLE NEW PACKAGES (for Redhat/CentOS) -----" >> $FILENAME
yum check-update >> $FILENAME
echo "-----END AVAILABLE NEW PACKAGES-----" >> $FILENAME

echo "-----START netstat-----" >> $FILENAME
netstat -nap >> $FILENAME
echo "-----END netstat-----" >> $FILENAME

echo "-----START ss (RHEL 7 equivalent of netstat) -----" >> $FILENAME
ss -l >> $FILENAME
echo "-----END ss-----" >> $FILENAME

echo "-----START arp list-----" >> $FILENAME
arp -a >> $FILENAME
echo "-----END arp list-----" >> $FILENAME

echo "-----START ip n list (RHEL 7 equivalent for arp) -----" >> $FILENAME
ip n show >> $FILENAME
echo "-----END ip n list-----" >> $FILENAME


echo "-----START CRONTAB -----" >> $FILENAME
crontab -u root -l >> $FILENAME
echo "-----END CRONTAB-----" >> $FILENAME

echo "-----LIST ALL AUTHORIZED KEY FILES-----"
echo "YOU WILL NEED TO MANUALLY COLLECT AND PROVIDE THE FOLLOWING FILES"
KEYS=`find /home/*/.ssh -name authorized_keys`
echo ${KEYS} >> $FILENAME
KEYS2=`find /root/.ssh -name authorized_keys`
echo ${KEYS2} >> $FILENAME
echo "END LIST"

