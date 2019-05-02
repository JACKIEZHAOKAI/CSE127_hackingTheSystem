#!/usr/bin/env sh

pidfile="PID"
archvprefix="hw2"

abort() {
  echo $1
  echo "Your homework was *NOT* submitted."
  exit
}

check_file() { # 1: name
  if [ -f $1 ]; then
    echo "Found file $1."
  else
    abort "Could not find file $1 in current directory."
  fi
}

confirm() { # 1: question to confirm
  while true; do
    read -p "$1 [y/n] " yn
    case $yn in
      [Yy]* ) break;;
      [Nn]* ) abort "You answered no.";;
      * ) echo "Please answer y for yes, or n for no.";;
    esac
  done
}

check_file $pidfile
check_file "writeup.txt"
check_file "sploits/sploit1.c"
check_file "sploits/sploit2.c"
check_file "sploits/sploit3.c"
check_file "sploits/sploit4.c"

read -r pid1 pid2 rest < $pidfile
if [ -z "$pid2" ]; then
  echo "Found one PID: '$pid1'"
  confirm "Are you submitting without a partner?"
else
  echo "Found one PID: '$pid1'"
  echo "Found one PID: '$pid2'"
  confirm "Please confirm that this is your PID and that of your partner."
  echo "We will expect the exploits to work with PID: '$pid1'"
  confirm "Please confirm that your exploit works with this PID." 
fi

confirm "Do you agree to all files in the current directory being archived?"
timestamp=`date +%s` # for uniqueness, not for checking late days, since students could spoof this
archv="${archvprefix}-${pid1}-${timestamp}.tar.gz"

tar_cmd="tar --exclude=*.tar.gz -zcvf $archv ./*"
echo "$tar_cmd"

$tar_cmd || abort "Something went wrong with the tar command"

confirm "Do you agree to submit the archive to the '$pid1' submission directory?"
sftpout=`sftp ${pid1}@b09-04.sysnet.ucsd.edu:/submissions << EOF
put ${archv}
quit
EOF`
echo "$sftpout"
success=`echo "$sftpout" | grep Uploading`
if [ -z "$success" ]; then
  abort "Something went wrong with the upload"
fi

echo "Congratulations, your homework was submitted"

