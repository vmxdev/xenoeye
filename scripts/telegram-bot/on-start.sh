#!/bin/bash

msgs_dir=/var/lib/xenoeye/telemsg/

args=("$@")

filename_src=${args[3]}
filename_dst=${msgs_dir}${filename_src##*/}".n"
filename_dst_tmp=${filename_dst}".tmp"

dt=$(date '+%F %T.%3N');

echo -n "Overlimit detected at '<b>${dt}</b>', object '<b>${args[0]}</b>', IP <b>${args[4]}</b>, proto <b>${args[5]}</b>, BPS <b>$((${args[6]}*8))</b>, limit $((${args[7]}*8)) BPS" > ${filename_dst_tmp}
mv ${filename_dst_tmp} ${filename_dst}
echo ${filename_dst}
