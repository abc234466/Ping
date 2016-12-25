# README #

This README would normally document whatever steps are necessary to get your application up and running.

### What is this repository for? ###

ACN Hw6 - implement Ping program

### Notice ###
1.使用區網測試 source routing.
2.Ubuntu預設是將source routing關閉的，使用
  echo 1 > /proc/sys/net/ipv4/conf/all/accept_source_route
  echo 1 > /proc/sys/net/ipv4/ip_forward
來開啟(需使用到root權限)。


Usage: sudo ./myping -g gateway [-w timeout (in msec)] [-c count] target_ip

測試環境的網路介面卡為ens33

目前已改為eth0