set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "memcpy.eps"
set size 0.8,0.65
f(x)=1000000

NANO=0.000000001

set ytics nomirror
set grid y

set xtics font ",16"
set ytics font ",16"
set ylabel "Avg. Latency (s)" font ",16" offset 0,0

#set logscale y 10
#set ytics ("10^{-6}" 0.0000010,"10^{-5}" 0.00001,"10^{-4}" 0.0001,"10^{-3}" 0.001,"10^{-2}" 0.01,"10^{-1}" 0.1,"10^{0}" 1,"10^{1}" 10)
#set xlabel "Num. of calls" font ",16"

set xlabel "Data size (bytes)" font ",16"

#set xtics("2" 2, "4" 4,"8" 8, "16" 16, "32" 32, "64" 64, "128" 128, "256" 256, "512" 512, "1024" 1024, "2048" 2056, "4096" 4096)
#set xrange[0:40]

set xtics offset 0,0.5,0
set xlabel offset 0,1,0

#------------------------------------------Plots-------------------------------------------------
 set title "SET Latency: 4 client threads, 10 conns, 500 req/conn " font "Helvetica-bold,16" offset 0,0.65
#set title "Run time for 2 callers doing ocall multi" font "Helvetica-bold,16" offset 0,0.65

#set xrange [0:100000]
set datafile separator ","
set key maxrows 1 samplen 1 width -1 invert center at graph 0.35,1.1 font ",12"
#set key vertical samplen 1.1 width 1 spacing -2 invert reverse Left outside maxrows 1  width -3 center at graph 0.62,1.11
set yrange [0:5]
plot\
	f(x) w lp ls 2006 title "vanilla-memcpy",\
	f(x) w lp ls 2004 title "zc-memcpy",\
	'data/mcd-tput/var-data/intel-old-memcpy.csv' using 1:4 notitle 'vanilla-memcpy' with lines ls 2006,\
	'' every 1 using 1:4  notitle '' with points ls 2006, \
  	'data/mcd-tput/var-data/intel-new-memcpy.csv' using 1:4 notitle 'zc-memcpy' with lines ls 2004, \
	'' every 1 using 1:4  notitle '' with points ls 2004
	


!epstopdf "memcpy.eps"
!rm "memcpy.eps"
quit