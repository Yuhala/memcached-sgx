set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "upd_tput_lat.eps"
set size 0.8,0.65
f(x)=1000000

NANO=0.000000001

set ytics nomirror
set grid y

set xtics font ",16"
set ytics font ",16"
set ylabel "Avg. update latency (ms)" font ",16" offset 0,0

#set logscale y 10
#set ytics ("10^{-6}" 0.0000010,"10^{-5}" 0.00001,"10^{-4}" 0.0001,"10^{-3}" 0.001,"10^{-2}" 0.01,"10^{-1}" 0.1,"10^{0}" 1,"10^{1}" 10)
set xlabel "Throughput (k.ops/s)" font ",16"
#set xtics("4" 4000,"8" 8000, "12" 12000, "16" 16000, "20" 20000, "24" 24000, "28" 28000, "32" 32000, "36" 36000, "40" 40000, "44" 44000, "48" 48000, "52" 52000)
set xtics("100" 100000,"200" 200000, "300" 300000, "400" 400000, "500" 500000, "600" 600000)

set xtics offset 0,0.5,0
set xlabel offset 0,1,0

#------------------------------------------Plots-------------------------------------------------
set title "Tput vs lat: workloada, 20k ops" font "Helvetica-bold,16" offset 0,0.5

#set yrange [0:10]
set datafile separator ","
set key maxrows 1 samplen 1 width -1 invert center at graph 0.35,1.1 font ",12"
#set key vertical samplen 1.1 width 1 spacing -2 invert reverse Left outside maxrows 1  width -3 center at graph 0.62,1.11
set yrange [0:3]
plot\
	f(x) w lp ls 2003 title "sgx-hw",\
	f(x) w lp ls 2005 title "mcd-native",\
	f(x) w lp ls 2006 title "sgx-sim",\
	f(x) w lp ls 2004 title "intel-swtcless",\
	f(x) w lp ls 2002 title "zc-swtcless",\
	'data/workloada/tput_lat_hw_no_switchless.csv' using 1:3 notitle 'sgx-hw' with lines ls 2003,\
	'' every 1 using 1:3  notitle '' with points ls 2003, \
  	'data/workloada/tput_lat_mcd_native.csv' using 1:3 notitle 'mcd-native' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005, \
	'data/workloada/tput_lat_sim.csv' using 1:3 notitle 'sgx-sim' with lines ls 2006, \
	'' every 1 using 1:3 notitle '' with points ls 2006
	#'' using 1:($5*NANO) notitle 'concrete-in' with lines ls 2004, \
	#'' every 1 using 1:($5*NANO) notitle '' with points ls 2004	



!epstopdf "upd_tput_lat.eps"
!rm "upd_tput_lat.eps"
quit