set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "var_conns.eps"

f(x)=1000000

NX=2
NY=1
# Size of graphs
SX=0.85
SY=0.675

# Margins
MX=0.075
MY=0.075
# Space between graphs
IX=-0.4
IY=0
# Space for legends
LX=0.05
LY=0.01


NUM_WORKERS=1



set size 1.0,0.65

set lmargin MX+1
set rmargin MX+6

set tmargin MY+5.56
set bmargin MY+0.5

set multiplot

set ytics nomirror
set grid y

set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set size 0.53,SY

set xtics font ",16"
set ytics font ",16"
set ylabel "Throughput (ops/s)" font ",16" offset 1.5,0



set xlabel "Num. conns/thread" font ",16"
set xtics("2" 2, "4" 4, "6" 6, "8" 8, "10" 10, "12" 12, "14" 14, "16" 16, "18" 18, "20" 20)


set xtics offset 0,0.5,0
set xlabel offset 0,1,0

#set key box
#set key spacing 1.25 font ",10"
#set key invert reverse Left outside
#set key ins vert
#set key left top

set key maxrows 1 samplen 1.1 width -1 invert center at graph 0.5,1.125 font ",12"
#set key maxrows 1 samplen 1.1 width -2 invert reverse at graph 1.,1.08 font ",12"
#set key horizontal font "Helvetica, 20" width 1.8 at  2.1,1.08, graph 0.1 center maxrows 1
#------------------------------------------Plots-------------------------------------------------
set title "(a) SET Tput: 4 client threads, 500 req/conn, 3W " font "Helvetica-bold,13" offset 0,1

set yrange [0:10000]
plot\
	f(x) w lp ls 2003 title "sgx-hw",\
	f(x) w lp ls 2005 title "zc+sch",\
	f(x) w lp ls 2006 title "native",\
	f(x) w lp ls 2004 title "intel",\
	f(x) w lp ls 2002 title "",\
	'data/mcd-tput/var-conns/worker-3/no-sl.csv' using 1:3 notitle 'sgx-hw' with lines ls 2003,\
	'' every 1 using 1:3  notitle '' with points ls 2003, \
  	'data/mcd-tput/var-conns/worker-3/zc.csv' using 1:3 notitle 'zc+schd' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005, \
	'data/mcd-tput/var-conns/worker-3/native.csv' using 1:3 notitle 'native' with lines ls 2006, \
	'' every 1 using 1:3 notitle '' with points ls 2006, \
	'data/mcd-tput/var-conns/worker-3/intel.csv' using 1:3 notitle 'intel-swtcless' with lines ls 2004, \
	'' every 1 using 1:3 notitle '' with points ls 2004, \
	'data/mcd-tput/var-conns/worker-3/xx.csv' using 1:3 notitle '' with lines ls 2002, \
	'' every 1 using 1:3 notitle '' with points ls 2002



unset ylabel

set origin MX+LX+1*(IX+SX)-0.01,MY+0*(IY+SY)+LY
set title "(b) SET Latency:4 client threads, 500 req/conn, 3W" font "Helvetica-bold,13" offset 0,1
set ylabel "Avg. Latency (s)" font ",16" offset 2,0



#set xrange[0:60000]
set xtics("2" 2, "4" 4, "6" 6, "8" 8, "10" 10, "12" 12, "14" 14, "16" 16, "18" 18, "20" 20)
set xtics offset 0,0.5,0


set xlabel "Num. conns/thread" font ",16"
set datafile separator ","
#unset key
set yrange [0:15]
plot\
	f(x) w lp ls 2003 title "sgx-hw",\
	f(x) w lp ls 2005 title "zc+sch",\
	f(x) w lp ls 2006 title "native",\
	f(x) w lp ls 2004 title "intel",\
	f(x) w lp ls 2002 title "",\
	'data/mcd-tput/var-conns/worker-3/no-sl.csv' using 1:5 notitle 'sgx-hw' with lines ls 2003,\
	'' every 1 using 1:5  notitle '' with points ls 2003, \
  	'data/mcd-tput/var-conns/worker-3/zc.csv' using 1:5 notitle 'zc+schd' with lines ls 2005, \
	'' every 1 using 1:5  notitle '' with points ls 2005, \
	'data/mcd-tput/var-conns/worker-3/native.csv' using 1:5 notitle 'native' with lines ls 2006, \
	'' every 1 using 1:5 notitle '' with points ls 2006, \
	'data/mcd-tput/var-conns/worker-3/intel.csv' using 1:5 notitle 'intel' with lines ls 2004, \
	'' every 1 using 1:5 notitle '' with points ls 2004, \
	'data/mcd-tput/var-conns/worker-3/xx.csv' using 1:5 notitle '' with lines ls 2002, \
	'' every 1 using 1:5 notitle '' with points ls 2002

!epstopdf "var_conns.eps"
!rm "var_conns.eps"
quit