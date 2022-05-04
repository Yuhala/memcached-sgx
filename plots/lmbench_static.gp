set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "lmbench_static.eps"

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

set lmargin MX+4
set rmargin MX+6

set tmargin MY+5.56
set bmargin MY+0.5

set multiplot

set ytics nomirror
set grid y

set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set size 0.53,SY




set xlabel "Num of ops (x1000)" font ",16"
set xtics("1" 1000,"2" 2000, "3" 3000, "4" 4000, "5" 5000, "6" 6000, "7" 7000, "8" 8000, "9" 9000, "10" 10000)

set xtics offset 0,0.5,0
set xtics font ",16"
set xlabel offset 0,1,0

#set key box
#set key spacing 1.25 font ",10"
#set key invert reverse Left outside
#set key ins vert
#set key left top

set key maxrows 1 samplen 1.1 width -1 invert center at graph 1,1.125 font ",12"
#set key maxrows 1 samplen 1.1 width -2 invert reverse at graph 1.,1.08 font ",12"
#set key horizontal font "Helvetica, 20" width 1.8 at  2.1,1.08, graph 0.1 center maxrows 1
#------------------------------------------Plots-------------------------------------------------

set title "(a) Operation latency" font "Helvetica-bold,13" offset 0,1

#set title "(a) Operation throughput" font "Helvetica-bold,13" offset 0,1
#set ytics("100" 100000 ,"200" 200000, "300" 300000, "400" 400000, "500" 500000, "600" 600000, "700" 700000, "800" 800000, "900" 900000, "1000" 1000000)

set ytics font ",16"
set ylabel "Latency (s)" font ",16" offset 1.5,0

set yrange [0:0.4]

plot\
	f(x) w lp ls 2006 title "i-all",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	f(x) w lp ls 2001 title "i-read",\
	f(x) w lp ls 2002 title "i-write",\
	'data/lmbench/intel-1thread/intel_all.csv' using 1:2 notitle 'i-all' with lines ls 2006,\
	'' every 1 using 1:2  notitle '' with points ls 2006, \
  	'data/lmbench/intel-1thread/zc.csv' using 1:2 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:2  notitle '' with points ls 2004, \
    'data/lmbench/no_sl.csv' using 1:2 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:2  notitle '' with points ls 2005, \
	'data/lmbench/intel-1thread/intel_read.csv' using 1:2 notitle 'i-read' with lines ls 2001,\
	'' every 1 using 1:2  notitle '' with points ls 2001, \
	'data/lmbench/intel-1thread/intel_write.csv' using 1:2 notitle 'i-write' with lines ls 2002,\
	'' every 1 using 1:2  notitle '' with points ls 2002
	


unset ylabel
set lmargin MX+1

set origin MX+LX+1*(IX+SX)-0.01,MY+0*(IY+SY)+LY


set title "(b) CPU % usage" font "Helvetica-bold,13" offset 0,1
set ytics font ",16"
set ylabel "Av. CPU usage (%)" font ",16" offset 1.5,0

set xlabel "Num of ops (x1000)" font ",16"
set xtics("1" 1000,"2" 2000, "3" 3000, "4" 4000, "5" 5000, "6" 6000, "7" 7000, "8" 8000, "9" 9000, "10" 10000)
set xtics font ",16"



set datafile separator ","
unset key
set yrange [0:100]


plot\
	f(x) w lp ls 2006 title "i-all",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	f(x) w lp ls 2001 title "i-read",\
	f(x) w lp ls 2002 title "i-write",\
	'data/lmbench/intel-1thread/intel_all.csv' using 1:4 notitle 'i-all' with lines ls 2006,\
	'' every 1 using 1:4  notitle '' with points ls 2006, \
  	'data/lmbench/intel-1thread/zc.csv' using 1:4 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:4  notitle '' with points ls 2004, \
    'data/lmbench/no_sl.csv' using 1:4 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:4  notitle '' with points ls 2005, \
	'data/lmbench/intel-1thread/intel_read.csv' using 1:4 notitle 'i-read' with lines ls 2001,\
	'' every 1 using 1:4  notitle '' with points ls 2001, \
	'data/lmbench/intel-1thread/intel_write.csv' using 1:4 notitle 'i-write' with lines ls 2002,\
	'' every 1 using 1:4  notitle '' with points ls 2002

	

!epstopdf "lmbench_static.eps"
!rm "lmbench_static.eps"
quit