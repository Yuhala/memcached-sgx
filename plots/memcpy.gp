set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "memcpy.eps"

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
set ylabel "Avg. Latency (s)" font ",16" offset 1.5,0



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
set title "(a) SET Latency: 4 client threads, 500 req/conn" font "Helvetica-bold,13" offset 0,1

set yrange [0:6]
plot\
	f(x) w lp ls 2006 title "vanilla-memcpy",\
	f(x) w lp ls 2004 title "zc-memcpy",\
	'data/memcpy/var-conns/intel-old-memcpy.csv' using 1:4 notitle 'vanilla-memcpy' with lines ls 2006,\
	'' every 1 using 1:4  notitle '' with points ls 2006, \
  	'data/memcpy/var-conns/intel-new-memcpy.csv' using 1:4 notitle 'zc-memcpy' with lines ls 2004, \
	'' every 1 using 1:4  notitle '' with points ls 2004
	


unset ylabel

set origin MX+LX+1*(IX+SX)-0.01,MY+0*(IY+SY)+LY
set title "(b) SET Latency: 4 client threads, 20k requests" font "Helvetica-bold,13" offset 0,1
#set ylabel "Avg. Latency (s)" font ",16" offset 2,0




set xrange [500:4000]
set xtics("0.5" 500, "1" 1000, "2" 2000, "3" 3000, "4" 4000)

set xtics font ",16"
#set xtics offset 0,0.5,0


set xlabel "Data size (x1000 bytes)" font ",16"
set datafile separator ","
#unset key
set yrange [0:4]
plot\
	f(x) w lp ls 2006 title "vanilla-memcpy",\
	f(x) w lp ls 2004 title "zc-memcpy",\
	'data/memcpy/var-data/intel-old-memcpy.csv' using 1:3 notitle 'vanilla-memcpy' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/memcpy/var-data/intel-new-memcpy.csv' using 1:3 notitle 'zc-memcpy' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004
	

!epstopdf "memcpy.eps"
!rm "memcpy.eps"
quit