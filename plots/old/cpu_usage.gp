set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "cpu_usage.eps"

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





set xlabel "Num of keys (x1000)" font ",16"
set xtics("1" 1000,"2" 2000, "3" 3000, "4" 4000, "5" 5000, "6" 6000, "7" 7000, "8" 8000, "9" 9000, "10" 10000)


set xtics offset 0,0.5,0
set xtics font ",16"
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
set title "Avg. CPU usage for SET operations(2 writers)" font "Helvetica-bold,13" offset 0,1

set ytics font ",16"
set ylabel "Avg. CPU usage (%)" font ",16" offset 1.5,0

set yrange [0:100]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/kyoto/cpu/intel.csv' using 1:3 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/kyoto/cpu/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/kyoto/cpu/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005
	


!epstopdf "cpu_usage.eps"
!rm "cpu_usage.eps"
quit