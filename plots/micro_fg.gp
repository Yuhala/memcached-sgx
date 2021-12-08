set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "micro_fg.eps"


f(x)=1000000

NX=3
NY=2
# Size of graphs
SX=0.001
SY=0.18

# Margins
MX=0.075
MY=0.075
# Space between graphs
IX=0.4
IY=0.2
# Space for legends
LX=0.05
LY=0

#NANO=0.000000001
#MILLI=0.001

set lmargin MX+0
set rmargin MX+35

set tmargin MY+12
set bmargin MY+4

set multiplot

#set border 3 front lt black linewidth 1.000 dashtype solid
#set boxwidth 0.95 absolute
set boxwidth 0.8 #relative
set style fill  solid 1.00 noborder
set grid y



set xtics border in scale 0,0 nomirror rotate by -45  autojustify
set xtics norangelimit font ",15"
#set xtics   ()

set ytics border in scale 0,0 mirror norotate  autojustify
set ytics font ",15" offset 0.5,0.0

set ytics nomirror
set grid y
set grid x




set ylabel "Avg. CPU usage (%)" font "Helvetica, 12" offset 2.5,0
#set key vertical maxrows 1 sample 0.8 width 0 at 5,4.55 font ",20" Right reverse
set key maxrows 1 samplen 4 width -1 invert center at graph 1.75,2.475 font ",12"

set origin MX+LX+0*(IX+SX)-0.05,MY+0*(IY+SY)+LY
set size 0.9,1
#set title "10% f, 90% g" offset 0,-0.75 font "Helvetica-bold,16"
#set xtics ("10" 10000, "20" 20000,"30" 30000,"40" 40000,"50" 50000, "60" 60000, "70" 70000, "80" 80000, "90" 90000, "100" 100000) norotate offset 0,0.5
set xtics ("20" 20000, "40" 40000,"60" 60000, "80" 80000, "100" 100000) norotate offset 0,0.5



set ytics ("0" 0, "50" 50, "100" 100)


set yrange [0:100]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/10f/intel.csv' using 1:3 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/micro-fg/10f/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/micro-fg/10f/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005


set origin MX+LX+1*(IX+SX)-0.15,MY+0*(IY+SY)+LY
unset ylabel
unset key

#set title "50% f, 50% g" offset 0,-0.75 font "Helvetica-bold,16"

set ytics ("0" 0, "50" 50, "100" 100)
set yrange [0:100]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/50f/intel.csv' using 1:3 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/micro-fg/50f/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/micro-fg/50f/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005




set origin MX+LX+2*(IX+SX)-0.25,MY+0*(IY+SY)+LY
#set title "90% f, 10% g" offset 0,-0.75 font "Helvetica-bold,16"

set ytics ("0" 0, "50" 50, "100" 100)
set yrange [0:100]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/90f/intel.csv' using 1:3 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/micro-fg/90f/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/micro-fg/90f/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005





set origin MX+LX+0*(IX+SX)-0.05,MY+1*(IY+SY)+LY
set ylabel "Total Latency (s)" font "Helvetica, 12" offset 2.5,0

set ytics ("0" 0, "0.2" 0.2, "0.4" 0.4, "0.6" 0.6, "0.8" 0.8, "1" 1)
set title "10% f, 90% g" offset 0,-0.75 font "Helvetica-bold,16"
#set label 2001 "#Ocalls (x1000):" font "Helvetica, 10" at -4.5,-0.15
set yrange [0:1.1]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/10f/intel.csv' using 1:2 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:2  notitle '' with points ls 2006, \
  	'data/micro-fg/10f/zc.csv' using 1:2 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:2  notitle '' with points ls 2004, \
    'data/micro-fg/10f/no_sl.csv' using 1:2 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:2  notitle '' with points ls 2005

set origin MX+LX+1*(IX+SX)-0.15,MY+1*(IY+SY)+LY
unset ylabel

set ytics ("0" 0, "0.2" 0.2, "0.4" 0.4, "0.6" 0.6, "0.8" 0.8)
set title "50% f, 50% g" offset 0,-0.75 font "Helvetica-bold,16"
set label 1001 "Num. of ocall invocations (x1000)" font "Helvetica, 16" at -3.5,-1.3


set yrange [0:0.8]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/50f/intel.csv' using 1:2 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:2  notitle '' with points ls 2006, \
  	'data/micro-fg/50f/zc.csv' using 1:2 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:2  notitle '' with points ls 2004, \
    'data/micro-fg/50f/no_sl.csv' using 1:2 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:2  notitle '' with points ls 2005
								 
set origin MX+LX+2*(IX+SX)-0.25,MY+1*(IY+SY)+LY
set title "90% f, 10% g" offset 0,-0.75 font "Helvetica-bold,16"


unset label 1001
set ytics ("0" 0, "0.1" 0.1, "0.2" 0.2, "0.3" 0.3)
set yrange [0:0.3]
plot\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	'data/micro-fg/90f/intel.csv' using 1:2 notitle 'intel' with lines ls 2006,\
	'' every 1 using 1:2  notitle '' with points ls 2006, \
  	'data/micro-fg/90f/zc.csv' using 1:2 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:2  notitle '' with points ls 2004, \
    'data/micro-fg/90f/no_sl.csv' using 1:2 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:2  notitle '' with points ls 2005
	



!epstopdf "micro_fg.eps"
!rm "micro_fg.eps"
quit