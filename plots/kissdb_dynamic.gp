set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "kissdb_dynamic.eps"

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




set xlabel "Time (s)" font ",16"
set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30, "35" 35, "40" 40, "45" 45, "50" 50, "55" 55, "60" 60)


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
set title "(a) Worker thread variation (2 writers)" font "Helvetica-bold,13" offset 0,1

set ytics font ",16"
set ylabel "# active workers" font ",16" offset 1.5,0

set yrange [0:4]
plot\
	f(x) w lp ls 2006 title "i-all",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	f(x) w lp ls 2001 title "i-fread",\
	f(x) w lp ls 2002 title "i-fwrite",\
	f(x) w lp ls 2003 title "i-frw",\
	f(x) w lp ls 2007 title "i-fseeko",\
	'data/dynamic/kissdb/intel-2threads/intel_all.csv' using 1:3 notitle 'i-all' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/dynamic/kissdb/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/dynamic/kissdb/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005, \
	'data/dynamic/kissdb/intel-2threads/intel_fread.csv' using 1:3 notitle 'i-fread' with lines ls 2001,\
	'' every 1 using 1:3  notitle '' with points ls 2001, \
	'data/dynamic/kissdb/intel-2threads/intel_fwrite.csv' using 1:3 notitle 'i-fwrite' with lines ls 2002,\
	'' every 1 using 1:3  notitle '' with points ls 2002, \
	'data/dynamic/kissdb/intel-2threads/intel_frw.csv' using 1:3 notitle 'i-frw' with lines ls 2003,\
	'' every 1 using 1:3  notitle '' with points ls 2003, \
	'data/dynamic/kissdb/intel-2threads/intel_fseeko.csv' using 1:3 notitle 'i-fseeko' with lines ls 2007,\
	'' every 1 using 1:3  notitle '' with points ls 2007
	


unset ylabel
set lmargin MX+1

set origin MX+LX+1*(IX+SX)-0.01,MY+0*(IY+SY)+LY
set title "(b) SET Throughput (2 writers)" font "Helvetica-bold,13" offset 0,1



set xlabel "Time (s)" font ",16"
set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30, "35" 35, "40" 40, "45" 45, "50" 50, "55" 55, "60" 60)
set xtics font ",16"



set datafile separator ","
unset key
set yrange [0:0.4]
plot\
	f(x) w lp ls 2006 title "i-all",\
	f(x) w lp ls 2004 title "zc",\
    f(x) w lp ls 2005 title "no-sl",\
	f(x) w lp ls 2001 title "i-fread",\
	f(x) w lp ls 2002 title "i-fwrite",\
	f(x) w lp ls 2003 title "i-frw",\
	f(x) w lp ls 2007 title "i-fseeko",\
	'data/dynamic/kissdb/intel-4threads/intel_all.csv' using 1:3 notitle 'i-all' with lines ls 2006,\
	'' every 1 using 1:3  notitle '' with points ls 2006, \
  	'data/dynamic/kissdb/zc.csv' using 1:3 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:3  notitle '' with points ls 2004, \
    'data/dynamic/kissdb/no_sl.csv' using 1:3 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:3  notitle '' with points ls 2005, \
	'data/dynamic/kissdb/intel-4threads/intel_fread.csv' using 1:3 notitle 'i-fread' with lines ls 2001,\
	'' every 1 using 1:3  notitle '' with points ls 2001, \
	'data/dynamic/kissdb/intel-4threads/intel_fwrite.csv' using 1:3 notitle 'i-fwrite' with lines ls 2002,\
	'' every 1 using 1:3  notitle '' with points ls 2002, \
	'data/dynamic/kissdb/intel-4threads/intel_frw.csv' using 1:3 notitle 'i-frw' with lines ls 2003,\
	'' every 1 using 1:3  notitle '' with points ls 2003, \
	'data/dynamic/kissdb/intel-4threads/intel_fseeko.csv' using 1:3 notitle 'i-fseeko' with lines ls 2007,\
	'' every 1 using 1:3  notitle '' with points ls 2007
	

!epstopdf "kissdb_dynamic.eps"
!rm "kissdb_dynamic.eps"
quit