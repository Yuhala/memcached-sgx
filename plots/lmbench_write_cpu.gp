set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "lmbench_write_cpu.eps"

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

set ytics ("0" 0, "25" 25, "50" 50, "75" 75, "100" 100)
set yrange [0:100]

set ytics font ",12"

set xlabel "Time (s)" font ",16"
#set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30)
set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30, "35" 35, "40" 40, "45" 45, "50" 50, "55" 55, "60" 60)


set xtics offset 0,0.5,0
set xtics font ",12"
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
set title "(a) 2 workers-intel" font "Helvetica-bold,13" offset 0,1


set ylabel "Avg. CPU usage (%)" font ",14" offset 1.5,0


#set yrange [0:1000000]
plot\
	'data/dynamic/lmbench/intel-2threads/writer/intel_all.csv' using 1:4 title 'i-all' w lp ls 2006,\
	'data/dynamic/lmbench/intel-2threads/writer/zc.csv' using 1:4 title 'zc' w lp ls 2004, \
	'data/dynamic/lmbench/no_sl_reader.csv' using 1:4 title 'no_sl' w lp ls 2005, \
	'data/dynamic/lmbench/intel-2threads/writer/intel_read.csv' using 1:4 title 'i-read' w lp ls 2001,\
	'data/dynamic/lmbench/intel-2threads/writer/intel_write.csv' using 1:4 title 'i-write' w lp ls 2002,\
		


unset ylabel
set lmargin MX+1

set origin MX+LX+1*(IX+SX)-0.01,MY+0*(IY+SY)+LY
set title "(b) 4 workers-intel" font "Helvetica-bold,13" offset 0,1


set xlabel "Time (s)" font ",16"
set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30, "35" 35, "40" 40, "45" 45, "50" 50, "55" 55, "60" 60)
#set xtics("5" 5,"10" 10, "15" 15, "20" 20, "25" 25, "30" 30)
set xtics font ",12"

set datafile separator ","
unset key

#set yrange [0:1000000]
plot\
	'data/dynamic/lmbench/intel-4threads/writer/intel_all.csv' using 1:4 title 'i-all' w lp ls 2006,\
	'data/dynamic/lmbench/intel-4threads/writer/zc.csv' using 1:4 title 'zc' w lp ls 2004, \
	'data/dynamic/lmbench/no_sl_reader.csv' using 1:4 notitle 'no_sl' w lp ls 2005, \
	'data/dynamic/lmbench/intel-4threads/writer/intel_read.csv' using 1:4 title 'i-read' w lp ls 2001,\
	'data/dynamic/lmbench/intel-4threads/writer/intel_write.csv' using 1:4 title 'i-write' w lp ls 2002,\
		

!epstopdf "lmbench_write_cpu.eps"
!rm "lmbench_write_cpu.eps"
quit