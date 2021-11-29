set term postscript color eps enhanced 22
set encoding utf8
load "styles.inc"
set output "kyoto.eps"
set size 0.8,0.65
f(x)=1000000

NANO=0.000000001

set ytics nomirror
set grid y

set xtics font ",16"
set ytics font ",16"
set ylabel "Total runtime (s)" font ",16" offset 0,0

#set logscale y 10
#set ytics ("10^{-6}" 0.0000010,"10^{-5}" 0.00001,"10^{-4}" 0.0001,"10^{-3}" 0.001,"10^{-2}" 0.01,"10^{-1}" 0.1,"10^{0}" 1,"10^{1}" 10)
#set xlabel "Num. of calls" font ",16"

set xlabel "Num. of keys (x1000)" font ",16"

#set xtics("4" 4000,"8" 8000, "12" 12000, "16" 16000, "20" 20000, "24" 24000, "28" 28000, "32" 32000, "36" 36000, "40" 40000, "44" 44000, "48" 48000, "52" 52000)
set xtics("10" 10000,"20" 20000, "3" 30000, "40" 40000, "50" 50000, "60" 60000, "70" 70000, "80" 80000, "90" 90000, "100" 100000)
#set xtics("10" 10000,"20" 20000, "30" 30000, "40" 40000, "50" 50000, "60" 60000)

set xtics offset 0,0.5,0
set xlabel offset 0,1,0

#------------------------------------------Plots-------------------------------------------------
 set title "Run time for writing kv pairs in kc HashDB" font "Helvetica-bold,16" offset 0,0.65
#set title "Run time for 2 callers doing ocall multi" font "Helvetica-bold,16" offset 0,0.65

#set xrange [0:100000]
set datafile separator ","
set key maxrows 1 samplen 1 width -1 invert center at graph 0.35,1.1 font ",12"
#set key vertical samplen 1.1 width 1 spacing -2 invert reverse Left outside maxrows 1  width -3 center at graph 0.62,1.11
#set yrange [0:2]

plot\
	f(x) w lp ls 2005 title "no_sl",\
	f(x) w lp ls 2006 title "intel",\
	f(x) w lp ls 2004 title "zc",\
	'data/kyoto/no_sl.csv' using 1:2 notitle 'no_sl' with lines ls 2005, \
	'' every 1 using 1:2  notitle '' with points ls 2005, \
	'data/kyoto/intel.csv' using 1:2 notitle 'intel' with lines ls 2006, \
	'' every 1 using 1:2 notitle '' with points ls 2006, \
	'data/kyoto/zc.csv' using 1:2 notitle 'zc' with lines ls 2004, \
	'' every 1 using 1:2 notitle '' with points ls 2004, 



!epstopdf "kyoto.eps"
!rm "kyoto.eps"
quit