#safe color combination
#e66101
#fdb863
#b2abd2
#5e3c99

#default histogram color sequence
set linetype  1 lc rgb "#a8ce78" lw 1
set linetype  2 lc rgb "#8eb8fc" lw 1
set linetype  3 lc rgb "#ed7e75" lw 1
set linetype  4 lc rgb "#ffc300" lw 1
set linetype  5 lc rgb "#fdb863" lw 1
set linetype  6 lc rgb "#b2abd2" lw 1

set pointsize 4

set style line 1001 lt 1 lc rgb "#e66101" lw 2 pt 3  ps 2 dashtype 1 #native 
set style line 1002 lt 1 lc rgb "#fdb863" lw 2 pt 5  ps 2 dashtype 1  #scone
set style line 1003 lt 1 lc rgb "#b2abd2" lw 2 pt 7  ps 2 dashtype 1  #palaemon ?
set style line 1004 lt 1 lc rgb "#5e3c99" lw 2 pt 6  ps 2 dashtype 1  #other 1
set style line 1005 lt 1 lc rgb "#5e3c99" lw 2 pt 11 ps 2 dashtype 1  #other 2
set style line 1006 lt 1 lc rgb "#E50000" lw 5 pt 6 ps 1 dt (2,1,2,1)  #other 2


set style line 2001  lc rgb "#E72322" lw 2 pt 13 ps 2  dt (2,1,2,1) #red dashed line -- diamond points
set style line 2002  lc rgb "#8b1a0e" lw 2 pt 9  ps 2 dt 1 #red solid line -- up triangle points
set style line 2003  lc rgb "#0E539C" lw 2 pt 7  ps 2 dt 1 #blue solid line -- circle points
set style line 2004  lc rgb "#003300" lw 4 pt 4 ps 1  dt (2,1,2,1)  #green dashed line -- empty square points
set style line 2005  lc rgb "#008F00" lw 2 pt 11 ps 2 dt 1 #green solid line -- down triangle points
set style line 2006  lc rgb "#E50000" lw 5 pt 6 ps 1 dt (2,1,2,1)  # additional 1 red dot dashed lines -- diamond points
set style line 2007  lc rgb "#1F7935" lw 5 pt 10 ps 1 dt (2,1,2,1)  # additional 2 green dashed -- down triangle points
set style line 2008  lc rgb "#0E539C" lw 3 pt 7 ps 2 dt 1 #native -- blue dashed line -- circle points
set style line 2009  lc rgb "#0E539C" lw 5 pt 7 ps 2 dt 1 #blue solid line -- diamond points

#Use these styles for histograms
set style line 1101 lt 1 lc rgb "#e66101" linewidth 1 pt 3  ps 2 dashtype 1  #native 
set style line 1102 lt 1 lc rgb "#fdb863" linewidth 1 pt 5  ps 2 dashtype 1  #scone
set style line 1103 lt 1 lc rgb "#b2abd2" linewidth 1 pt 7  ps 2 dashtype 1  #palaemon ?
set style line 1104 lt 1 lc rgb "#5e3c99" linewidth 1 pt 6  ps 2 dashtype 1  #other 1
set style line 1105 lt 1 lc rgb "#1F7935" linewidth 4 pt 11 ps 2 dashtype 1  #other 2
set style line 1106 lt 1 lc rgb "#0E539C" linewidth 1 pt 11 ps 2 dashtype 1  #

#DIFFERENT COLORS FOR LINES USED IN PERCENTILES
set style line 105 lt 1 lc rgb "#404040" lw 1 pt 9 ps 2
set style line 125 lt 1 lc rgb "#595959" lw 1 pt 9 ps 2 
set style line 150 lt 1 lc rgb "#808080" lw 1 pt 9 ps 2 
set style line 175 lt 1 lc rgb "#A6A6A6" lw 1 pt 9 ps 2 
set style line 190 lt 1 lc rgb "#D9D9D9" lw 1 pt 9 ps 2 

set style line 101 lt 1 lc rgb "black" lw 2
set style line 102 lt 1 lc rgb "black" lw 6
set style line 103 lt 2 lc rgb "black" lw 2
set style line 104 lt 2 lc rgb "black" lw 6
                  

# DASHED LINE STYLES
set style line 300  linewidth 1.000 pointtype 2 dashtype 1 pointsize default pointinterval 0
set style line 301  linewidth 2.000 pointtype 2 dashtype 2 pointsize default pointinterval 0
set style line 302  linewidth 2.000 pointtype 2 dashtype 4 pointsize default pointinterval 0
set style line 303  linewidth 2.000 pointtype 2 dashtype 5 pointsize default pointinterval 0
set style line 304  linewidth 2.000 pointtype 2 dashtype 6 pointsize default pointinterval 0
set style line 305  linewidth 2.000 pointtype 2 dashtype 7 pointsize default pointinterval 0
set style line 306  linewidth 2.000 pointtype 2 dashtype 8 pointsize default pointinterval 0

#UNUSED:
#set style line 1 lc rgb 'gray90' lt 1 lw 1 pt 9 ps 2
#set style line 2 lc rgb 'gray60' lt 1 lw 1
#set style line 3 lc rgb 'gray30' lt 1 lw 1
#set style line 4 lc rgb 'black'  lt 1 lw 1
