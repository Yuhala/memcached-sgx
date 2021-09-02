#!/bin/bash

NUMBER_OF_EXECS=10
NUMBER_OF_GROUPS=250
NUMBER_OF_LOOPS=2048
ONLY_PHASE3=0

print_usage_exit()
{
    echo "options:"
    echo -e "\t-g\t\tnumber of groups used by hackbench (default 250)"
    echo -e "\t-l\t\tnumber of loops made by hackbench (default 10)"
    echo -e "\t-e\t\tnumber of executions of hackbench (default 10)"
    echo -e "\t-p\t\tlook only at the time of the third phase (default off)"
    echo -e "\t-h\t\tdisplays help"
    exit 0
}

print_progress()
{
    local actual=$1
    local total=$2
    local number_of_bars=$(echo "($actual/$total)*50" | bc -l)
    local i
    number_of_bars=$(echo "$number_of_bars / 1" | bc) # I found no simpler way to floor a value

    echo -n '['
    for (( i=0; i<number_of_bars; i++))
    do
	echo -n "#"
    done
    for (( i=number_of_bars ; i<50; i++))
    do
	echo -n " "
    done

    echo -e "]\t($actual/$total)"
}

while getopts "h?g:l:e:p" opt; do
    case "$opt" in
	h|\?)
            print_usage_exit
            ;;
	g)  NUMBER_OF_GROUPS=$OPTARG
            ;;
	l)  NUMBER_OF_LOOPS=$OPTARG
            ;;
	e)  NUMBER_OF_EXECS=$OPTARG
            ;;
	p)  ONLY_PHASE3=1
	    ;;
    esac
done


# Calcul des temps
print_progress 0 $NUMBER_OF_EXECS
for (( i=0; i<$NUMBER_OF_EXECS; i++ ))
do
    if (( $ONLY_PHASE3 == 0 ))
    then
	start=$(date +%s.%N)
	hackbench -g$NUMBER_OF_GROUPS -l$NUMBER_OF_LOOPS > /dev/null
	end=$(date +%s.%N)
	duration=$(echo "$end - $start" | bc -l)
    else
	duration=$(./app $NUMBER_OF_LOOPS 2> /dev/null | grep 'Time elapsed' | tail -c+15 | head -c-9)
    fi
    bench_times[$i]=$duration
    echo -e "\e[2A"
    print_progress $((i+1)) $NUMBER_OF_EXECS
done

# Calcul de la moyenne
sum=0
for (( i=0; i<$NUMBER_OF_EXECS; i++ ))
do
    sum=$(echo "${bench_times[$i]} + $sum" | bc -l)
done
average=$(echo "$sum / $NUMBER_OF_EXECS" | bc -l)

# Calcul de l'écart type
tmp_sum=0
for (( i=0; i<$NUMBER_OF_EXECS; i++ ))
do
    tmp_sum=$(echo "$tmp_sum + (${bench_times[$i]} - $average)^2" | bc -l)
done
standard_deviation=$(echo "sqrt($tmp_sum  / $NUMBER_OF_EXECS)" | bc -l)

# Affichage des résultats
echo "average: $average"
echo "standard deviation: $standard_deviation"
