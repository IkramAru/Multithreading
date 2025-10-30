#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <logfile>"
    exit 1
fi

LOGFILE="$1"

awk '
/\[Worker\] processed/ {
    val=$3
    sum+=val
    if (val > max || NR==1) max=val
    if (val < min || NR==1) min=val
    count++
}
END {
    if (count > 0) {
        avg=sum/count
        printf "Hasil dari %s:\n", FILENAME
        printf "Rata-rata = %.2f events/detik\n", avg
        printf "Max = %d\n", max
        printf "Min = %d\n", min
    } else {
        print "Tidak ada data ditemukan."
    }
}' "$LOGFILE"
