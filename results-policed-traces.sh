#!/bin/bash
set -e

UNAME_S=$(uname -s)
if [ "$UNAME_S" == "Darwin" ]; then
	ZCAT_CMD=gzcat
	READLINK=greadlink
else
	ZCAT_CMD=zcat
	READLINK=readlink
fi

POLICED_TRACE_DIR="`$READLINK -f $(dirname ${BASH_SOURCE[0]})/ndt-trace-data`"
PROCESS_PCAP="`$READLINK -f $(dirname \"${BASH_SOURCE[0]}\")/exp_process_1.py`"
rm $POLICED_TRACE_DIR/results.csv
rm ./results.csv

if ls $POLICED_TRACE_DIR >/dev/null 2>&1; then
	cd $POLICED_TRACE_DIR

	for file in `ls ./`;
	do
		echo "Processing trace: $file"
		(echo "$(python $PROCESS_PCAP $file)" || echo $file,ERROR) >> results.csv
	done
	cd -

	cp $POLICED_TRACE_DIR/results.csv ./results.csv
else
	echo "No trace to be processed"
	touch ./results.csv
fi
