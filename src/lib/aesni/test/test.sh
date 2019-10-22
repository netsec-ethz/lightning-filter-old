noTests=10000 # number of test cases per block size
maxNoBlocks=4 # eg 4 --> tests 1, 2, 3 and 4 blocks

for j in $(seq 1 $maxNoBlocks)
do
	successful=0
	noBytes=$((j*16))
	echo "Testing $j blocks.."
	for i in $(seq 1 $noTests)
	do	
		#key=`hexdump -n 16 -e '4/4 "%08X"' /dev/urandom`
		key=`openssl rand -hex 16`
		#randInput=`hexdump -n $noBytes -e '4/4 "%08X"' /dev/random	`
		randInput=`openssl rand -hex $noBytes`
		refSolution=`echo $randInput | perl -ne 's/([0-9a-f]{2})/print chr hex $1/gie' | openssl enc -e -aes-128-cbc -K $key -iv 00000000000000000000000000000000 -nopad | hexdump -e '16/1 "%02X"' | tail -c 32` 
		implSolution=`./cbcmactest $key $randInput`

		if [ "$refSolution" = "$implSolution" ]
		then
			successful=$((successful+1))
		else
			echo "ERROR: The following test case failed: "	
			echo "key: $key"
			echo "input: $randInput"
			echo "reference solution: $refSolution"
			echo "output: $implSolution"
		fi
	done

	echo "$successful / $noTests successful for $j blocks"
done
