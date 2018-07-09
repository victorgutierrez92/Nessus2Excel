for file in *.xml
do
	echo "Procesando: $file..."
	output=$(echo $file | sed s/\.xml$//)
	python Nessus2Excel.py "$file" "$output.xlsx" "medium"
done
