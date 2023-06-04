
root_path := ./../
own_path := ./

output_path := $(own_path)output/
src_path := $(root_path)src/

output_file_name := output.out

nvcc := nvcc
flags := -rdc=true
disable_warning_about_void_operations := -diag-suppress 1143

all:

	# Creates output directory if it does not exists
	mkdir output

	# Copies the main file into output path
	cp $(src_path)*.cuh $(src_path)*.cu $(output_path) 

	# Copies example file into output path
	cp $(own_path)*.cu $(output_path) 

	# Compile
	$(nvcc) $(flags) $(disable_warning_about_void_operations) $(output_path)*.cu -o $(output_file_name)

	#Remove .cuh file
	rm $(output_path)*

	# Move output file into output directory
	mv $(output_file_name) $(output_path)
