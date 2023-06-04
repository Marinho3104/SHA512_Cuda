
root_path := ./../
own_path := ./

nvcc := nvcc

flags := -rdc=true
disable_warning_about_void_operations := -diag-suppress 1143

all:

	# Copies the main file into root root_path
	cp $(root_path)*.cuh $(own_path) 

	# Compile
	$(nvcc) $(flags) $(disable_warning_about_void_operations) *.cu

	#Remove .cuh file
	rm *.cuh
