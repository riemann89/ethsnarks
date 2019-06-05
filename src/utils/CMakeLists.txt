file(GLOB utils_sources "*.cpp")

foreach(util_path ${utils_sources})
	get_filename_component(util_name ${util_path} NAME)
	string(REPLACE ".cpp" "" util_exe ${util_name})
	add_executable(${util_exe} ${util_name})
	target_link_libraries(${util_exe} ethsnarks_common)
endforeach()

target_link_libraries(mimc Boost::program_options SHA3IUF)
target_link_libraries(mimc_hash_test_cases Boost::program_options SHA3IUF)
