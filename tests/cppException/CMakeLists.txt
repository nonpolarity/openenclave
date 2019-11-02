# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/cppException cppException_host cppException_enc)
set_tests_properties(tests/cppException PROPERTIES SKIP_RETURN_CODE 2)
