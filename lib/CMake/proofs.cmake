add_compile_definitions(OPENSSL_SUPPRESS_DEPRECATED=1)

# No GTest or Benchmark required here

macro(proofs_add_exec PROG)
    add_executable(${PROG} ${PROG}.cc ${ARGN})
    target_link_libraries(${PROG} ec)
    target_link_libraries(${PROG} algebra)
    target_link_libraries(${PROG} util)
endmacro()

macro(proofs_add_test PROG)
    # Keep original test macro if you want later tests
    add_executable(${PROG} ${PROG}.cc ${ARGN})
    target_link_libraries(${PROG} ec)
    target_link_libraries(${PROG} algebra)
    target_link_libraries(${PROG} util)
    # No linking to gtest or benchmark if you want to disable tests
    # proofs_add_testing_libraries(${PROG})
endmacro()

# For building tests, use proofs_add_test
# For building normal executables, use proofs_add_exec

