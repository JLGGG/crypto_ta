project (optee_example_crypto_ta C)

file(GLOB SRCS CONFIGURE_DEPENDS "*.c" "${CMAKE_CURRENT_SOURCE_DIR}/host/*.c")

add_executable (${PROJECT_NAME} ${SRCS})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
