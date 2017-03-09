

# Configure go mpin wrapper
configure_file (
  "${PROJECT_SOURCE_DIR}/wrappers/go/rsa.go.in"
  "${PROJECT_BINARY_DIR}/wrappers/go/rsa.go"
)

if(BUILD_MPIN)
  # Configure go mpin wrapper
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/mpin.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/mpin.go"
  )
endif(BUILD_MPIN)

file(COPY rsa_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go/")

#add_test(NAME test_golang_rsa COMMAND go test -race -v)
#set_tests_properties (test_golang_rsa PROPERTIES PASS_REGULAR_EXPRESSION PASS)

if(BUILD_MPIN)
  file(COPY mpin_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go/")

  add_test(NAME test_golang COMMAND go test -race -v)
  set_tests_properties (test_golang PROPERTIES PASS_REGULAR_EXPRESSION PASS)
endif(BUILD_MPIN)

  INSTALL(DIRECTORY DESTINATION "${GO_PATH}/src/github.com" DIRECTORY_PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_WRITE GROUP_READ
          WORLD_WRITE WORLD_READ WORLD_EXECUTE)

  INSTALL(DIRECTORY DESTINATION "${GO_PATH}/src/github.com/miracl" DIRECTORY_PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_WRITE GROUP_READ
          WORLD_WRITE WORLD_READ WORLD_EXECUTE)

  INSTALL(DIRECTORY DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" DIRECTORY_PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_WRITE GROUP_READ
          WORLD_WRITE WORLD_READ WORLD_EXECUTE)

if(BUILD_MPIN)
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/mpin.go mpin_test.go  DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)
endif(BUILD_MPIN)

