
# Configure go amcl wrapper
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/amcl.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/amcl.go"
  )

  # Configure go rsa wrapper
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/rsa.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/rsa.go"
  )


  # Configure go ecdsa wrapper
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/ecdsa.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/ecdsa.go"
  )

if(BUILD_MPIN)
if(USE_SIGNATURE)
  # Configure go mpin wrapper
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/mpin_kel.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/mpin.go"
  )
else(USE_SIGNATURE)
  configure_file (
    "${PROJECT_SOURCE_DIR}/wrappers/go/mpin.go.in"
    "${PROJECT_BINARY_DIR}/wrappers/go/mpin.go"
  )
endif(USE_SIGNATURE)
endif(BUILD_MPIN)

  file(COPY rsa_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go")
if(BUILD_MPIN)
if(USE_SIGNATURE)
  file(COPY mpin_kel_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go")
else(USE_SIGNATURE)
  file(COPY mpin_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go")
endif(USE_SIGNATURE)
endif(BUILD_MPIN)
  file(COPY ecdsa_test.go DESTINATION "${PROJECT_BINARY_DIR}/wrappers/go")

  add_test(NAME test_golang_wrappers COMMAND go test -race -v)
  set_tests_properties (test_golang_wrappers PROPERTIES PASS_REGULAR_EXPRESSION PASS)

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

  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/amcl.go DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)

   INSTALL(FILES ${PROJECT_BINARY_DIR}/wrappers/go/rsa.go rsa_test.go DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)

	INSTALL(FILES ${PROJECT_BINARY_DIR}/wrappers/go/ecdsa.go ecdsa_test.go DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
	  OWNER_WRITE OWNER_READ OWNER_EXECUTE
	  GROUP_READ GROUP_EXECUTE
	  WORLD_READ WORLD_EXECUTE)

if(BUILD_MPIN)
if(USE_SIGNATURE)
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/mpin.go mpin_kel_test.go DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)
else(USE_SIGNATURE)
  INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/mpin.go mpin_test.go DESTINATION "${GO_PATH}/src/github.com/miracl/amcl-go-wrapper" PERMISSIONS
          OWNER_WRITE OWNER_READ OWNER_EXECUTE
          GROUP_READ GROUP_EXECUTE
          WORLD_READ WORLD_EXECUTE)
endif(USE_SIGNATURE)
endif(BUILD_MPIN)



