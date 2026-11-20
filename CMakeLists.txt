cmake_minimum_required(VERSION 3.20)
project(OpenSabba VERSION 1.0.0 LANGUAGES CXX)

add_library(opensabba_protocol src/pstream.cpp)
target_include_directories(opensabba_protocol PUBLIC include)
target_compile_features(opensabba_protocol PUBLIC cxx_std_20)
set_target_properties(opensabba_protocol PROPERTIES CXX_EXTENSIONS OFF)
if(MSVC)
  target_compile_options(opensabba_protocol PRIVATE /W4 /permissive-)
else()
  target_compile_options(opensabba_protocol PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_executable(opensabba src/main.cpp src/cli.cpp)
target_compile_definitions(opensabba PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
find_package(Threads REQUIRED)
target_link_libraries(opensabba PRIVATE Threads::Threads)
set_target_properties(opensabba PROPERTIES SKIP_BUILD_RPATH TRUE)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
find_path(LZ4_INCLUDE_DIR NAMES lz4.h REQUIRED)
find_library(LZ4_LIBRARY NAMES lz4 REQUIRED)
add_library(LZ4::LZ4 UNKNOWN IMPORTED)
set_target_properties(LZ4::LZ4 PROPERTIES
  IMPORTED_LOCATION "${LZ4_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${LZ4_INCLUDE_DIR}")
add_library(opensabba_client src/client.cpp src/ntlm.cpp src/events.cpp src/image.cpp src/layout.cpp src/snapshot.cpp src/filesystem.cpp src/snapshot_driver.cpp src/cow_index.cpp src/delta_plan.cpp src/backup_job.cpp src/backup_resume.cpp src/job_recovery.cpp src/service_backup.cpp src/source_read.cpp src/bad_cluster.cpp src/registration.cpp)
target_sources(opensabba_client PRIVATE src/machine.cpp src/machine_inventory.cpp src/lvm.cpp src/volume_nodes.cpp src/capture.cpp src/machine_capture.cpp src/machine_artifact.cpp src/machine_snapshot.cpp src/service_machine_capture.cpp src/machine_tracking.cpp src/task_policy.cpp)
target_sources(opensabba_client PRIVATE src/tracking_record.cpp src/tracking_record_store.cpp)
target_sources(opensabba_client PRIVATE src/diagnostics.cpp)
target_sources(opensabba_client PRIVATE src/filesystem_allocation.cpp)
target_sources(opensabba_client PRIVATE src/historical_logs.cpp src/log_export.cpp)
target_compile_definitions(opensabba_client PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
target_sources(opensabba_client PRIVATE src/bandwidth.cpp src/server_time.cpp)
target_sources(opensabba_client PRIVATE src/service_status.cpp src/service_process.cpp)
target_sources(opensabba_client PRIVATE src/file_restore_job.cpp)
target_sources(opensabba_client PRIVATE src/backup_scripts.cpp src/display.cpp)
target_sources(opensabba_client PRIVATE src/certificate_trust.cpp)
target_sources(opensabba_client PRIVATE src/agent_config.cpp)
target_sources(opensabba_client PRIVATE src/device_info.cpp)
target_sources(opensabba_client PRIVATE src/backup_cache.cpp src/task_schedule.cpp src/service_observations.cpp)
target_link_libraries(opensabba_client PRIVATE Threads::Threads)
target_link_libraries(opensabba_client PUBLIC opensabba_protocol PRIVATE OpenSSL::SSL OpenSSL::Crypto LZ4::LZ4)
if(WIN32)
  target_link_libraries(opensabba_client PRIVATE ws2_32)
endif()
if(MSVC)
  target_compile_options(opensabba_client PRIVATE /W4 /permissive-)
else()
  target_compile_options(opensabba_client PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()
add_library(opensabba_session STATIC src/session.cpp)
target_compile_definitions(opensabba_session PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
target_link_libraries(opensabba_session PUBLIC opensabba_client PRIVATE OpenSSL::Crypto Threads::Threads)
target_link_libraries(opensabba PRIVATE opensabba_session)
include(CTest)
if(BUILD_TESTING)
  add_library(opensabba_lab_restore STATIC src/restore_job.cpp)
  target_link_libraries(opensabba_lab_restore PUBLIC opensabba_client PRIVATE OpenSSL::Crypto)
  add_library(opensabba_fixture_delta STATIC tests/image_delta_fixture.cpp)
  target_link_libraries(opensabba_fixture_delta PUBLIC opensabba_client)
  set(OPENSABBA_LAB_SOURCES tests/lab_main.cpp tests/lab_cli.cpp tests/lab_session.cpp
      tests/lab_connection.cpp tests/lab_capture.cpp tests/lab_image.cpp)
  add_executable(opensabba-lab ${OPENSABBA_LAB_SOURCES})
  target_compile_definitions(opensabba-lab PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
  target_link_libraries(opensabba-lab PRIVATE opensabba_session opensabba_lab_restore OpenSSL::Crypto Threads::Threads)
  add_executable(machine_inventory_tests tests/machine_inventory_tests.cpp)
  target_link_libraries(machine_inventory_tests PRIVATE opensabba_client)
  add_test(NAME machine_inventory COMMAND machine_inventory_tests)
  add_executable(registration_tests tests/registration_tests.cpp)
  target_link_libraries(registration_tests PRIVATE opensabba_client)
  add_test(NAME registration_prompt COMMAND registration_tests)
  add_executable(registration_restore_driver tests/registration_restore_driver.cpp)
  target_link_libraries(registration_restore_driver PRIVATE opensabba_client)
  add_executable(bad_cluster_tests tests/bad_cluster_tests.cpp)
  target_link_libraries(bad_cluster_tests PRIVATE opensabba_client)
  add_test(NAME bad_cluster COMMAND bad_cluster_tests)
  add_executable(source_read_tests tests/source_read_tests.cpp)
  target_link_libraries(source_read_tests PRIVATE opensabba_client)
  add_test(NAME source_read_policy COMMAND source_read_tests)
  add_executable(service_status_tests tests/service_status_tests.cpp)
  target_link_libraries(service_status_tests PRIVATE opensabba_client)
  add_test(NAME service_status COMMAND service_status_tests)
  add_executable(device_info_tests tests/device_info_tests.cpp)
  target_link_libraries(device_info_tests PRIVATE opensabba_client)
  add_test(NAME device_info COMMAND device_info_tests)
  add_executable(backup_cache_tests tests/backup_cache_tests.cpp)
  target_link_libraries(backup_cache_tests PRIVATE opensabba_client LZ4::LZ4)
  add_test(NAME backup_cache COMMAND backup_cache_tests)
  add_executable(task_schedule_tests tests/task_schedule_tests.cpp)
  target_link_libraries(task_schedule_tests PRIVATE opensabba_client)
  add_test(NAME task_schedule COMMAND task_schedule_tests)
  add_executable(agent_config_tests tests/agent_config_tests.cpp)
  target_link_libraries(agent_config_tests PRIVATE opensabba_client)
  add_test(NAME agent_config COMMAND agent_config_tests)
  add_executable(log_export_tests tests/log_export_tests.cpp)
  target_link_libraries(log_export_tests PRIVATE opensabba_client)
  add_test(NAME log_export_redaction COMMAND log_export_tests)
  add_executable(backup_scripts_tests tests/backup_scripts_tests.cpp)
  target_link_libraries(backup_scripts_tests PRIVATE opensabba_client)
  add_test(NAME backup_script_policy COMMAND backup_scripts_tests)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(log_export_driver tests/log_export_driver.cpp)
    target_link_libraries(log_export_driver PRIVATE opensabba_client)
    add_executable(backup_script_process_tests tests/backup_script_process_tests.cpp)
    target_link_libraries(backup_script_process_tests PRIVATE opensabba_client)
    add_test(NAME backup_script_process COMMAND backup_script_process_tests)
  endif()
  add_executable(protocol_tests tests/protocol_tests.cpp)
  target_link_libraries(protocol_tests PRIVATE opensabba_protocol)
  add_test(NAME protocol COMMAND protocol_tests)
  add_executable(event_tests tests/event_tests.cpp)
  target_link_libraries(event_tests PRIVATE opensabba_client)
  add_test(NAME events COMMAND event_tests)
  add_executable(directory_nodes_tests tests/directory_nodes_tests.cpp)
  target_link_libraries(directory_nodes_tests PRIVATE opensabba_client)
  add_test(NAME directory_nodes COMMAND directory_nodes_tests)
  add_executable(file_restore_tests tests/file_restore_tests.cpp)
  target_link_libraries(file_restore_tests PRIVATE opensabba_client)
  add_test(NAME file_restore_schema COMMAND file_restore_tests)
  add_executable(cow_index_tests tests/cow_index_tests.cpp)
  target_link_libraries(cow_index_tests PRIVATE opensabba_fixture_delta)
  add_test(NAME cow_index COMMAND cow_index_tests)
  add_executable(delta_plan_tests tests/delta_plan_tests.cpp)
  target_link_libraries(delta_plan_tests PRIVATE opensabba_fixture_delta)
  add_test(NAME delta_plan COMMAND delta_plan_tests)
  add_executable(unused_interval_tests tests/unused_interval_tests.cpp)
  target_link_libraries(unused_interval_tests PRIVATE opensabba_client)
  add_test(NAME unused_interval COMMAND unused_interval_tests)
  add_executable(machine_image_tests tests/machine_image_tests.cpp)
  target_link_libraries(machine_image_tests PRIVATE opensabba_fixture_delta LZ4::LZ4)
  add_test(NAME machine_image COMMAND machine_image_tests)
  add_executable(machine_plan_tests tests/machine_plan_tests.cpp)
  target_link_libraries(machine_plan_tests PRIVATE opensabba_client)
  add_test(NAME machine_plan COMMAND machine_plan_tests)
  add_executable(lvm_tests tests/lvm_tests.cpp)
  target_link_libraries(lvm_tests PRIVATE opensabba_client)
  add_test(NAME lvm COMMAND lvm_tests)
  add_executable(lvm_layout_tests tests/lvm_layout_tests.cpp)
  target_link_libraries(lvm_layout_tests PRIVATE opensabba_client)
  add_test(NAME lvm_layouts COMMAND lvm_layout_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/lvm-layouts")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(lvm_capture_probe tests/lvm_capture_probe.cpp)
    target_link_libraries(lvm_capture_probe PRIVATE opensabba_client)
  endif()
  add_executable(server_time_tests tests/server_time_tests.cpp)
  target_link_libraries(server_time_tests PRIVATE opensabba_client)
  add_test(NAME server_time_policy COMMAND server_time_tests)
  add_executable(capture_tests tests/capture_tests.cpp)
  target_link_libraries(capture_tests PRIVATE opensabba_client)
  add_test(NAME capture_transaction COMMAND capture_tests)
  add_executable(raw_cache_tests tests/raw_cache_tests.cpp)
  target_link_libraries(raw_cache_tests PRIVATE opensabba_client)
  add_test(NAME raw_cache COMMAND raw_cache_tests)
  add_executable(machine_artifact_tests tests/machine_artifact_tests.cpp)
  target_link_libraries(machine_artifact_tests PRIVATE opensabba_client)
  add_test(NAME machine_artifact COMMAND machine_artifact_tests)
  add_executable(machine_reservation_driver tests/machine_reservation_driver.cpp)
  target_link_libraries(machine_reservation_driver PRIVATE opensabba_client)
  add_executable(tracking_record_tests tests/tracking_record_tests.cpp)
  target_link_libraries(tracking_record_tests PRIVATE opensabba_client)
  add_test(NAME tracking_record COMMAND tracking_record_tests)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(tracking_record_store_tests tests/tracking_record_store_tests.cpp)
    target_link_libraries(tracking_record_store_tests PRIVATE opensabba_client)
    add_test(NAME tracking_record_store COMMAND tracking_record_store_tests)
    add_executable(machine_tracking_probe tests/machine_tracking_probe.cpp)
    target_link_libraries(machine_tracking_probe PRIVATE opensabba_client)
  endif()
  add_executable(task_policy_tests tests/task_policy_tests.cpp)
  target_link_libraries(task_policy_tests PRIVATE opensabba_client)
  add_test(NAME task_policy COMMAND task_policy_tests)
  add_executable(diagnostics_tests tests/diagnostics_tests.cpp src/display.cpp)
  target_link_libraries(diagnostics_tests PRIVATE opensabba_client)
  add_test(NAME diagnostics COMMAND diagnostics_tests)
  add_executable(bandwidth_tests tests/bandwidth_tests.cpp)
  target_link_libraries(bandwidth_tests PRIVATE opensabba_client)
  add_test(NAME bandwidth COMMAND bandwidth_tests)
  add_test(NAME cli_help COMMAND opensabba --help)
  add_executable(cli_tests tests/cli_tests.cpp src/cli.cpp)
  target_link_libraries(cli_tests PRIVATE opensabba_protocol)
  add_test(NAME official_cli COMMAND cli_tests)
  add_executable(certificate_trust_tests tests/certificate_trust_tests.cpp)
  target_link_libraries(certificate_trust_tests PRIVATE opensabba_client)
  add_test(NAME certificate_trust COMMAND certificate_trust_tests)
  find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
  add_test(NAME product_command_surface
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_product_surface.py" "$<TARGET_FILE:opensabba>")
  set_tests_properties(product_command_surface PROPERTIES TIMEOUT 30)
  add_test(NAME upload_timing
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_upload_timing.py")
  add_test(NAME system_service_unit
    COMMAND "${Python3_EXECUTABLE}" -X utf8 "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_system_service_unit.py")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(service_process_driver tests/service_process_driver.cpp)
    target_link_libraries(service_process_driver PRIVATE opensabba_client)
    add_test(NAME service_daemon_process
      COMMAND "${Python3_EXECUTABLE}" -X utf8 "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_process.py"
        "$<TARGET_FILE:service_process_driver>")
    set_tests_properties(service_daemon_process PROPERTIES TIMEOUT 30)
  endif()
  find_program(OPENSABBA_TEST_SHELL NAMES sh HINTS "C:/msys64/usr/bin" REQUIRED)
  add_test(NAME initramfs_premount
    COMMAND "${Python3_EXECUTABLE}" -X utf8 "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_initramfs_premount.py"
      "${OPENSABBA_TEST_SHELL}")
  set_tests_properties(initramfs_premount PROPERTIES TIMEOUT 30)
  add_test(NAME proxy_peer_cancellation
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_proxy_peer.py")
  set_tests_properties(proxy_peer_cancellation PROPERTIES TIMEOUT 15)
  add_test(NAME machine_reservation_recovery
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_machine_reservation_recovery.py"
      "$<TARGET_FILE:machine_reservation_driver>")
  set_tests_properties(machine_reservation_recovery PROPERTIES TIMEOUT 30)
  add_test(NAME snapshot_read_oracle
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_snapshot_read_oracle.py")

  add_test(NAME diagnostic_zip_format
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_diagnostic_zip.py"
      "$<TARGET_FILE:log_export_tests>")
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME log_export_archive
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_log_export.py"
        "$<TARGET_FILE:log_export_driver>")
    set_tests_properties(log_export_archive PROPERTIES TIMEOUT 30)
  endif()
  find_program(OPENSSL_EXECUTABLE openssl REQUIRED)
  add_executable(interval_transfer_driver tests/interval_transfer_driver.cpp)
  target_link_libraries(interval_transfer_driver PRIVATE opensabba_client)
  add_test(NAME machine_interval_transfer
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_interval_transfer.py"
      "$<TARGET_FILE:interval_transfer_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(machine_interval_transfer PROPERTIES TIMEOUT 90)
  add_executable(backup_cache_driver tests/backup_cache_driver.cpp)
  target_link_libraries(backup_cache_driver PRIVATE opensabba_client)
  add_test(NAME backup_cache_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_cache.py"
      "$<TARGET_FILE:backup_cache_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(backup_cache_integration PROPERTIES TIMEOUT 120)
  add_executable(backup_transport_driver tests/backup_transport_driver.cpp)
  target_link_libraries(backup_transport_driver PRIVATE opensabba_client)
  add_test(NAME backup_transport_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_transport.py"
      "$<TARGET_FILE:backup_transport_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(backup_transport_integration PROPERTIES TIMEOUT 90)
  add_executable(certificate_probe tests/certificate_probe.cpp)
  target_link_libraries(certificate_probe PRIVATE opensabba_client)
  add_test(NAME certificate_transport
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_certificate_transport.py"
      "$<TARGET_FILE:certificate_probe>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(certificate_transport PROPERTIES TIMEOUT 90)
  add_executable(server_time_driver tests/server_time_driver.cpp)
  target_link_libraries(server_time_driver PRIVATE opensabba_client)
  add_test(NAME server_time_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_server_time.py"
      "$<TARGET_FILE:server_time_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(server_time_integration PROPERTIES TIMEOUT 60)
  add_executable(backup_scripts_driver tests/backup_scripts_driver.cpp)
  target_link_libraries(backup_scripts_driver PRIVATE opensabba_client)
  add_test(NAME backup_scripts_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_scripts.py"
      "$<TARGET_FILE:backup_scripts_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(backup_scripts_integration PROPERTIES TIMEOUT 120)
  add_executable(service_idle_driver tests/service_idle_driver.cpp)
  target_link_libraries(service_idle_driver PRIVATE opensabba_client)
  add_test(NAME service_idle_budget
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_idle.py"
      "$<TARGET_FILE:service_idle_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(service_idle_budget PROPERTIES TIMEOUT 45)
  foreach(ALIVE_VALUE IN ITEMS 0 1)
    add_test(NAME service_idle_alive_${ALIVE_VALUE}
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_idle.py"
        "$<TARGET_FILE:service_idle_driver>" "${OPENSSL_EXECUTABLE}" --alive ${ALIVE_VALUE})
    set_tests_properties(service_idle_alive_${ALIVE_VALUE} PROPERTIES TIMEOUT 45)
  endforeach()
  add_executable(schedule_service_driver tests/schedule_service_driver.cpp)
  target_link_libraries(schedule_service_driver PRIVATE opensabba_client)
  add_test(NAME schedule_service_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_schedule_service.py"
      "$<TARGET_FILE:schedule_service_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(schedule_service_integration PROPERTIES TIMEOUT 60)
  add_executable(service_recovery_driver tests/service_recovery_driver.cpp)
  target_link_libraries(service_recovery_driver PRIVATE opensabba_client)
  add_test(NAME service_recovery_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_recovery.py"
      "$<TARGET_FILE:service_recovery_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(service_recovery_integration PROPERTIES TIMEOUT 90)
  add_test(NAME source_read_service_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_recovery.py"
      "$<TARGET_FILE:service_recovery_driver>" "${OPENSSL_EXECUTABLE}" --source-reads)
  set_tests_properties(source_read_service_integration PROPERTIES TIMEOUT 90)
  add_executable(task_result_driver tests/task_result_driver.cpp)
  target_link_libraries(task_result_driver PRIVATE opensabba_client)
  add_test(NAME task_result_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_task_result.py"
      "$<TARGET_FILE:task_result_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(task_result_integration PROPERTIES TIMEOUT 60)
  add_executable(file_restore_driver tests/file_restore_driver.cpp)
  target_link_libraries(file_restore_driver PRIVATE opensabba_client)
  if(WIN32)
    target_compile_definitions(file_restore_driver PRIVATE _WIN32_WINNT=0x0A00 NTDDI_VERSION=0x0A000002)
  endif()
  add_test(NAME file_restore_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_restore.py"
      "$<TARGET_FILE:file_restore_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(file_restore_integration PROPERTIES TIMEOUT 120)
  add_test(NAME file_restore_ack_cadence
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_restore.py"
      "$<TARGET_FILE:file_restore_driver>" "${OPENSSL_EXECUTABLE}" --ack-cadence)
  set_tests_properties(file_restore_ack_cadence PROPERTIES TIMEOUT 45)
  add_test(NAME file_restore_restart
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_restore.py"
      "$<TARGET_FILE:file_restore_driver>" "${OPENSSL_EXECUTABLE}" --restart)
  set_tests_properties(file_restore_restart PROPERTIES TIMEOUT 45)
  add_executable(machine_queue_driver tests/machine_queue_driver.cpp)
  target_link_libraries(machine_queue_driver PRIVATE opensabba_fixture_delta OpenSSL::Crypto)
  add_test(NAME single_unused_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_single_unused.py"
      "$<TARGET_FILE:machine_queue_driver>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(single_unused_integration PROPERTIES TIMEOUT 60)
  add_test(NAME probe_integration
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_probe.py"
      "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
  set_tests_properties(probe_integration PROPERTIES TIMEOUT 60)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME operational_cli_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_operational_cli.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(operational_cli_integration PROPERTIES TIMEOUT 120)
    add_test(NAME cli_certificate_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_certificate.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(cli_certificate_integration PROPERTIES TIMEOUT 90)
    add_test(NAME file_restore_metadata_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_restore.py"
        "$<TARGET_FILE:file_restore_driver>" "${OPENSSL_EXECUTABLE}" --metadata)
    set_tests_properties(file_restore_metadata_integration PROPERTIES TIMEOUT 45)
    add_test(NAME file_restore_official_filesystem_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_file_restore_filesystem.py"
        "$<TARGET_FILE:file_restore_driver>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(file_restore_official_filesystem_integration PROPERTIES TIMEOUT 60)
    # These fixtures drive the client through a pty and require POSIX termios.
    add_test(NAME machine_queue_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_machine_queue.py"
        "$<TARGET_FILE:machine_queue_driver>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(machine_queue_integration PROPERTIES TIMEOUT 60)
    add_test(NAME diagnostics_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_diagnostics.py"
        "$<TARGET_FILE:opensabba-lab>")
    set_tests_properties(diagnostics_integration PROPERTIES TIMEOUT 180)
    # Exercise native libc ioctl layouts with the target's GNU-compatible linker.
    # Zig's cross-link driver does not implement --wrap; run this test natively.
    if(NOT CMAKE_CROSSCOMPILING)
      add_executable(snapshot_driver_tests tests/snapshot_driver_tests.cpp)
      target_link_libraries(snapshot_driver_tests PRIVATE opensabba_client)
      target_link_options(snapshot_driver_tests PRIVATE
        -Wl,--wrap=open -Wl,--wrap=open64 -Wl,--wrap=close -Wl,--wrap=fstat -Wl,--wrap=flock -Wl,--wrap=ioctl
        -Wl,--wrap=stat -Wl,--wrap=umount)
      add_test(NAME snapshot_driver COMMAND snapshot_driver_tests)
      add_executable(filesystem_origin_probe tests/filesystem_origin_probe.cpp)
      target_link_libraries(filesystem_origin_probe PRIVATE opensabba_client)
      add_executable(ntlm_vectors tests/ntlm_vectors.cpp)
      target_link_libraries(ntlm_vectors PRIVATE opensabba_client)
      target_link_options(ntlm_vectors PRIVATE -Wl,--wrap=RAND_bytes)
      add_test(NAME ntlm_vectors COMMAND ntlm_vectors)
    endif()
    add_test(NAME backup_resume_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_resume.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(backup_resume_integration PROPERTIES TIMEOUT 180)
    add_test(NAME restore_resume_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_restore_resume.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(restore_resume_integration PROPERTIES TIMEOUT 180)
    add_test(NAME job_recovery_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_job_recovery.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(job_recovery_integration PROPERTIES TIMEOUT 120)
    add_test(NAME restore_cli_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_restore_cli.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(restore_cli_integration PROPERTIES TIMEOUT 120)
    add_test(NAME restore_catalog_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_restore_catalog.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(restore_catalog_integration PROPERTIES TIMEOUT 60)

    add_test(NAME lvm_kernel_layouts
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_lvm_kernel_layouts.py"
        "$<TARGET_FILE:lvm_layout_tests>")
    set_tests_properties(lvm_kernel_layouts PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77 RUN_SERIAL TRUE)

    add_test(NAME snapshot_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_snapshot.py"
        "$<TARGET_FILE:opensabba-lab>")
    set_tests_properties(snapshot_integration PROPERTIES TIMEOUT 60)
    add_test(NAME filesystem_formats_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_filesystem_formats.py"
        "$<TARGET_FILE:opensabba-lab>" "$<TARGET_FILE:machine_image_tests>")
    set_tests_properties(filesystem_formats_integration PROPERTIES TIMEOUT 120)
    add_test(NAME backup_cli_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_cli.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(backup_cli_integration PROPERTIES TIMEOUT 120)
    add_test(NAME layout_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_layout.py"
        "$<TARGET_FILE:opensabba-lab>")
    set_tests_properties(layout_integration PROPERTIES TIMEOUT 30)
    add_executable(backup_control_driver tests/backup_control_driver.cpp)
    target_link_libraries(backup_control_driver PRIVATE opensabba_client)
    add_test(NAME service_cancellation_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_cancellation.py"
        "$<TARGET_FILE:backup_control_driver>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(service_cancellation_integration PROPERTIES TIMEOUT 180)
    add_test(NAME backup_control_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_control.py"
        "$<TARGET_FILE:backup_control_driver>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(backup_control_integration PROPERTIES TIMEOUT 90)
    add_executable(image_transfer_driver tests/image_transfer_driver.cpp)
    target_link_libraries(image_transfer_driver PRIVATE opensabba_client)
    add_test(NAME image_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_image.py"
        "$<TARGET_FILE:opensabba-lab>" "$<TARGET_FILE:image_transfer_driver>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(image_integration PROPERTIES TIMEOUT 90)
    add_test(NAME login_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_login.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(login_integration PROPERTIES TIMEOUT 90)
    add_test(NAME registration_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_registration.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:registration_restore_driver>")
    set_tests_properties(registration_integration PROPERTIES TIMEOUT 90)
    add_test(NAME service_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(service_integration PROPERTIES TIMEOUT 90)
    # The service and all event/catalog/transfer code are identical to the CLI.
    # Only topology discovery and physical acquisition use deterministic OS specimens.
    add_executable(service_machine_fixture ${OPENSABBA_LAB_SOURCES} tests/service_machine_capture_fixture.cpp)
    target_compile_definitions(service_machine_fixture PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
    target_link_libraries(service_machine_fixture PRIVATE opensabba_session opensabba_lab_restore OpenSSL::Crypto Threads::Threads)
    set_target_properties(service_machine_fixture PROPERTIES SKIP_BUILD_RPATH TRUE)
    add_executable(service_network_fixture ${OPENSABBA_LAB_SOURCES} tests/service_network_capture_fixture.cpp)
    target_compile_definitions(service_network_fixture PRIVATE OPENSABBA_VERSION="${PROJECT_VERSION}")
    target_link_libraries(service_network_fixture PRIVATE opensabba_session opensabba_lab_restore OpenSSL::Crypto Threads::Threads)
    set_target_properties(service_network_fixture PROPERTIES SKIP_BUILD_RPATH TRUE)
    add_library(snapshot_source_fixture SHARED tests/snapshot_source_fixture.cpp)
    target_compile_features(snapshot_source_fixture PRIVATE cxx_std_20)
    target_link_libraries(snapshot_source_fixture PRIVATE ${CMAKE_DL_LIBS})
    add_executable(snapshot_metadata_probe tests/snapshot_metadata_probe.cpp)
    target_link_libraries(snapshot_metadata_probe PRIVATE opensabba_client)
    add_test(NAME snapshot_metadata_routing
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_snapshot_metadata_routing.py"
        "$<TARGET_FILE:snapshot_metadata_probe>" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(snapshot_metadata_routing PROPERTIES TIMEOUT 45)
    add_test(NAME snapshot_read_errors_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_snapshot_read_errors.py"
        "$<TARGET_FILE:service_recovery_driver>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(snapshot_read_errors_integration PROPERTIES TIMEOUT 90)
    add_test(NAME machine_pending_recovery_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_machine_pending_recovery.py"
        "$<TARGET_FILE:opensabba-lab>" "$<TARGET_FILE:machine_reservation_driver>"
        "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(machine_pending_recovery_integration PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME machine_startup_recovery_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_machine_startup_recovery.py"
        "$<TARGET_FILE:opensabba-lab>" "$<TARGET_FILE:machine_reservation_driver>"
        "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(machine_startup_recovery_integration PROPERTIES TIMEOUT 90
      RESOURCE_LOCK machine_service_fixture_images)
    add_executable(raw_cache_source_probe tests/raw_cache_source_probe.cpp)
    target_link_libraries(raw_cache_source_probe PRIVATE opensabba_client LZ4::LZ4)
    add_test(NAME raw_cache_sources
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_raw_cache_sources.py"
        "$<TARGET_FILE:raw_cache_source_probe>" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(raw_cache_sources PROPERTIES TIMEOUT 60)
    add_test(NAME service_interval_parity_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_interval_parity.py"
        "$<TARGET_FILE:service_machine_fixture>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(service_interval_parity_integration PROPERTIES TIMEOUT 180
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME service_active_restore_events
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_active_events.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(service_active_restore_events PROPERTIES TIMEOUT 90)
    add_test(NAME service_active_backup_events
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_reload_transfer.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>" active-events)
    set_tests_properties(service_active_backup_events PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME service_multi_image_visible_progress
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_reload_transfer.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>" active-events multi progress)
    set_tests_properties(service_multi_image_visible_progress PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME service_source_read_failure
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_reload_transfer.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>" source-error multi)
    set_tests_properties(service_source_read_failure PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME service_policy_transition_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_policy_transition.py"
        "$<TARGET_FILE:service_machine_fixture>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(service_policy_transition_integration PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    add_test(NAME service_lvm_inventory_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_lvm_inventory.py"
        "$<TARGET_FILE:service_machine_fixture>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>")
    set_tests_properties(service_lvm_inventory_integration PROPERTIES TIMEOUT 120
      RESOURCE_LOCK machine_service_fixture_images)
    foreach(scenario IN ITEMS reload_transfer single_incremental multi_disk multi_incremental omitted_base
                              lvm_incremental lvm_root logout_transfer proxy_transfer proxy_logout_transfer)
      set(scenario_args)
      if(scenario STREQUAL single_incremental)
        set(scenario_args single-incremental)
      elseif(scenario STREQUAL multi_disk)
        set(scenario_args multi)
      elseif(scenario STREQUAL multi_incremental)
        set(scenario_args multi-incremental)
      elseif(scenario STREQUAL omitted_base)
        set(scenario_args multi-incremental omitted-base)
      elseif(scenario STREQUAL lvm_incremental)
        set(scenario_args lvm-incremental)
      elseif(scenario STREQUAL lvm_root)
        set(scenario_args lvm-root)
      elseif(scenario STREQUAL logout_transfer)
        set(scenario_args logout)
      elseif(scenario STREQUAL proxy_transfer)
        set(scenario_args proxy)
      elseif(scenario STREQUAL proxy_logout_transfer)
        set(scenario_args proxy logout)
      endif()
      if(scenario MATCHES "^proxy")
        set(scenario_name ${scenario}_integration)
      else()
        set(scenario_name service_${scenario}_integration)
      endif()
      set(scenario_executable opensabba-lab)
      if(scenario MATCHES "^(single_incremental|multi_incremental|omitted_base|lvm_incremental|lvm_root)$")
        set(scenario_executable service_machine_fixture)
      endif()
      add_test(NAME ${scenario_name}
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_reload_transfer.py"
          "$<TARGET_FILE:${scenario_executable}>" "${OPENSSL_EXECUTABLE}" "$<TARGET_FILE:snapshot_source_fixture>" ${scenario_args})
      set_tests_properties(${scenario_name} PROPERTIES TIMEOUT 120)
      # Each multi-volume Python specimen retains several full image copies.
      # Serialize this memory-heavy group on the disposable lab VM, while
      # allowing the rest of the suite to continue running concurrently.
      if(scenario MATCHES "^(multi_incremental|omitted_base|lvm_incremental|lvm_root)$")
        set_tests_properties(${scenario_name} PROPERTIES RESOURCE_LOCK machine_service_fixture_images)
      endif()
    endforeach()
    add_test(NAME sealed_machine_capture_refusal
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_sealed_capture_refusal.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(sealed_machine_capture_refusal PROPERTIES TIMEOUT 30)
    add_test(NAME logout_timeout_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_logout_timeout.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(logout_timeout_integration PROPERTIES TIMEOUT 45)
    add_test(NAME proxy_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_proxy.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(proxy_integration PROPERTIES TIMEOUT 45)
    add_test(NAME ntlm_proxy_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_ntlm_proxy.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(ntlm_proxy_integration PROPERTIES TIMEOUT 90)
    add_test(NAME proxy_backup_resume_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_backup_resume.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" --proxy)
    add_test(NAME proxy_restore_resume_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_restore_resume.py"
        "$<TARGET_FILE:opensabba-lab>" "${OPENSSL_EXECUTABLE}" --proxy)
    set_tests_properties(proxy_backup_resume_integration proxy_restore_resume_integration PROPERTIES TIMEOUT 120)
    add_test(NAME service_idle_native_gate
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_service_idle.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}" --service)
    set_tests_properties(service_idle_native_gate PROPERTIES TIMEOUT 45)
    add_test(NAME event_integration
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_events.py"
        "$<TARGET_FILE:service_network_fixture>" "${OPENSSL_EXECUTABLE}")
    set_tests_properties(event_integration PROPERTIES TIMEOUT 90)
  endif()
endif()
include(GNUInstallDirs)
install(TARGETS opensabba RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES README.md LICENSE DESTINATION share/doc/opensabba)
install(DIRECTORY LICENSES DESTINATION share/doc/opensabba)
install(DIRECTORY docs DESTINATION share/doc/opensabba)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  configure_file(packaging/initramfs/opensabba-hook.in
    packaging/initramfs/opensabba-hook @ONLY NEWLINE_STYLE UNIX)
  install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/packaging/initramfs/opensabba-hook"
    DESTINATION share/initramfs-tools/hooks RENAME opensabba)
  install(PROGRAMS packaging/initramfs/opensabba-premount
    DESTINATION share/initramfs-tools/scripts/init-premount RENAME opensabba)
  configure_file(packaging/system/opensabba.service.in
    packaging/system/opensabba.service @ONLY NEWLINE_STYLE UNIX)
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/packaging/system/opensabba.service"
    packaging/system/opensabba-driver.service
    DESTINATION lib/systemd/system)
  install(PROGRAMS packaging/system/opensabba.shutdown
    DESTINATION lib/systemd/system-shutdown)
  set(CPACK_GENERATOR DEB)
  set(CPACK_PACKAGE_NAME opensabba)
  set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
  set(CPACK_PACKAGE_CONTACT "OpenSabba contributors")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Experimental Active Backup for Business command-line client")
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  # External runtime tools are not discovered by dpkg-shlibdeps.
  set(CPACK_DEBIAN_PACKAGE_DEPENDS "util-linux, kmod")
  set(CPACK_DEBIAN_PACKAGE_SUGGESTS "lvm2, initramfs-tools")
  configure_file(packaging/debian/postinst.in
    packaging/debian/postinst @ONLY NEWLINE_STYLE UNIX)
  set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/preinst"
    "${CMAKE_CURRENT_BINARY_DIR}/packaging/debian/postinst"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/prerm"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/postrm"
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/debian/triggers")
  set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)
  include(CPack)
endif()
