# SPDX-License-Identifier: LicenseRef-Proprietary
add_executable(g5c-inspect inspect.c)
target_link_libraries(g5c-inspect g5c_nas g5c_ngap g5c_udm g5c_pcf g5c_smf g5c_amf g5c_nrf g5c_ausf g5c_udr)
