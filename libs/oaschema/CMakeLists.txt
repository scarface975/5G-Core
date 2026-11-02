# SPDX-License-Identifier: LicenseRef-Proprietary
add_library(g5c_oaschema STATIC src/oaschema.c)
target_include_directories(g5c_oaschema PUBLIC include)
target_link_libraries(g5c_oaschema PUBLIC g5c_base)
