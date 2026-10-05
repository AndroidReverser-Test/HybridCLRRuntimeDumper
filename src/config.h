#pragma once

#include "platform.h"

namespace hcd {

// Every target function/evidence RVA, hash and layout must be explicitly present.
bool load_config(const std::string& path, Config& config, std::string& error);

} // namespace hcd
