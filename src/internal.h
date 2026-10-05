#pragma once

#include "platform.h"
#include <atomic>

namespace hcd {

int dump_runtime(const Config& config, const std::atomic<bool>& cancelled);

} // namespace hcd
