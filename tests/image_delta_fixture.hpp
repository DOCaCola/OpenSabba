#pragma once
#include "opensabba/image.hpp"
namespace opensabba {
DeltaPlan snapshot_delta_plan(std::uint64_t,std::span<const ChangedExtent>);
DeltaPlan image_delta_plan(ImageSource&,ImageSource&,const std::function<bool()>& cancelled = {});
}
