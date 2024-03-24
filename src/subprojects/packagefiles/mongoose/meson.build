project('mongoose', 'c', default_options: {'default_library': 'both'})

mongoose_inc = include_directories('.')
mongoose_lib = library('mongoose', ['mongoose.c', 'mongoose.h'], install: true)
install_headers('mongoose.h', subdir: 'mongoose')

mongoose_dep = declare_dependency(
  include_directories: mongoose_inc,
  link_with: mongoose_lib)
