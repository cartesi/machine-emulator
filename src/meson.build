project('machine-emulator', 'c', 'cpp')

deps = [
  dependency('nlohmann_json', required: true),
  dependency('protobuf', required: true)]

protoc = generator(find_program('protoc', required : true),
  output : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
  arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/../lib/grpc-interfaces', '--cpp_out=@BUILD_DIR@', '@INPUT@'])

libcartesi_sources = [
  'pma-driver.cpp',
  'clint.cpp',
  'clint-factory.cpp',
  'dtb.cpp',
  'os.cpp',
  'htif.cpp',
  'htif-factory.cpp',
  'shadow-state.cpp',
  'shadow-state-factory.cpp',
  'shadow-pmas.cpp',
  'shadow-pmas-factory.cpp',
  'shadow-tlb.cpp',
  'shadow-tlb-factory.cpp',
  'shadow-uarch-state.cpp',
  'shadow-uarch-state-factory.cpp',
  'pma.cpp',
  'machine.cpp',
  'machine-config.cpp',
  'json-util.cpp',
  'base64.cpp',
  'interpret.cpp',
  'virtual-machine.cpp',
  'uarch-machine.cpp',
  'uarch-step.cpp',
  'uarch-reset-state.cpp',
  '../third-party/tiny_sha3/sha3.c',
  'machine-merkle-tree.cpp',
  'pristine-merkle-tree.cpp',
  'uarch-interpret.cpp',
  'machine-c-api.cpp',
  'uarch-pristine-ram.c',
  'uarch-pristine-state-hash.cpp',
  '../uarch/uarch-pristine-hash.c',
  ]

libcartesi = library('cartesi',
  libcartesi_sources,
  dependencies: deps,
  include_directories: [
    '../third-party/tiny_sha3',
    '../third-party/llvm-flang-uint128',
    ],
  version: '1.2.3', soversion: '1',
  install : true,
  )

data = configuration_data()
data.set('jsonrpc-discover', import('fs').read('jsonrpc-discover.json').strip())
configure_file(
  input: 'jsonrpc-discover.cpp.in',
  output: 'jsonrpc-discover.cpp',
  configuration: data)

mongoose = dependency('mongoose', required: true, static: true)
jsonrpc_remote_cartesi_machine_sources = [
  'jsonrpc-remote-machine.cpp',
  'jsonrpc-discover.cpp',
  'slog.cpp',
  'uarch-pristine-ram.c',
  'uarch-pristine-state-hash.cpp',
  '../uarch/uarch-pristine-hash.c',
  ]

jsonrpc_remote_cartesi_machine = executable('jsonrpc-remote-cartesi-machine',
  jsonrpc_remote_cartesi_machine_sources,
  dependencies: mongoose,
  include_directories: [
    '../third-party/tiny_sha3',
    ],
  link_with: libcartesi,
  install: true)


grpc_files = [
  protoc.process('../lib/grpc-interfaces/versioning.proto'),
  protoc.process('../lib/grpc-interfaces/cartesi-machine.proto'),
  protoc.process('../lib/grpc-interfaces/cartesi-machine-checkin.proto'),
]
