Pod::Spec.new do |spec|
  spec.name = "KpqC"
  spec.version = "0.1.0"
  spec.summary = "Swift APIs for AIMer, HAETAE, NTRU+, and SMAUG-T."
  spec.description = <<-DESC
    Synchronous Swift bindings for the bundled AIMer and HAETAE signature
    schemes and NTRU+ and SMAUG-T key-encapsulation mechanisms.
  DESC
  spec.homepage = "https://github.com/osuolfou/kpqc-swift"
  spec.license = { type: "MIT", file: "LICENSE" }
  spec.author = { "osuolfou" => "osuolfou@naver.com" }
  spec.source = {
    git: "https://github.com/osuolfou/kpqc-swift.git",
    tag: "v#{spec.version}"
  }

  spec.module_name = "KpqC"
  spec.swift_versions = ["5.8"]
  spec.ios.deployment_target = "13.0"
  spec.osx.deployment_target = "10.15"
  spec.tvos.deployment_target = "13.0"
  spec.watchos.deployment_target = "6.0"

  spec.source_files = [
    "Sources/KpqC/**/*.swift",
    "Sources/KpqCCore/Generated/**/*.c",
    "native/csrc/secure_zero.c",
    "Sources/KpqCCore/include/KpqCCore.h"
  ]
  spec.public_header_files = "Sources/KpqCCore/include/KpqCCore.h"
  spec.preserve_paths = [
    "Sources/KpqCCore/Generated/**/*.h",
    "native/csrc/*",
    "THIRD_PARTY_NOTICES.md",
    "scripts/generate_native_sources.rb",
    "vendor/**/*"
  ]
  spec.compiler_flags = "-O2 -fvisibility=hidden -fno-strict-aliasing -w"
  spec.pod_target_xcconfig = {
    "CLANG_C_LANGUAGE_STANDARD" => "c11",
    "HEADER_SEARCH_PATHS" => "$(inherited) \"$(PODS_TARGET_SRCROOT)\""
  }

  spec.test_spec "Tests" do |test_spec|
    test_spec.source_files = "Tests/KpqCTests/*.swift"
  end
end
