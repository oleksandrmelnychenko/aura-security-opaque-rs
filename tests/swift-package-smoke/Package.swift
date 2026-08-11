// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraOPAQUESmoke",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(name: "AuraOPAQUE", path: "../..")
    ],
    targets: [
        .executableTarget(
            name: "AuraOPAQUESmoke",
            dependencies: [
                .product(name: "AuraOPAQUE", package: "AuraOPAQUE")
            ]
        )
    ]
)
