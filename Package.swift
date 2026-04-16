// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraOPAQUE",
    platforms: [
        .iOS(.v18),
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "AuraOPAQUE",
            targets: ["AuraOPAQUEBinary"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "AuraOPAQUEBinary",
            path: "dist/apple/AuraOPAQUE.xcframework"
        ),
        .target(
            name: "AuraOPAQUESwift",
            dependencies: ["AuraOPAQUEBinary"],
            path: "swift/Sources/AuraOPAQUE"
        )
    ]
)
